//! Demo pipeline over a live S3-family store: artifact-in-R2 → process →
//! commit-rule output → receipt, with worker kills injected mid-pipeline.
//!
//! Two modes:
//!
//! - `driver [--jobs N] [--kills K] [--lease-s S]` — initializes a fresh
//!   queue root, enqueues N jobs as DETACHED payloads (artifacts in the
//!   bucket), then spawns worker children and SIGKILLs each after a
//!   random delay; after K kills a final worker runs to completion. The
//!   driver then asserts the converged state per job — exactly one
//!   receipt whose output digests are correct, first-wins output bytes,
//!   no dead record — and prints the claim-chain-depth distribution
//!   (the tail-hint data).
//! - `worker --root R [--lease-s S]` — one consumer loop: doorbell sweep
//!   hints through run_delivery until the NoWork streak covers a full
//!   lease window, then exits. Detached payloads are verified on claim;
//!   the executor is deliberately slow so kills land mid-execution.
//!
//! Configuration is the conformance suite's: STOWQ_CONFORMANCE_ENDPOINT
//! (required), STOWQ_CONFORMANCE_BUCKET, and the standard AWS_ chain.

use async_trait::async_trait;
use bytes::Bytes;
use sha2::Digest as _;
use std::time::{Duration, Instant};
use stowq_core::{EnqueueInput, EnqueueOutcome, OpBudget, OpenOptions, Queue};
use stowq_format::FormatRecord;
use stowq_store::{Key, StoreError};
use stowq_store_s3::{S3Config, S3Store};
use stowq_worker::{DeliveryReport, DoorbellMsg, Executor, ExecutorOutput};

/// The deterministic transform: output bytes are the payload reversed.
fn transform(payload: &[u8]) -> Vec<u8> {
    let mut v = payload.to_vec();
    v.reverse();
    v
}

/// 64 KiB patterned artifact bytes for job `index`.
fn artifact(index: usize) -> Vec<u8> {
    (0..64 * 1024)
        .map(|i| ((i * 7 + index * 13) & 0xff) as u8)
        .collect()
}

fn format() -> FormatRecord {
    FormatRecord {
        shard_count: 1,
        lease_bucket_width_ns: 1_000_000_000,
        delayed_bucket_width_ns: 1_000_000_000,
        terminal_bucket_width_ns: 1_000_000_000,
        inline_limit: 65_536,
        required_feature_bits: 0,
    }
}

fn opts() -> OpenOptions {
    let mut o = OpenOptions::new([1; 16]);
    o.worker_id = "demo-worker".into();
    o
}

async fn store() -> Result<S3Store, String> {
    let endpoint = std::env::var("STOWQ_CONFORMANCE_ENDPOINT").map_err(|_| {
        "STOWQ_CONFORMANCE_ENDPOINT is required (the conformance configuration)".to_string()
    })?;
    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let config = S3Config {
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "auto".into()),
        endpoint: Some(endpoint),
        force_path_style: true,
    };
    let bucket =
        std::env::var("STOWQ_CONFORMANCE_BUCKET").unwrap_or_else(|_| "stowq-conformance".into());
    Ok(S3Store::new(&sdk, &config, bucket))
}

fn jhex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- worker mode ----------

/// Sleeps mid-execution so kills land inside the executor, then emits
/// the deterministic output.
struct SlowTransform {
    think: Duration,
}

#[async_trait]
impl Executor for SlowTransform {
    async fn run(
        &self,
        _job_id: [u8; 16],
        payload: Bytes,
    ) -> Result<Vec<ExecutorOutput>, stowq_worker::ExecutionFailure> {
        tokio::time::sleep(self.think).await;
        Ok(vec![ExecutorOutput {
            name: "result".into(),
            body: Bytes::from(transform(&payload)),
        }])
    }
}

async fn worker(root: &str, lease_s: u64) -> Result<(), String> {
    let lease_ns = lease_s * 1_000_000_000;
    // Exit after a NoWork streak covering a full lease window plus
    // slack: whatever a killed worker held has lapsed by then, so
    // nothing is claimable and the driver takes over.
    let exit_after = (lease_s + 4) as u32;
    let mut nowork = 0u32;
    loop {
        // A fresh handle per retry round: the takeover gate needs a
        // CURRENT floor, but a handle caches its floor for the
        // staleness window — a retrying worker must re-beacon or it
        // waits out its own patience below the gate.
        let q = Queue::open(
            Box::new(store().await?),
            root,
            OpenOptions {
                worker_id: format!("worker-{}-{nowork}", std::process::id()),
                ..opts()
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let report = stowq_worker::run_delivery(
            &q,
            &DoorbellMsg::sweep(),
            &SlowTransform {
                think: Duration::from_secs(2),
            },
            lease_ns,
        )
        .await
        .map_err(|e| format!("delivery error: {e}"))?;
        match report {
            DeliveryReport::Delivered { .. } => nowork = 0,
            DeliveryReport::NoWork => {
                nowork += 1;
                if nowork >= exit_after {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
            // LostLease and Failed(retryable) are the kill/restart
            // dynamics; the loop continues either way.
            _ => nowork = 0,
        }
    }
}

// ---------- driver mode ----------

/// Total claim records under the root (every generation of every
/// job): the observable "did the worker get into the pipeline" signal.
async fn claim_count(q: &Queue, root: &str) -> Result<usize, String> {
    let mut after: Option<Key> = None;
    let mut n = 0usize;
    loop {
        let page = q
            .store()
            .list(&format!("{root}/claims/"), after.as_ref(), 1024)
            .await
            .map_err(|e| e.to_string())?;
        n += page.items.len();
        match page.next_after {
            Some(k) => after = Some(k),
            None => return Ok(n),
        }
    }
}

/// splitmix64 — the testkit driver's PRNG shape.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
}

async fn driver(jobs_n: usize, kills: usize, lease_s: u64) -> Result<(), String> {
    let t0 = Instant::now();
    let root = format!("demo-{}", std::process::id());
    Queue::init(Box::new(store().await?), &root, &opts(), &format())
        .await
        .map_err(|e| e.to_string())?;
    println!("root: {root}");

    // Enqueue detached artifacts: max_inline_payload 0 forces the
    // payload object under payloads/ — the artifact-in-R2 leg.
    let mut eq_opts = opts();
    eq_opts.max_inline_payload = 0;
    let eq = Queue::open(Box::new(store().await?), &root, eq_opts)
        .await
        .map_err(|e| e.to_string())?;
    let mut job_ids = Vec::with_capacity(jobs_n);
    let mut payloads = Vec::with_capacity(jobs_n);
    for i in 0..jobs_n {
        let p = artifact(i);
        let mut b = OpBudget::new(64);
        let EnqueueOutcome::Committed { job_id } = eq
            .enqueue(
                EnqueueInput {
                    job_id: None,
                    payload: &p,
                    content_type: "application/octet-stream".into(),
                    maximum_attempts: 50,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .map_err(|e| e.to_string())?
        else {
            return Err(format!("enqueue rejected on the fresh root for job {i}"));
        };
        job_ids.push(job_id);
        payloads.push(p);
    }
    println!("enqueued {jobs_n} detached artifacts");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut rng = Rng::new(now ^ ((std::process::id() as u64) << 32));

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let spawn = || {
        std::process::Command::new(&exe)
            .arg("worker")
            .arg("--root")
            .arg(&root)
            .arg("--lease-s")
            .arg(lease_s.to_string())
            .spawn()
    };

    // Kill rounds: the child dies mid-pipeline at a random moment. A
    // kill landing before the worker's first claim is ineffective —
    // observed via the claim-record delta across the round, and the
    // run's success is conditioned on at least one effective kill
    // (with kills requested), so a chaos-free pass cannot pose as a
    // chaos-surviving one.
    let mut effective_kills = 0usize;
    let observe_q = Queue::open(Box::new(store().await?), &root, opts())
        .await
        .map_err(|e| e.to_string())?;
    for k in 0..kills {
        let before = claim_count(&observe_q, &root).await?;
        let mut child = spawn().map_err(|e| e.to_string())?;
        let wait = rng.range(1000, 5000);
        println!("kill round {k}: SIGKILL worker {} in {wait}ms", child.id());
        tokio::time::sleep(Duration::from_millis(wait)).await;
        child.kill().map_err(|e| e.to_string())?;
        let _ = child.wait();
        let after_k = claim_count(&observe_q, &root).await?;
        let grew = after_k > before;
        if grew {
            effective_kills += 1;
        }
        println!(
            "kill round {k}: {} (claims {} -> {})",
            if grew {
                "landed mid-pipeline"
            } else {
                "ineffective (pre-claim)"
            },
            before,
            after_k
        );
    }
    assert!(
        kills == 0 || effective_kills > 0,
        "no kill landed mid-pipeline — the run demonstrated nothing"
    );

    // Final worker runs to completion (bounded, one respawn on a
    // transient child failure: the store state is idempotent, so a
    // blip that kills the child costs a restart, not the run).
    let deadline = Duration::from_secs(600);
    let mut attempt = 0;
    loop {
        let mut child = spawn().map_err(|e| e.to_string())?;
        let start = Instant::now();
        let status = loop {
            if start.elapsed() > deadline {
                // F3: reap even on the deadline path.
                child.kill().map_err(|e| e.to_string())?;
                let _ = child.wait();
                return Err("final worker exceeded 600s".into());
            }
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(status) => break status,
                None => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        };
        if status.success() {
            break;
        }
        attempt += 1;
        if attempt > 1 {
            return Err(format!("final worker exited {status} twice"));
        }
        println!("final worker exited {status}; respawning once");
    }
    println!(
        "workers done after {} kill rounds; wall {}s",
        kills,
        t0.elapsed().as_secs()
    );

    // Convergence assertions per job.
    let assert_q = Queue::open(Box::new(store().await?), &root, opts())
        .await
        .map_err(|e| e.to_string())?;
    let s = assert_q.store();
    let mut depths = Vec::with_capacity(jobs_n);
    for (job_id, payload) in job_ids.iter().zip(&payloads) {
        let hex = jhex(job_id);
        let rel = format!("receipts/0000/{hex}");
        let obj = s
            .get(&Key::new(format!("{root}/{rel}")), None)
            .await
            .map_err(|e| format!("job {hex}: no receipt: {e}"))?;
        let tag = stowq_keys::key_tag(&[1; 16], &rel);
        match stowq_format::decode(&obj.body, &[1; 16], &tag)
            .map_err(|e| format!("job {hex}: receipt undecodable: {e}"))?
        {
            stowq_format::Record::Receipt(r) => {
                let want: [u8; 32] = sha2::Sha256::digest(transform(payload)).into();
                assert_eq!(r.output_digests, vec![want], "job {hex}: output digests");
            }
            other => return Err(format!("job {hex}: non-receipt at receipt key: {other:?}")),
        }
        assert_eq!(
            s.head(&Key::new(format!("{root}/dead/0000/{hex}"))).await,
            Err(StoreError::NotFound),
            "job {hex}: dead record"
        );
        let out = s
            .get(&Key::new(format!("{root}/outputs/{hex}/result")), None)
            .await
            .map_err(|e| format!("job {hex}: no output: {e}"))?;
        assert_eq!(&out.body[..], &transform(payload)[..], "job {hex}: bytes");
        let page = s
            .list(&format!("{root}/claims/0000/{hex}/"), None, 1024)
            .await
            .map_err(|e| e.to_string())?;
        depths.push(page.items.len());
    }

    // The durable audit: no findings after the chaos.
    let mut b = OpBudget::new(8192);
    let (report, _) = assert_q
        .repair_scan(0, &mut b)
        .await
        .map_err(|e| e.to_string())?;
    assert!(
        report.findings.is_empty(),
        "repair findings after kills: {:?}",
        report.findings
    );

    depths.sort_unstable();
    let mean = depths.iter().sum::<usize>() as f64 / depths.len() as f64;
    println!("all {jobs_n} jobs: one receipt, correct digests, first-wins bytes");
    println!(
        "chain depth: min {} / median {} / max {} / mean {mean:.1}",
        depths[0],
        depths[depths.len() / 2],
        depths[depths.len() - 1]
    );
    println!("histogram: {depths:?}");
    Ok(())
}

// ---------- arg parsing ----------

struct Args {
    mode: String,
    jobs: usize,
    kills: usize,
    lease_s: u64,
    root: String,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let Some(mode) = it.next() else {
        return Err(
            "usage: stowq-demo driver|worker [--jobs N] [--kills K] [--lease-s S] [--root R]"
                .into(),
        );
    };
    let mut a = Args {
        mode,
        jobs: 8,
        kills: 6,
        lease_s: 6,
        root: String::new(),
    };
    while let Some(flag) = it.next() {
        let val = it
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--jobs" => a.jobs = val.parse().map_err(|_| "--jobs")?,
            "--kills" => a.kills = val.parse().map_err(|_| "--kills")?,
            "--lease-s" => a.lease_s = val.parse().map_err(|_| "--lease-s")?,
            "--root" => a.root = val,
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(a)
}

#[tokio::main]
async fn main() {
    let args = parse_args().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });
    let r = match args.mode.as_str() {
        "driver" => driver(args.jobs, args.kills, args.lease_s).await,
        "worker" => {
            let root = args.root.clone();
            if root.is_empty() {
                Err("worker requires --root".into())
            } else {
                worker(&root, args.lease_s).await
            }
        }
        m => Err(format!("unknown mode {m}")),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn executor_is_deterministic_across_attempts() {
        let p = artifact(5);
        let a = SlowTransform {
            think: Duration::ZERO,
        }
        .run([0; 16], Bytes::from(p.clone()))
        .await
        .unwrap();
        let b = SlowTransform {
            think: Duration::ZERO,
        }
        .run([0; 16], Bytes::from(p))
        .await
        .unwrap();
        assert_eq!(a, b, "duplicate attempts converge on identical outputs");
    }

    #[test]
    fn transform_is_an_involutive_content_function() {
        let p = artifact(3);
        let t = transform(&p);
        assert_eq!(t.len(), p.len());
        // Reversing twice returns the artifact: the output is a pure
        // function of the payload, which is what makes duplicate
        // attempts converge on identical first-wins bytes.
        assert_eq!(transform(&t), p);
        // Distinct jobs have distinct artifacts and outputs.
        assert_ne!(p, artifact(4));
        assert_ne!(transform(&p), transform(&artifact(4)));
    }
}
