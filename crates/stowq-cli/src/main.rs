//! Command-line interface for StowQ queues over a memory-backed store.
//! The store backend is selected at link time in v1; the S3 backend
//! arrives with the conformance program and the same binary shape.

use clap::{Parser, Subcommand};
use std::io::Read;
use stowq_core::{
    AckOutcome, ClaimOptions, ClaimOutcome, EnqueueInput, EnqueueOutcome, OpBudget, OpenOptions,
    Queue,
};
use stowq_format::FormatRecord;
use stowq_store::MemoryStore;

/// In-process CLI runs share one memory store per invocation through a
/// file-backed swap: queue state is persisted as JSON of the raw store
/// map. This is a development surface; production use rides the S3
/// backend.
mod state;

#[derive(Parser)]
#[command(name = "stowq", version, about = "StowQ durable-work queue CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a queue prefix.
    Init {
        queue: String,
        #[arg(long, default_value_t = 256)]
        shard_count: u32,
    },
    /// Enqueue a job; payload from file or stdin.
    Put {
        queue: String,
        /// Payload file; '-' for stdin.
        payload: String,
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,
        #[arg(long, default_value_t = 5)]
        maximum_attempts: u64,
        #[arg(long)]
        job_id: Option<String>,
    },
    /// Claim one job, printing its handle as JSON.
    Claim {
        queue: String,
        #[arg(long, default_value_t = 60_000_000_000)]
        lease_ns: u64,
    },
    /// Acknowledge a claimed job by handle.
    Ack { queue: String, handle: String },
    /// Release a claim with a retry backoff.
    Nack {
        queue: String,
        handle: String,
        #[arg(default_value_t = 1)]
        reason: u64,
    },
    /// Bury a claimed job.
    Bury {
        queue: String,
        handle: String,
        #[arg(default_value_t = 0)]
        reason: u64,
    },
    /// Sweep expired-lease and delayed indexes.
    Sweep { queue: String },
    /// Collect terminal graphs past retention and stale beacons.
    Gc {
        queue: String,
        #[arg(long, default_value_t = 86_400_000_000_000)]
        retention_ns: u64,
    },
    /// Print a job's object graph.
    Inspect { queue: String, job_id: String },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli.command) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn open(queue: &str) -> Result<(Queue, MemoryStore), String> {
    let store = state::load(queue).map_err(|e| e.to_string())?;
    let q = Queue::open(Box::new(store.clone()), queue, OpenOptions::new([1; 16]))
        .map_err(|e| e.to_string())?;
    Ok((q, store))
}

fn persist(queue: &str, store: &MemoryStore) -> Result<(), String> {
    state::save(queue, store).map_err(|e| e.to_string())
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Init { queue, shard_count } => {
            let store = state::load(&queue).map_err(|e| e.to_string())?;
            let shared = store.clone();
            let format = FormatRecord {
                shard_count,
                lease_bucket_width_ns: 1_000,
                delayed_bucket_width_ns: 1_000,
                terminal_bucket_width_ns: 1_000,
                inline_limit: 4_096,
                required_feature_bits: 0,
            };
            let _q = Queue::init(Box::new(store), &queue, &OpenOptions::new([1; 16]), &format)
                .map_err(|e| e.to_string())?;
            persist(&queue, &shared)?;
            println!("initialized {queue}");
        }
        Command::Put {
            queue,
            payload,
            content_type,
            maximum_attempts,
            job_id,
        } => {
            let (q, store) = open(&queue)?;
            let body = if payload == "-" {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(|e| e.to_string())?;
                buf
            } else {
                std::fs::read(&payload).map_err(|e| format!("read {payload}: {e}"))?
            };
            let job_id = job_id.map(|h| parse_job_id(&h)).transpose()?;
            let mut budget = OpBudget::new(64);
            let out = q
                .enqueue(
                    EnqueueInput {
                        job_id,
                        payload: &body,
                        content_type,
                        maximum_attempts,
                        not_before_ns: None,
                    },
                    &mut budget,
                )
                .map_err(|e| e.to_string())?;
            match out {
                EnqueueOutcome::Committed { job_id } => {
                    println!("{}", hex(&job_id));
                    persist(&queue, &store)?;
                }
                EnqueueOutcome::IdTaken { job_id } => {
                    return Err(format!(
                        "job {} exists with different content",
                        hex(&job_id)
                    ))
                }
            }
        }
        Command::Claim { queue, lease_ns } => {
            let (q, store) = open(&queue)?;
            let floor = q
                .establish_floor(&mut OpBudget::new(16))
                .map_err(|e| e.to_string())?;
            let shard_count = q.format().shard_count.max(1);
            let mut outcome = ClaimOutcome::Empty;
            for shard in 0..shard_count {
                let opts = ClaimOptions {
                    shard: shard as u16,
                    floor_ns: floor,
                    lease_duration_ns: lease_ns,
                };
                outcome = q
                    .claim(&opts, &mut OpBudget::new(512))
                    .map_err(|e| e.to_string())?;
                if matches!(outcome, ClaimOutcome::Claimed(_)) {
                    break;
                }
            }
            match outcome {
                ClaimOutcome::Claimed(claim) => {
                    let payload_ref = match claim.payload_preview() {
                        Some(b) => format!(
                            "inline:{}",
                            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
                        ),
                        None => format!("detached:{}", hex(&claim.job_id)),
                    };
                    let handle = state::Handle::from_claim(&claim, &payload_ref);
                    println!(
                        "{}",
                        serde_json::to_string(&handle).map_err(|e| e.to_string())?
                    );
                    persist(&queue, &store)?;
                }
                ClaimOutcome::Empty => println!("empty"),
            }
        }
        Command::Ack { queue, handle } => {
            let (q, store) = open(&queue)?;
            let handle: state::Handle = serde_json::from_str(&handle).map_err(|e| e.to_string())?;
            let claim = handle.to_claim(&store, &queue)?;
            match q.ack(&claim, &mut OpBudget::new(128)) {
                Ok(AckOutcome::Acked) => {
                    println!("acked");
                    persist(&queue, &store)?;
                }
                Ok(AckOutcome::AlreadyAcked) => println!("already-acked"),
                Ok(AckOutcome::SupersededByDead) => return Err("superseded by dead record".into()),
                Err(e) => return Err(e.to_string()),
            }
        }
        Command::Nack {
            queue,
            handle,
            reason,
        } => {
            let (q, store) = open(&queue)?;
            let handle: state::Handle = serde_json::from_str(&handle).map_err(|e| e.to_string())?;
            let claim = handle.to_claim(&store, &queue)?;
            let floor = q
                .establish_floor(&mut OpBudget::new(16))
                .map_err(|e| e.to_string())?;
            q.nack(&claim, reason, floor, &mut OpBudget::new(128))
                .map_err(|e| e.to_string())?;
            println!("nacked");
            persist(&queue, &store)?;
        }
        Command::Bury {
            queue,
            handle,
            reason,
        } => {
            let (q, store) = open(&queue)?;
            let handle: state::Handle = serde_json::from_str(&handle).map_err(|e| e.to_string())?;
            let claim = handle.to_claim(&store, &queue)?;
            q.bury(&claim, reason, &mut OpBudget::new(128))
                .map_err(|e| e.to_string())?;
            println!("buried");
            persist(&queue, &store)?;
        }
        Command::Sweep { queue } => {
            let (q, store) = open(&queue)?;
            let floor = q
                .establish_floor(&mut OpBudget::new(16))
                .map_err(|e| e.to_string())?;
            let leases = q
                .sweep_expired_leases(floor, &mut OpBudget::new(1024))
                .map_err(|e| e.to_string())?;
            let delayed = q
                .sweep_delayed(floor, &mut OpBudget::new(1024))
                .map_err(|e| e.to_string())?;
            println!(
                "leases: {} entries, {} reclaimed; delayed: {} entries, {} promoted",
                leases.entries, leases.reclaimed, delayed.entries, delayed.promoted
            );
            persist(&queue, &store)?;
        }
        Command::Gc {
            queue,
            retention_ns,
        } => {
            let (q, store) = open(&queue)?;
            let floor = q
                .establish_floor(&mut OpBudget::new(16))
                .map_err(|e| e.to_string())?;
            let report = q
                .gc(floor, retention_ns, &mut OpBudget::new(4096))
                .map_err(|e| e.to_string())?;
            println!(
                "{} jobs deleted, {} beacons collected",
                report.jobs_deleted, report.beacons_deleted
            );
            persist(&queue, &store)?;
        }
        Command::Inspect { queue, job_id } => {
            let (q, _store) = open(&queue)?;
            let id = parse_job_id(&job_id)?;
            let out = state::inspect(q.store(), &queue, id, q.format().shard_count.max(1))
                .map_err(|e| e.to_string())?;
            println!("{out}");
        }
    }
    Ok(())
}

fn parse_job_id(h: &str) -> Result<[u8; 16], String> {
    let bytes = hex_decode(h)?;
    bytes
        .try_into()
        .map_err(|_| format!("job id must be 32 hex chars, got {h}"))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| format!("invalid hex in {s}"))
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
