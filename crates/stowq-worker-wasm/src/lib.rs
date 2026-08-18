//! Cloudflare Worker wiring for StowQ: the Fetch transport over the
//! HttpTransport seam, a Queues-consumer doorbell feeding the native
//! harness, and a cron sweeper over sweep_once. The decision-memo
//! shape: the Worker is a doorbell relay and sweeper (edge-cheap,
//! R2-adjacent); executors stay native — the 15-minute invocation
//! cap and 5-minute CPU cap make the Worker the wrong place for
//! transcoding work.
//!
//! Target discipline: everything wasm-specific (the Fetch transport,
//! the Date clock, the worker entry points) is behind
//! `cfg(target_family = "wasm")`. Native builds compile the crate as
//! an empty shell: CI's workspace gate covers the pure logic (the
//! status-mapping tables below), and `cargo build -p
//! stowq-worker-wasm --target wasm32-unknown-unknown` is the wasm
//! gate.

// ---------- pure logic (both targets; table-tested) ----------

/// Maps a fetch-phase failure to the transport marker prefix the
/// store classifies (see stowq_store_http::HttpTransport's contract:
/// Err means no HTTP response was received). Pure so the mapping is
/// unit-testable natively; the wasm side feeds it the phase.
pub fn transport_marker(was_connect_phase: bool, was_timeout: bool) -> &'static str {
    match (was_connect_phase, was_timeout) {
        // Connect-phase covers DNS (resolution runs in the
        // connector): provably not transmitted.
        (true, _) => "[pretransmit]",
        (false, true) => "[timeout]",
        (false, false) => "[unknown]",
    }
}

/// The doorbell message body the Queues producer sends and the
/// consumer parses: shard numbers as decimal lines. Lossy, mutable
/// hints per the doorbell rule — a malformed body is an empty hint
/// (sweep every shard), never an error.
pub fn parse_doorbell(body: &str) -> Vec<u16> {
    body.lines().filter_map(|l| l.trim().parse().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_table() {
        assert_eq!(transport_marker(true, false), "[pretransmit]");
        assert_eq!(transport_marker(true, true), "[pretransmit]");
        assert_eq!(transport_marker(false, true), "[timeout]");
        assert_eq!(transport_marker(false, false), "[unknown]");
    }

    #[test]
    fn doorbell_parsing() {
        assert_eq!(parse_doorbell("3\n7\n"), vec![3, 7]);
        assert_eq!(parse_doorbell(""), Vec::<u16>::new());
        // Malformed lines drop; a hostile body degrades to the
        // shards it can name, possibly none (the sweep shape).
        assert_eq!(parse_doorbell("nope\n5\n99999\n"), vec![5]);
        assert_eq!(parse_doorbell("65536\n"), Vec::<u16>::new());
    }
}

// ---------- wasm wiring ----------

#[cfg(target_family = "wasm")]
mod wasm {
    use crate::{parse_doorbell, transport_marker};
    use stowq_store::ObjectStore;
    use stowq_store_http::{HttpRequest, HttpResponse, HttpTransport, SigningClock};
    use stowq_worker::DeliveryReport;
    use worker::*;

    // ----- Fetch transport -----

    pub struct FetchTransport;

    #[async_trait::async_trait(?Send)]
    impl HttpTransport for FetchTransport {
        async fn send(&self, req: HttpRequest) -> std::result::Result<HttpResponse, String> {
            // The runtime derives Host from the URL; the signed value
            // stays in the signature only (R2 rejects duplicates).
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::from(req.method.to_string()));
            let headers: worker::Headers = req
                .headers
                .iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("host"))
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            init.with_headers(headers);
            if !req.body.is_empty() {
                init.with_body(Some(js_sys::Uint8Array::from(req.body.as_slice()).into()));
            }
            let built = worker::Request::new_with_init(&req.url, &init)
                .map_err(|e| "[unknown] ".to_string() + &e.to_string())?;
            let mut resp = Fetch::Request(built)
                .send()
                .await
                .map_err(|e| transport_marker(false, e.to_string().contains("timeout")))?;
            let status = resp.status_code();
            // The four headers the store parses are read by name
            // (case-insensitive on Headers::get); the full list is
            // not needed.
            let h = |n: &str| resp.headers().get(n).ok().flatten().unwrap_or_default();
            let headers = vec![
                ("ETag".to_string(), h("ETag")),
                ("Last-Modified".to_string(), h("Last-Modified")),
                ("Content-Length".to_string(), h("Content-Length")),
                ("Content-Range".to_string(), h("Content-Range")),
            ];
            // Text: the bodies are small (records, XML pages).
            let body = resp
                .text()
                .await
                .map_err(|e| "[unknown] ".to_string() + &e.to_string())?;
            Ok(HttpResponse {
                status,
                headers,
                body: body.into_bytes(),
            })
        }
    }

    // Workers' Date is frozen during CPU but advances across I/O —
    // exactly the shape signing needs (the amz-date must track real
    // time across the request boundary).
    pub struct WorkerClock;

    impl SigningClock for WorkerClock {
        fn amz_stamps(&self) -> (String, String) {
            let ms = Date::now().as_millis();
            stowq_store_http::stamps_from_unix(ms / 1000)
        }
    }

    // ----- environment assembly -----

    fn store_from_env(env: &Env) -> Option<stowq_store_http::HttpStore<FetchTransport>> {
        let endpoint = env.var("STOWQ_ENDPOINT").ok()?.to_string();
        let region = env
            .var("STOWQ_REGION")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "auto".into());
        let access_key = env.var("STOWQ_ACCESS_KEY_ID").ok()?.to_string();
        let secret_key = env.var("STOWQ_SECRET_ACCESS_KEY").ok()?.to_string();
        let bucket = env.var("STOWQ_BUCKET").ok()?.to_string();
        let cfg = stowq_store_http::HttpStoreConfig {
            region,
            endpoint,
            force_path_style: true,
            bucket,
            access_key,
            secret_key,
            session_token: env.var("STOWQ_SESSION_TOKEN").map(|v| v.to_string()).ok(),
        };
        Some(stowq_store_http::HttpStore::new(
            FetchTransport,
            cfg,
            std::sync::Arc::new(WorkerClock),
        ))
    }

    fn queue_options(env: &Env) -> stowq_core::OpenOptions {
        let root = env
            .var("STOWQ_QUEUE_ROOT")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "q".into());
        let _ = root; // root flows through Queue::open below
        let mut o = stowq_core::OpenOptions::new([0u8; 16]);
        if let Ok(id) = env.var("STOWQ_QUEUE_ID") {
            let hex = id.to_string();
            let mut qid = [0u8; 16];
            if hex.len() == 32 {
                for i in 0..16 {
                    qid[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0);
                }
            }
            o = stowq_core::OpenOptions::new(qid);
        }
        o
    }

    // ----- the doorbell consumer -----

    /// One Queues message becomes one doorbell hint consumed through
    /// the native harness. The hint names shards; a malformed or
    /// empty body is the sweep shape. The Worker never executes
    /// jobs: a claimed delivery would need renewal heartbeats
    /// bounded by the invocation cap, so the hint is delivered to a
    /// NATIVE executor by re-publishing to the executor queue —
    /// here, in this minimal deployment shape, the doorbell drives a
    /// store-only probe (claim-none verification) and the cron
    /// sweeper keeps the indexes bounded. Executors subscribe by
    /// polling or their own doorbells; see the design doc.
    pub(crate) async fn handle_doorbell(
        env: &Env,
        body: String,
    ) -> std::result::Result<(), String> {
        let shards = parse_doorbell(&body);
        let store = store_from_env(env).ok_or("missing STOWQ_* env")?;
        let root = env
            .var("STOWQ_QUEUE_ROOT")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "q".into());
        let q = stowq_core::Queue::open(Box::new(store), &root, queue_options(env))
            .await
            .map_err(|e| e.to_string())?;
        // Hints bound EXECUTOR claiming, not sweep cost; the relay
        // action is the sweep pass (bounded indexes, R2 reachability
        // proven) regardless of which shards were named.
        let _ = shards;
        let mut budget = stowq_core::OpBudget::new(2048);
        stowq_worker::sweep_once(&q, &mut budget)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ----- cron -----

    pub(crate) async fn handle_scheduled(env: Env) -> std::result::Result<(), String> {
        let store = store_from_env(&env).ok_or("missing STOWQ_* env")?;
        let root = env
            .var("STOWQ_QUEUE_ROOT")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "q".into());
        let q = stowq_core::Queue::open(Box::new(store), &root, queue_options(&env))
            .await
            .map_err(|e| e.to_string())?;
        let mut budget = stowq_core::OpBudget::new(4096);
        stowq_worker::sweep_once(&q, &mut budget)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(target_family = "wasm")]
mod entry {
    use super::wasm::{handle_doorbell, handle_scheduled};
    use worker::*;

    #[event(queue)]
    pub async fn queue(
        batch: MessageBatch<String>,
        env: Env,
        _ctx: Context,
    ) -> std::result::Result<(), String> {
        // A batch of doorbell hints: each becomes one sweep pass.
        // Per the doorbell rule, hints are lossy; a failed pass logs
        // and the batch continues (the cron sweeper is the safety
        // net for anything dropped).
        for msg in batch.messages().map_err(|e| e.to_string())? {
            if let Err(e) = handle_doorbell(&env, msg.body().clone()).await {
                console_log!("doorbell pass failed: {e}");
            }
        }
        Ok(())
    }

    #[event(scheduled)]
    pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        if let Err(e) = handle_scheduled(env).await {
            console_log!("scheduled sweep failed: {e}");
        }
    }
}
