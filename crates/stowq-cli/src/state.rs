//! Development persistence for the CLI: the memory store's map is
//! serialized to a JSON sidecar next to the queue name. The S3 backend
//! replaces this whole module in the conformance program.

use serde::{Deserialize, Serialize};
use stowq_core::Claim;
use stowq_store::{Key, MemoryStore, ObjectStore, StoreError};

#[derive(Serialize, Deserialize)]
pub struct Handle {
    pub job_id: String,
    pub shard: u16,
    pub generation: u64,
    pub attempt: u64,
    pub worker_token: String,
    pub lease_duration_ns: u64,
    pub claim_store_time_ns: u64,
    pub inline_payload: String,
}

impl Handle {
    pub fn from_claim(c: &Claim) -> Self {
        // The payload reference is inline for CLI flows (small
        // payloads); detached reads re-fetch through the store.
        let inline = c
            .payload_preview()
            .map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
            .unwrap_or_default();
        Handle {
            job_id: c.job_id.iter().map(|x| format!("{x:02x}")).collect(),
            shard: c.shard,
            generation: c.generation,
            attempt: c.attempt,
            worker_token: c.worker_token.iter().map(|x| format!("{x:02x}")).collect(),
            lease_duration_ns: c.lease_duration_ns,
            claim_store_time_ns: c.claim_store_time_ns,
            inline_payload: inline,
        }
    }

    pub fn to_claim(&self) -> Result<Claim, String> {
        let decode = |s: &str| -> Result<Vec<u8>, String> {
            (0..s.len() / 2)
                .map(|i| {
                    u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                        .map_err(|_| "invalid hex in handle".to_string())
                })
                .collect()
        };
        let job_id: [u8; 16] = decode(&self.job_id)?
            .try_into()
            .map_err(|_| "bad job id".to_string())?;
        let token: [u8; 16] = decode(&self.worker_token)?
            .try_into()
            .map_err(|_| "bad token".to_string())?;
        let payload = decode(&self.inline_payload)?;
        Ok(stowq_core::Claim::inline(
            job_id,
            self.shard,
            self.generation,
            self.attempt,
            token,
            self.lease_duration_ns,
            self.claim_store_time_ns,
            bytes::Bytes::from(payload),
        ))
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Snapshot {
    objects: Vec<Entry>,
    next_version: u64,
    clock: u64,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    key: String,
    body: String,
    version: u64,
    store_time_ns: u64,
}

fn path_for(queue: &str) -> std::path::PathBuf {
    let sanitized: String = queue
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    std::env::temp_dir().join(format!("stowq-{sanitized}.json"))
}

pub fn load(queue: &str) -> Result<MemoryStore, std::io::Error> {
    let path = path_for(queue);
    if !path.exists() {
        return Ok(MemoryStore::new());
    }
    let raw = std::fs::read_to_string(path)?;
    let snap: Snapshot = serde_json::from_str(&raw)?;
    let store = MemoryStore::with_tick_step_ns(1);
    let mut objects = Vec::with_capacity(snap.objects.len());
    for e in snap.objects {
        objects.push((e.key, decode_hex(&e.body)?, e.version, e.store_time_ns));
    }
    store.restore_raw(objects, snap.next_version, snap.clock);
    Ok(store)
}

/// Persists from the CLI's own store handle (Arc-shared with the
/// queue). The S3 backend replaces this module wholesale.
pub fn save(queue: &str, store: &MemoryStore) -> Result<(), std::io::Error> {
    let (objects, next_version, clock) = store.snapshot_raw();
    let snap = Snapshot {
        objects: objects
            .into_iter()
            .map(|(k, body, version, t)| Entry {
                key: k,
                body: body.iter().map(|x| format!("{x:02x}")).collect(),
                version,
                store_time_ns: t,
            })
            .collect(),
        next_version,
        clock,
    };
    let path = path_for(queue);
    std::fs::write(
        path,
        serde_json::to_string(&snap).map_err(std::io::Error::other)?,
    )
}

fn decode_hex(s: &str) -> Result<Vec<u8>, std::io::Error> {
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| std::io::Error::other("invalid hex in snapshot"))
        })
        .collect()
}

pub fn inspect(store: &dyn ObjectStore, queue: &str, job_id: [u8; 16]) -> Result<String, String> {
    let h: String = job_id.iter().map(|x| format!("{x:02x}")).collect();
    let shard = stowq_keys::compute_shard(&[1; 16], &job_id, 256);
    let mut lines = Vec::new();
    let keys = [
        format!("{queue}/jobs/{shard:04x}/{h}"),
        format!("{queue}/receipts/{shard:04x}/{h}"),
        format!("{queue}/dead/{shard:04x}/{h}"),
    ];
    for k in keys {
        match store.head(&Key::new(k.clone())) {
            Ok(_) => lines.push(format!("{k}: present")),
            Err(StoreError::NotFound) => lines.push(format!("{k}: absent")),
            Err(e) => return Err(e.to_string()),
        }
    }
    let claims_prefix = format!("{queue}/claims/{shard:04x}/{h}/");
    let mut after: Option<Key> = None;
    loop {
        let page = store
            .list(&claims_prefix, after.as_ref(), 64)
            .map_err(|e| e.to_string())?;
        if page.items.is_empty() {
            break;
        }
        for item in &page.items {
            lines.push(format!(
                "{}: gen at t={}",
                item.key, item.meta.store_time_ns
            ));
        }
        match page.next_after {
            Some(k) => after = Some(k),
            None => break,
        }
    }
    Ok(lines.join("\n"))
}
