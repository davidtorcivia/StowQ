//! The native transport: async reqwest behind the `native` feature,
//! so the conformance suite certifies the fetch-based store exactly
//! as it certifies the SDK backend. The wasm path never compiles
//! this.

use crate::{HttpRequest, HttpResponse, HttpTransport};

pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    pub fn new() -> Self {
        ReqwestTransport {
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HttpTransport for ReqwestTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| format!("method: {e}"))?;
        let mut r = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            // The HTTP layer derives Host from the URL; sending an
            // explicit Host duplicates it and breaks signature
            // reconstruction server-side. It is signed, not sent.
            if k.eq_ignore_ascii_case("host") {
                continue;
            }
            r = r.header(k, v);
        }
        // R2 rejects PUTs without Content-Length (411) — including
        // empty bodies (the floor beacon) — and the HTTP layer omits
        // the header for zero-length bodies, so set it explicitly.
        // Unsigned for SigV4 (only declared headers are signed).
        r = r.header("Content-Length", req.body.len().to_string());
        r = r.body(req.body.clone());
        let resp = r.send().await.map_err(|e| {
            // The contract: Err means no HTTP response was received.
            // Marker prefixes drive the store's class mapping; the
            // error text itself is never classified (post-transmit
            // failures often contain "connection" — substring
            // matching would misclassify them as pre-transmit).
            if e.is_connect() {
                "[pretransmit]".to_string()
            } else if e.is_timeout() {
                "[timeout]".to_string()
            } else {
                "[unknown]".to_string()
            }
        })?;
        let status = resp.status().as_u16();
        let mut headers = Vec::new();
        let mut etag: Option<String> = None;
        let mut last_modified: Option<String> = None;
        let mut content_length: Option<String> = None;
        let mut content_range: Option<String> = None;
        for (name, value) in resp.headers() {
            let v = value.to_str().unwrap_or("").to_string();
            match name.as_str() {
                "etag" => etag = Some(v.clone()),
                "last-modified" => last_modified = Some(v.clone()),
                "content-length" => content_length = Some(v.clone()),
                "content-range" => content_range = Some(v.clone()),
                _ => {}
            }
            headers.push((name.as_str().to_string(), v));
        }
        // HEAD responses have no body; read before consuming.
        let body = if req.method == "HEAD" {
            Vec::new()
        } else {
            resp.bytes()
                .await
                .map_err(|e| format!("body: {e}"))?
                .to_vec()
        };
        // Re-add the header names reqwest strips from the typed map
        // are kept above; ensure the four we parse are present even if
        // duplicated filtering dropped them (they are single-valued).
        if let Some(v) = etag {
            headers.push(("ETag".into(), v));
        }
        if let Some(v) = last_modified {
            headers.push(("Last-Modified".into(), v));
        }
        if let Some(v) = content_length {
            headers.push(("Content-Length".into(), v));
        }
        if let Some(v) = content_range {
            headers.push(("Content-Range".into(), v));
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
