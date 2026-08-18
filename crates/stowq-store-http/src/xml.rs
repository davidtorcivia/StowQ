//! Minimal ListObjectsV2 XML extraction. The S3-family response is a
//! small, stable document; a full XML parser is not warranted for
//! one endpoint's shape. Malformed responses surface as empty parses
//! (the store's error taxonomy treats a successful status with an
//! unusable body as a profile violation upstream — here we return
//! what we can read).

pub struct ListContents {
    pub key: String,
    pub etag: String,
    pub last_modified_ns: u64,
    pub size: u64,
}

pub struct ListResponse {
    pub contents: Vec<(String, ListContents)>,
    pub is_truncated: bool,
}

/// Extracts `<Contents>` blocks and `<IsTruncated>`.
pub fn parse_list(xml: &str) -> ListResponse {
    let mut contents = Vec::new();
    let is_truncated = extract(xml, "IsTruncated")
        .map(|v| v == "true")
        .unwrap_or(false);
    let mut rest = xml;
    while let Some(start) = rest.find("<Contents>") {
        let after_open = &rest[start + "<Contents>".len()..];
        let Some(end_rel) = after_open.find("</Contents>") else {
            break;
        };
        let block = &after_open[..end_rel];
        let key = extract(block, "Key")
            .map(|k| xml_unescape(&k))
            .unwrap_or_default();
        let etag = extract(block, "ETag")
            .map(|e| xml_unescape(&e).trim_matches('"').to_string())
            .unwrap_or_default();
        let last_modified_ns = extract(block, "LastModified")
            .and_then(|v| parse_iso8601_secs(&v))
            .unwrap_or(0);
        let size = extract(block, "Size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        contents.push((
            key,
            ListContents {
                key: String::new(),
                etag,
                last_modified_ns,
                size,
            },
        ));
        rest = &after_open[end_rel + "</Contents>".len()..];
    }
    ListResponse {
        contents,
        is_truncated,
    }
}

/// Decodes the five XML predefined entities plus decimal character
/// references; keys and attributes in S3 listings may contain any of
/// them.
fn xml_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        let (entity, len) = if let Some(semi) = after.find(';') {
            (Some(&after[..=semi]), semi + 1)
        } else {
            (None, 1)
        };
        let replacement = match entity {
            Some("&amp;") => Some("&".to_string()),
            Some("&lt;") => Some("<".to_string()),
            Some("&gt;") => Some(">".to_string()),
            Some("&quot;") => Some("\"".to_string()),
            Some("&apos;") => Some("'".to_string()),
            Some(e) if e.starts_with("&#") => {
                let n = e[2..e.len() - 1].parse::<u32>().ok();
                n.and_then(char::from_u32).map(|c| c.to_string())
            }
            _ => None,
        };
        match replacement {
            Some(r) => out.push_str(&r),
            None => out.push_str(&after[..len.min(after.len())]),
        }
        rest = &after[len.min(after.len())..];
    }
    out.push_str(rest);
    out
}

/// Extracts the first `<tag>...</tag>` value; handles the tag being
/// empty (`<Tag/>` returns None — an absent value).
fn extract(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

/// Parses "1994-11-06T08:49:37.000Z" (or without fractional seconds)
/// to whole-second nanoseconds.
fn parse_iso8601_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;
    // Days-from-civil (same algorithm family as the signing clock).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + (day as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = doe as i64 + era * 146_097 - 719_468;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    Some(secs as u64 * 1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_page() {
        let xml = r#"<?xml version="1.0"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>jobs/0000/aa</Key>
    <LastModified>2026-08-17T20:05:30.000Z</LastModified>
    <ETag>&quot;abc123&quot;</ETag>
    <Size>128</Size>
  </Contents>
  <Contents>
    <Key>jobs/0000/bb</Key>
    <LastModified>2026-08-17T20:05:31Z</LastModified>
    <ETag>"def456"</ETag>
    <Size>256</Size>
  </Contents>
</ListBucketResult>"#;
        let r = parse_list(xml);
        assert!(!r.is_truncated);
        assert_eq!(r.contents.len(), 2);
        assert_eq!(r.contents[0].0, "jobs/0000/aa");
        assert_eq!(r.contents[0].1.etag, "abc123");
        assert_eq!(r.contents[0].1.size, 128);
        assert_eq!(r.contents[0].1.last_modified_ns % 1_000_000_000, 0);
        assert_eq!(r.contents[1].1.etag, "def456");
    }

    #[test]
    fn truncated_flag_and_empty() {
        let xml = "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>";
        let r = parse_list(xml);
        assert!(r.is_truncated);
        assert!(r.contents.is_empty());
        let empty = parse_list("garbage");
        assert!(!empty.is_truncated);
        assert!(empty.contents.is_empty());
    }
}
