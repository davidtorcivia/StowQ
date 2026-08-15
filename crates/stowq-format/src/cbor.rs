//! Canonical deterministic CBOR (RFC 8949 §4.2.1) restricted to the value
//! set StowQ records need. Encoding is canonical by construction; decoding
//! accepts only canonical form: minimal-length integers, definite lengths
//! only, bytewise-sorted unique map keys, no tags, floats, negative
//! integers, or indefinite chunks. Anything else is an error, because a
//! non-canonical byte string can never have been produced by this crate.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TrailingBytes,
    UnexpectedEof,
    NonMinimalInteger,
    IndefiniteLength,
    UnsupportedMajorType(u8),
    UnsupportedSimple(u8),
    InvalidUtf8,
    UnsortedMapKeys,
    DuplicateMapKey,
    LengthOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::TrailingBytes => "trailing bytes after value",
            Error::UnexpectedEof => "unexpected end of input",
            Error::NonMinimalInteger => "integer not minimally encoded",
            Error::IndefiniteLength => "indefinite length not allowed",
            Error::UnsupportedMajorType(_) => "unsupported major type",
            Error::UnsupportedSimple(_) => "unsupported simple value",
            Error::InvalidUtf8 => "text string is not valid UTF-8",
            Error::UnsortedMapKeys => "map keys not in bytewise order",
            Error::DuplicateMapKey => "duplicate map key",
            Error::LengthOverflow => "declared length exceeds input",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

// ---------- Encoding ----------

fn push_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    match value {
        0..=23 => out.push(m | value as u8),
        24..=0xff => {
            out.push(m | 24);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn encoded_key_bytes(key: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(key, &mut out);
    out
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(n) => push_head(out, 0, *n),
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Bytes(b) => {
            push_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            push_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            push_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(pairs) => {
            let mut sorted: Vec<&(Value, Value)> = pairs.iter().collect();
            sorted.sort_by_key(|a| encoded_key_bytes(&a.0));
            push_head(out, 5, sorted.len() as u64);
            for (k, v) in sorted {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
    }
}

/// Encodes a value in canonical form. Map keys are sorted bytewise over
/// their encoded form.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

// ---------- Decoding ----------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.pos + n > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn head(&mut self) -> Result<(u8, u64), Error> {
        let b = self.take(1)?[0];
        let major = b >> 5;
        let info = b & 0x1f;
        let value = match info {
            0..=23 => info as u64,
            24 => {
                let v = self.take(1)?[0] as u64;
                if v < 24 {
                    return Err(Error::NonMinimalInteger);
                }
                v
            }
            25 => {
                let v = u16::from_be_bytes(self.take(2)?.try_into().unwrap());
                if v < 0x100 {
                    return Err(Error::NonMinimalInteger);
                }
                v as u64
            }
            26 => {
                let v = u32::from_be_bytes(self.take(4)?.try_into().unwrap());
                if v < 0x1_0000 {
                    return Err(Error::NonMinimalInteger);
                }
                v as u64
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if v < 0x1_0000_0000 {
                    return Err(Error::NonMinimalInteger);
                }
                v
            }
            _ => return Err(Error::IndefiniteLength),
        };
        Ok((major, value))
    }

    fn value(&mut self) -> Result<Value, Error> {
        let (major, value) = self.head()?;
        match major {
            0 => Ok(Value::Uint(value)),
            2 => {
                let len = value as usize;
                let bytes = self.take(len)?;
                Ok(Value::Bytes(bytes.to_vec()))
            }
            3 => {
                let len = value as usize;
                let bytes = self.take(len)?;
                let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(text.to_string()))
            }
            4 => {
                let len = value as usize;
                let mut items = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    items.push(self.value()?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = value as usize;
                let mut pairs = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    let k = self.value()?;
                    let v = self.value()?;
                    pairs.push((k, v));
                }
                // Canonical maps: keys strictly increasing bytewise.
                for window in pairs.windows(2) {
                    let a = encoded_key_bytes(&window[0].0);
                    let b = encoded_key_bytes(&window[1].0);
                    if a == b {
                        return Err(Error::DuplicateMapKey);
                    }
                    if a > b {
                        return Err(Error::UnsortedMapKeys);
                    }
                }
                Ok(Value::Map(pairs))
            }
            7 => match value {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                _ => Err(Error::UnsupportedSimple(value as u8)),
            },
            m => Err(Error::UnsupportedMajorType(m)),
        }
    }
}

/// Decodes exactly one canonical value covering the entire input.
pub fn decode(data: &[u8]) -> Result<Value, Error> {
    let mut r = Reader { data, pos: 0 };
    let v = r.value()?;
    if r.pos != data.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: Value) {
        let bytes = encode(&v);
        assert_eq!(decode(&bytes), Ok(v.clone()), "round trip failed for {v:?}");
    }

    #[test]
    fn scalar_round_trips() {
        round_trip(Value::Uint(0));
        round_trip(Value::Uint(23));
        round_trip(Value::Uint(24));
        round_trip(Value::Uint(0xff));
        round_trip(Value::Uint(0x100));
        round_trip(Value::Uint(0xffff));
        round_trip(Value::Uint(0x1_0000));
        round_trip(Value::Uint(0xffff_ffff));
        round_trip(Value::Uint(u64::MAX));
        round_trip(Value::Bool(true));
        round_trip(Value::Bool(false));
        round_trip(Value::Bytes(vec![]));
        round_trip(Value::Bytes(vec![1, 2, 3]));
        round_trip(Value::Text("hello".into()));
        round_trip(Value::Text("".into()));
        round_trip(Value::Array(vec![Value::Uint(1), Value::Bool(false)]));
        round_trip(Value::Map(vec![(Value::Text("a".into()), Value::Uint(1))]));
    }

    #[test]
    fn minimal_integers_enforced() {
        // 5 encoded as u8 (0x18 0x05) is non-minimal.
        assert_eq!(decode(&[0x18, 0x05]), Err(Error::NonMinimalInteger));
        // 100 encoded as u16.
        assert_eq!(decode(&[0x19, 0x00, 0x64]), Err(Error::NonMinimalInteger));
        // Boundary values are accepted in their minimal width.
        assert_eq!(decode(&[0x18, 0x18]), Ok(Value::Uint(24)));
    }

    #[test]
    fn map_keys_sorted_bytewise() {
        let m = Value::Map(vec![
            (Value::Text("a".into()), Value::Uint(1)),
            (Value::Text("ab".into()), Value::Uint(2)),
        ]);
        let bytes = encode(&m);
        // "a" (0x61 0x61) sorts before "ab" (0x62 0x61 0x62).
        let a = bytes.iter().position(|&b| b == 0x61).unwrap();
        assert_eq!(bytes[a], 0x61);
        assert_eq!(decode(&bytes), Ok(m));

        // Hand-built unsorted map is rejected: {"b":1, "a":2} in literal
        // canonical item encodings.
        let unsorted = [0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert_eq!(decode(&unsorted), Err(Error::UnsortedMapKeys));

        let dup = [0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
        assert_eq!(decode(&dup), Err(Error::DuplicateMapKey));
    }

    #[test]
    fn rejects_indefinite_and_unsupported() {
        // Indefinite byte string.
        assert_eq!(
            decode(&[0x5f, 0x41, 0x01, 0xff]),
            Err(Error::IndefiniteLength)
        );
        // Negative integer.
        assert_eq!(decode(&[0x20]), Err(Error::UnsupportedMajorType(1)));
        // Tag.
        assert_eq!(decode(&[0xc0, 0x01]), Err(Error::UnsupportedMajorType(6)));
        // Null, undefined, and floats. A half-precision float with a
        // small payload hits the minimality check; one with a real
        // mantissa reaches the simple-value rejection.
        assert_eq!(decode(&[0xf6]), Err(Error::UnsupportedSimple(22)));
        assert_eq!(decode(&[0xf7]), Err(Error::UnsupportedSimple(23)));
        assert_eq!(decode(&[0xf9, 0x00, 0x00]), Err(Error::NonMinimalInteger));
        assert_eq!(
            decode(&[0xf9, 0x3e, 0x00]),
            Err(Error::UnsupportedSimple(0))
        );
    }

    #[test]
    fn rejects_truncated_and_trailing() {
        assert_eq!(decode(&[0x18]), Err(Error::UnexpectedEof));
        assert_eq!(decode(&[0x43, 0x01, 0x02]), Err(Error::UnexpectedEof));
        assert_eq!(decode(&[0x01, 0x02]), Err(Error::TrailingBytes));
    }

    #[test]
    fn invalid_utf8_text_rejected() {
        assert_eq!(decode(&[0x62, 0xc3, 0x28]), Err(Error::InvalidUtf8));
    }
}
