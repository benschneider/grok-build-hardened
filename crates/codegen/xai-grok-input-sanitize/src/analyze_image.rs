//! Fast statistical / container checks on image payloads (no full decode).
//!
//! Goal: catch **packed stego**, **high-entropy shells**, and **odd PNG
//! ancillary mass** without pulling a full image codec. Reliable, cheap
//! signals complement text residual analysis on tool/MCP/vision paths.

use crate::analyze::{finish_report, shannon_entropy, AnalysisReport, AnalysisSignal, SignalKind};
use crate::note::format_untrusted_note;
use crate::sanitize::SanitizeResult;
use crate::untrusted::UntrustedSource;

/// Analyze raw image bytes (+ optional mime hint).
pub fn analyze_image_bytes(bytes: &[u8], mime: Option<&str>) -> AnalysisReport {
    if bytes.len() < 32 {
        return AnalysisReport::empty();
    }

    let mut signals = Vec::new();

    // ── Global byte statistics ───────────────────────────────────────
    let h = shannon_entropy(bytes);
    // Natural photos after codec compression are high-entropy but rarely
    // near-perfect 8.0 with uniform histogram. Near-max entropy + low
    // chi-square vs uniform is a classic packed/encrypted/stego shell.
    let chi = crate::analyze::chi_square_uniform(bytes);
    if bytes.len() >= 512 && h >= 7.85 {
        let weight = if h >= 7.95 && chi < 400.0 {
            36
        } else if h >= 7.90 {
            28
        } else {
            18
        };
        signals.push(AnalysisSignal {
            kind: SignalKind::ImageStatisticalAnomaly,
            weight,
            detail: format!(
                "Image byte entropy ≈ {h:.3} bits/byte (χ²_uniform≈{chi:.0}) — \
                 packed/encrypted/stego-like payload"
            ),
        });
    }

    // LSB monobit on full payload (common naive LSB stego leaves fair coins).
    if bytes.len() >= 256 {
        let ones = bytes.iter().filter(|b| *b & 1 == 1).count();
        let n = bytes.len() as f64;
        let p1 = ones as f64 / n;
        let e = n / 2.0;
        let chi_lsb = (ones as f64 - e).powi(2) / e + ((n - ones as f64) - e).powi(2) / e;
        if (0.485..=0.515).contains(&p1) && chi_lsb < 1.0 && bytes.len() >= 1024 {
            signals.push(AnalysisSignal {
                kind: SignalKind::ImageStatisticalAnomaly,
                weight: 24,
                detail: format!(
                    "Image LSBs are suspiciously fair (p1={p1:.3}, χ²={chi_lsb:.2}) — \
                     possible LSB steganography"
                ),
            });
        }
    }

    // ── Container-specific ───────────────────────────────────────────
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'])
        || mime.is_some_and(|m| m.contains("png"))
    {
        signal_png_container(bytes, &mut signals);
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) || mime.is_some_and(|m| m.contains("jpeg") || m.contains("jpg")) {
        signal_jpeg_stub(bytes, &mut signals);
    }

    finish_report(signals)
}

/// Decode standard/URL-safe base64 (no padding required) best-effort.
pub fn decode_base64_image(data: &str) -> Option<Vec<u8>> {
    let s: String = data
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    // Manual base64 decode without extra deps.
    decode_b64(&s)
}

/// If analysis is elevated, return a model-facing warning note for the image.
pub fn image_untrusted_note(bytes: &[u8], mime: Option<&str>) -> Option<String> {
    let report = analyze_image_bytes(bytes, mime);
    if !report.should_warn() {
        return None;
    }
    // Reuse note formatter with a synthetic sanitize result.
    let synthetic = SanitizeResult {
        text: String::new(),
        hits: Vec::new(),
        original_len: bytes.len(),
        cleaned_len: bytes.len(),
        analysis: report,
    };
    Some(format_untrusted_note(
        &synthetic,
        UntrustedSource::File, // vision/tool images treated as external file-class
    ))
}

fn signal_png_container(bytes: &[u8], out: &mut Vec<AnalysisSignal>) {
    if bytes.len() < 8 {
        return;
    }
    let mut i = 8usize; // after signature
    let mut idat = 0u64;
    let mut ancillary = 0u64;
    let mut textish = 0u64;
    let mut unknown_big = 0u64;
    let mut chunks = 0usize;

    while i + 12 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let typ = &bytes[i + 4..i + 8];
        let data_start = i + 8;
        let data_end = data_start.saturating_add(len);
        if data_end + 4 > bytes.len() {
            break;
        }
        chunks += 1;
        let is_critical = typ[0].is_ascii_uppercase();
        if typ == b"IDAT" {
            idat += len as u64;
        } else if typ == b"tEXt" || typ == b"zTXt" || typ == b"iTXt" {
            textish += len as u64;
            ancillary += len as u64;
        } else if !is_critical {
            ancillary += len as u64;
            if len >= 4096 {
                unknown_big += len as u64;
            }
        }
        if typ == b"IEND" {
            break;
        }
        i = data_end + 4; // skip CRC
        if chunks > 10_000 {
            break;
        }
    }

    let total = bytes.len() as u64;
    if textish >= 256 {
        out.push(AnalysisSignal {
            kind: SignalKind::ImageContainerAnomaly,
            weight: if textish >= 4096 { 30 } else { 18 },
            detail: format!(
                "PNG text/ztxt/itxt ancillary mass {textish} bytes — possible hidden payload in metadata"
            ),
        });
    }
    if total > 0 && ancillary > idat.saturating_mul(2).max(2048) && ancillary >= 4096 {
        out.push(AnalysisSignal {
            kind: SignalKind::ImageContainerAnomaly,
            weight: 26,
            detail: format!(
                "PNG ancillary mass {ancillary}B dwarfs IDAT {idat}B — container stego / polyglot risk"
            ),
        });
    }
    if unknown_big >= 8192 {
        out.push(AnalysisSignal {
            kind: SignalKind::ImageContainerAnomaly,
            weight: 22,
            detail: format!(
                "PNG has large non-standard ancillary chunk data ({unknown_big}B)"
            ),
        });
    }
}

fn signal_jpeg_stub(bytes: &[u8], out: &mut Vec<AnalysisSignal>) {
    // Trailing data after EOI (FFD9) is a common polyglot / stego append.
    if let Some(pos) = find_subslice(bytes, &[0xFF, 0xD9]) {
        let trailing = bytes.len().saturating_sub(pos + 2);
        if trailing >= 256 {
            out.push(AnalysisSignal {
                kind: SignalKind::ImageContainerAnomaly,
                weight: if trailing >= 4096 { 28 } else { 18 },
                detail: format!(
                    "JPEG has {trailing} bytes after EOI — trailing stego/polyglot payload"
                ),
            });
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ── minimal base64 (std alphabet) ────────────────────────────────────

fn decode_b64(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => None,
            _ => None,
        }
    }
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if clean.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &c in &clean {
        if c == b'=' {
            break;
        }
        let v = val(c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_flag_high_entropy() {
        // Near-uniform payload
        let mut bytes = Vec::with_capacity(2048);
        for i in 0..2048u32 {
            bytes.push(((i.wrapping_mul(1103515245).wrapping_add(12345)) >> 16) as u8);
        }
        let r = analyze_image_bytes(&bytes, Some("application/octet-stream"));
        assert!(
            r.score > 0,
            "expected some image statistical signal, got {:?}",
            r.signals
        );
    }

    #[test]
    fn png_with_large_text_chunk_flagged() {
        // Minimal-ish PNG signature + synthetic tEXt chunk (not a valid CRC —
        // parser only reads lengths/types).
        let mut bytes = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        // IHDR len=13
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&[0u8; 13]);
        bytes.extend_from_slice(&0u32.to_be_bytes()); // fake CRC
        // tEXt with 3000 bytes
        let text = vec![b'A'; 3000];
        bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
        bytes.extend_from_slice(b"tEXt");
        bytes.extend_from_slice(&text);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        // IEND
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"IEND");
        bytes.extend_from_slice(&0u32.to_be_bytes());

        let r = analyze_image_bytes(&bytes, Some("image/png"));
        assert!(
            r.signals
                .iter()
                .any(|s| s.kind == SignalKind::ImageContainerAnomaly),
            "signals={:?}",
            r.signals
        );
    }

    #[test]
    fn jpeg_trailing_after_eoi() {
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xD9];
        bytes.extend(std::iter::repeat(0x41).take(500));
        let r = analyze_image_bytes(&bytes, Some("image/jpeg"));
        assert!(
            r.signals
                .iter()
                .any(|s| s.kind == SignalKind::ImageContainerAnomaly),
            "signals={:?}",
            r.signals
        );
    }

    #[test]
    fn base64_roundtrip_decode() {
        // "hi" = aGk=
        let d = decode_base64_image("aGk=").unwrap();
        assert_eq!(d, b"hi");
    }
}
