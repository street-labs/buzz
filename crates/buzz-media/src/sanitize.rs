//! Server-side image metadata stripping.
//!
//! The validation policy (`validation.rs`) is a strict structural allowlist:
//! stored blobs must be free of EXIF, XMP, comments, ICC profiles, private
//! chunks, and other unrestricted metadata channels. Real-world encoders
//! (phone cameras, screenshot tools, `sips`) emit EXIF APP1 segments and pHYs
//! chunks on nearly every image, so rejecting them made ordinary uploads
//! impossible. Instead of rejecting, the upload pipeline strips these channels
//! server-side and stores the sanitized bytes; the canonical-image checks then
//! run on exactly what gets stored.
//!
//! Stripping is removal-only: segment/chunk boundaries and pixel data are
//! never rewritten. The single exception is the WebP VP8X feature-flags byte,
//! whose metadata bits must be cleared alongside the dropped chunks.
//! Each function returns the input unchanged when it is already canonical,
//! so already-clean uploads pay one parse and zero copies.

use std::borrow::Cow;

/// Strip metadata channels from image bytes according to the same allowlist
/// the validator enforces. Returns `Cow::Borrowed` when the input is already
/// canonical.
pub fn sanitize_image<'a>(bytes: &'a [u8], mime: &str) -> Cow<'a, [u8]> {
    let sanitized: Vec<u8> = match mime {
        "image/jpeg" => sanitize_jpeg(bytes),
        "image/png" => sanitize_png(bytes),
        "image/webp" => sanitize_webp(bytes),
        "image/gif" => sanitize_gif(bytes),
        _ => return Cow::Borrowed(bytes),
    };
    if sanitized == bytes {
        Cow::Borrowed(bytes)
    } else {
        Cow::Owned(sanitized)
    }
}

// ── JPEG ────────────────────────────────────────────────────────────────────

fn canonical_jfif_app0(payload: &[u8]) -> bool {
    payload.len() >= 14
        && &payload[..5] == b"JFIF\0"
        && payload.len() == 14 + 3 * payload[12] as usize * payload[13] as usize
}

fn canonical_adobe_app14(payload: &[u8]) -> bool {
    payload.len() == 12 && &payload[..5] == b"Adobe"
}

fn sanitize_jpeg(bytes: &[u8]) -> Vec<u8> {
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..2]);
    let mut i = 2usize;
    while i < bytes.len() {
        if bytes[i] != 0xff {
            // Entropy-coded scan data — copy verbatim.
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // Skip 0xFF fill bytes (the validator ignores them too).
        while i < bytes.len() && bytes[i] == 0xff {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let marker = bytes[i];
        let marker_start = i - 1; // position of the 0xFF preceding the marker
        i += 1;
        if (0xd0..=0xd7).contains(&marker) || marker == 0x01 || marker == 0xd9 || marker == 0xd8 {
            out.extend_from_slice(&bytes[marker_start..i]);
            continue;
        }
        if i + 2 > bytes.len() {
            break;
        }
        let len = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
        if len < 2 || i.checked_add(len).is_none_or(|end| end > bytes.len()) {
            // Malformed — hand back the input unchanged; the validator will
            // reject it with the precise error.
            return bytes.to_vec();
        }
        let segment = &bytes[marker_start..i + len]; // FF + marker + length + payload
        let keep = match marker {
            0xe0 => canonical_jfif_app0(&bytes[i + 2..i + len]),
            0xee => canonical_adobe_app14(&bytes[i + 2..i + len]),
            0xe1..=0xed | 0xdf | 0xef | 0xfe => false,
            _ => true,
        };
        if keep {
            out.extend_from_slice(segment);
        }
        i += len;
    }
    out
}

// ── PNG ─────────────────────────────────────────────────────────────────────

const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Ancillary chunks the validator allows — colour/animation/rendering hints.
const PNG_KEEP_ANCILLARY: &[&[u8; 4]] = &[
    b"cHRM", b"gAMA", b"sBIT", b"sRGB", b"bKGD", b"hIST", b"tRNS", b"sPLT", b"acTL", b"fcTL",
    b"fdAT",
];

/// tEXt keywords that carry Buzz snapshot manifests (`.agent.png` /
/// `.team.png`); mirrors the validator's exemption. Exactly one snapshot
/// chunk is preserved per file.
fn png_is_snapshot_chunk(payload: &[u8]) -> bool {
    const KEYWORDS: [&[u8]; 2] = [b"buzz_agent_snapshot", b"buzz_team_snapshot"];
    KEYWORDS.iter().any(|keyword| {
        payload.len() > keyword.len()
            && &payload[..keyword.len()] == *keyword
            && payload[keyword.len()] == 0
    })
}

fn sanitize_png(bytes: &[u8]) -> Vec<u8> {
    if !bytes.starts_with(PNG_SIG) {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(PNG_SIG);
    let mut i = PNG_SIG.len();
    let mut changed = false;
    let mut kept_snapshot = false;
    while i + 12 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        let kind: [u8; 4] = bytes[i + 4..i + 8].try_into().unwrap();
        let end = match i.checked_add(12).and_then(|v| v.checked_add(len)) {
            Some(end) if end <= bytes.len() => end,
            _ => return bytes.to_vec(),
        };
        let chunk = &bytes[i..end]; // length + type + payload + CRC
        let payload = &bytes[i + 8..end - 4];
        let keep = if &kind == b"tEXt" {
            let snapshot = png_is_snapshot_chunk(payload);
            let keep = snapshot && !kept_snapshot;
            if snapshot {
                kept_snapshot = true;
            }
            keep
        } else if &kind == b"eXIf" || &kind == b"zTXt" || &kind == b"iTXt" || &kind == b"iCCP" {
            false
        } else if kind[0] & 0x20 != 0 {
            PNG_KEEP_ANCILLARY.contains(&&kind)
        } else {
            true
        };
        if keep {
            out.extend_from_slice(chunk);
        } else {
            changed = true;
        }
        i = end;
        if &kind == b"IEND" {
            break;
        }
    }
    if changed {
        out
    } else {
        bytes.to_vec()
    }
}

// ── WebP ────────────────────────────────────────────────────────────────────

fn sanitize_webp(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return bytes.to_vec();
    }
    let declared = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if declared.checked_add(8) != Some(bytes.len()) {
        return bytes.to_vec();
    }
    const KEEP: &[&[u8; 4]] = &[b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF"];
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..12]); // RIFF header, size rewritten below
    let mut i = 12usize;
    let mut changed = false;
    while i + 8 <= bytes.len() {
        let kind: [u8; 4] = bytes[i..i + 4].try_into().unwrap();
        let len = u32::from_le_bytes(bytes[i + 4..i + 8].try_into().unwrap()) as usize;
        let padded = match len.checked_add(len & 1) {
            Some(p) if i + 8 + p <= bytes.len() => p,
            _ => return bytes.to_vec(),
        };
        let chunk = &bytes[i..i + 8 + padded];
        if KEEP.contains(&&kind) {
            if &kind == b"VP8X" {
                // Clear the ICC (0x20), EXIF (0x08), and XMP (0x04) presence
                // flags — the chunks they point at are dropped below.
                let mut clean = chunk.to_vec();
                if let Some(first) = clean.get_mut(8) {
                    let cleared = *first & !(0x20 | 0x08 | 0x04);
                    if cleared != *first {
                        *first = cleared;
                        changed = true;
                    }
                }
                out.extend_from_slice(&clean);
            } else {
                out.extend_from_slice(chunk);
            }
        } else {
            changed = true;
        }
        i += 8 + padded;
    }
    if changed {
        let riff_size = (out.len() - 8) as u32;
        out[4..8].copy_from_slice(&riff_size.to_le_bytes());
        out
    } else {
        bytes.to_vec()
    }
}

// ── GIF ─────────────────────────────────────────────────────────────────────

fn sanitize_gif(bytes: &[u8]) -> Vec<u8> {
    if !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) || bytes.len() < 13 {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 13usize;
    let packed = bytes[10];
    if packed & 0x80 != 0 {
        let table_len = 3usize << ((packed & 0x07) as usize + 1);
        match i.checked_add(table_len) {
            Some(end) if end <= bytes.len() => {
                out.extend_from_slice(&bytes[..end]);
                i = end;
            }
            _ => return bytes.to_vec(),
        }
    } else {
        out.extend_from_slice(&bytes[..i]);
    }
    let mut changed = false;
    // Copy a run of length-prefixed data sub-blocks (terminated by a 0 block).
    fn copy_sub_blocks(bytes: &[u8], i: &mut usize, out: &mut Vec<u8>) -> bool {
        loop {
            match bytes.get(*i) {
                Some(&0) => {
                    out.push(0);
                    *i += 1;
                    return true;
                }
                Some(&len) => {
                    if *i + 1 + len as usize > bytes.len() {
                        return false;
                    }
                    out.extend_from_slice(&bytes[*i..*i + 1 + len as usize]);
                    *i += 1 + len as usize;
                }
                None => return false,
            }
        }
    }
    while let Some(&block) = bytes.get(i) {
        match block {
            0x2c => {
                // Image descriptor + optional local colour table + LZW data.
                if i + 10 > bytes.len() {
                    return bytes.to_vec();
                }
                let image_packed = bytes[i + 9];
                let mut end = i + 10;
                if image_packed & 0x80 != 0 {
                    let table_len = 3usize << ((image_packed & 0x07) as usize + 1);
                    end = match end.checked_add(table_len) {
                        Some(e) if e <= bytes.len() => e,
                        _ => return bytes.to_vec(),
                    };
                }
                out.extend_from_slice(&bytes[i..end]);
                i = end;
                if !copy_sub_blocks(bytes, &mut i, &mut out) {
                    return bytes.to_vec();
                }
            }
            0x21 => {
                let label = match bytes.get(i + 1) {
                    Some(&l) => l,
                    None => return bytes.to_vec(),
                };
                let mut j = i + 2;
                let keep = match label {
                    // Graphic Control Extension: fixed-shape rendering state.
                    0xf9 => bytes.get(j) == Some(&4),
                    0xff => {
                        matches!(bytes.get(j), Some(&11))
                            && j + 12 <= bytes.len()
                            && (&bytes[j + 1..j + 12] == b"NETSCAPE2.0"
                                || &bytes[j + 1..j + 12] == b"ANIMEXTS1.0")
                    }
                    _ => false,
                };
                if keep {
                    out.extend_from_slice(&bytes[i..j]);
                    // Copy the extension's sub-blocks (GCE has exactly one).
                    if !copy_sub_blocks(bytes, &mut j, &mut out) {
                        return bytes.to_vec();
                    }
                } else {
                    // Skip the extension's sub-blocks.
                    loop {
                        match bytes.get(j) {
                            Some(&0) => {
                                j += 1;
                                break;
                            }
                            Some(&len) if j + 1 + len as usize <= bytes.len() => {
                                j += 1 + len as usize
                            }
                            _ => return bytes.to_vec(),
                        }
                    }
                    changed = true;
                }
                i = j;
            }
            0x3b => {
                out.push(0x3b);
                i += 1;
                break;
            }
            _ => return bytes.to_vec(),
        }
    }
    if changed && i == bytes.len() {
        out
    } else {
        bytes.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid 1x1 grayscale JPEG: SOI, extras, DQT, SOF0, DHT, SOS + data, EOI.
    fn tiny_jpeg_with(extras: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0xff, 0xd8];
        for (marker, payload) in extras {
            out.push(0xff);
            out.push(*marker);
            out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
            out.extend_from_slice(payload);
        }
        // DQT
        out.extend_from_slice(&[0xff, 0xdb, 0x00, 0x43, 0x00]);
        out.extend_from_slice(&[0u8; 64]);
        // SOF0: 1x1, 1 component
        out.extend_from_slice(&[
            0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
        ]);
        // DHT
        out.extend_from_slice(&[0xff, 0xc4, 0x00, 0x14, 0x00]);
        out.extend_from_slice(&[0u8; 17]);
        // SOS + minimal entropy data + EOI
        out.extend_from_slice(&[0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00]);
        out.extend_from_slice(&[0x3c, 0xfa, 0xff, 0xd9]);
        out
    }

    #[test]
    fn jpeg_exif_app1_is_stripped() {
        let exif = b"Exif\0\0II*\0\0\0\0\0".to_vec();
        let bytes = tiny_jpeg_with(&[(0xe1, exif)]);
        let sanitized = sanitize_image(&bytes, "image/jpeg");
        assert_ne!(sanitized.as_ref(), &bytes[..]);
        assert!(!sanitized.windows(4).any(|w| w == *b"Exif"));
        // Still ends with EOI and retains the scan + critical segments.
        assert!(sanitized.ends_with(&[0xff, 0xd9]));
        assert!(sanitized.windows(2).any(|w| w == [0xff, 0xda]));
    }

    #[test]
    fn jpeg_canonical_jfif_app0_is_kept() {
        let mut jfif = b"JFIF\0".to_vec();
        jfif.extend_from_slice(&[1, 1, 0, 0, 1, 0, 1, 0, 0]); // version, units, density, 1x1 thumb
        let bytes = tiny_jpeg_with(&[(0xe0, jfif)]);
        assert!(matches!(
            sanitize_image(&bytes, "image/jpeg"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn png_phys_is_stripped() {
        fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(payload);
            out.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder
            out
        }
        let mut bytes = PNG_SIG.to_vec();
        bytes.extend_from_slice(&chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        bytes.extend_from_slice(&chunk(b"pHYs", &[0, 0, 0x0b, 0x13, 0, 0, 0, 0x0b, 0x13, 1]));
        bytes.extend_from_slice(&chunk(b"IDAT", &[0x78, 0x9c, 0x63, 0x60, 0, 0, 0, 2, 0, 1]));
        bytes.extend_from_slice(&chunk(b"IEND", &[]));
        let sanitized = sanitize_image(&bytes, "image/png");
        assert_ne!(sanitized.as_ref(), &bytes[..]);
        assert!(sanitized.windows(4).all(|w| w != *b"pHYs"));
        // Critical chunks and IEND survive.
        assert!(sanitized.windows(4).any(|w| w == *b"IHDR"));
        assert!(sanitized.ends_with(&chunk(b"IEND", &[])));
    }

    #[test]
    fn png_snapshot_text_chunk_is_preserved() {
        fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(payload);
            out.extend_from_slice(&[0, 0, 0, 0]);
            out
        }
        let mut bytes = PNG_SIG.to_vec();
        bytes.extend_from_slice(&chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        bytes.extend_from_slice(&chunk(b"tEXt", b"buzz_agent_snapshot\0manifest"));
        bytes.extend_from_slice(&chunk(b"IDAT", &[1, 2, 3]));
        bytes.extend_from_slice(&chunk(b"IEND", &[]));
        assert!(matches!(
            sanitize_image(&bytes, "image/png"),
            Cow::Borrowed(_)
        ));
    }
}
