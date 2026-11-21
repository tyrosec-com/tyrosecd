//! Diff und Patch auf Byte-Ebene (kein UTF-8-Zwang, Latin-1 und CRLF
//! bleiben erhalten). Dieselbe Bibliothek erzeugt und wendet an, damit der
//! spätere Ingest exakt dieselbe Semantik hat (Hauptplan 27, Spike Tag 5).

use anyhow::{anyhow, Result};

pub struct DiffResult {
    pub patch: Vec<u8>,
    /// Anzahl geänderter Zeilen (+ und −).
    pub changed_lines: u32,
}

pub fn make_patch(old: &[u8], new: &[u8]) -> DiffResult {
    let patch = diffy::create_patch_bytes(old, new);
    let bytes = patch.to_bytes();
    let mut changed = 0u32;
    for hunk in patch.hunks() {
        for line in hunk.lines() {
            match line {
                diffy::Line::Insert(_) | diffy::Line::Delete(_) => changed += 1,
                diffy::Line::Context(_) => {}
            }
        }
    }
    DiffResult { patch: bytes, changed_lines: changed }
}

pub fn apply_patch(old: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    let p = diffy::Patch::from_bytes(patch).map_err(|e| anyhow!("Patch nicht lesbar: {e}"))?;
    diffy::apply_bytes(old, &p).map_err(|e| anyhow!("Patch nicht anwendbar: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash_bytes, Algo};

    fn roundtrip(old: &[u8], new: &[u8]) {
        let d = make_patch(old, new);
        let applied = apply_patch(old, &d.patch).expect("apply");
        assert_eq!(
            hash_bytes(Algo::Sha256, &applied),
            hash_bytes(Algo::Sha256, new),
            "Round-Trip fehlgeschlagen"
        );
    }

    #[test]
    fn simple() {
        roundtrip(b"a\nb\nc\n", b"a\nB\nc\n");
    }
    #[test]
    fn no_trailing_newline() {
        roundtrip(b"a\nb", b"a\nb\nc");
        roundtrip(b"a\nb\n", b"a\nb");
    }
    #[test]
    fn crlf() {
        roundtrip(b"a\r\nb\r\n", b"a\r\nX\r\nb\r\n");
        roundtrip(b"a\r\nb\r\n", b"a\nb\n");
    }
    #[test]
    fn latin1() {
        roundtrip(b"<?php echo 'Gr\xfc\xdfe';\n", b"<?php echo 'Gr\xfc\xdfe Welt';\n");
    }
    #[test]
    fn empty_and_long_lines() {
        roundtrip(b"", b"neu\n");
        roundtrip(b"x\n", b"");
        let long_a = vec![b'a'; 200_000];
        let mut long_b = long_a.clone();
        long_b[100_000] = b'b';
        roundtrip(&long_a, &long_b);
    }
    #[test]
    fn webshell_append() {
        let old = b"<?php\n/* core */\nfunction x() { return 1; }\n".to_vec();
        let mut new = old.clone();
        new.extend_from_slice(b"@eval(base64_decode($_POST['c']));\n");
        let d = make_patch(&old, &new);
        assert_eq!(d.changed_lines, 1);
        roundtrip(&old, &new);
    }
}
