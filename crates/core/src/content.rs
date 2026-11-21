/// Grobe Text/Binär-Erkennung: NUL-Byte in den ersten 8 KiB = binär.
/// Bewusst keine UTF-8-Pflicht: PHP-Dateien in Latin-1 sind Text.
pub fn is_text(data: &[u8]) -> bool {
    let head = &data[..data.len().min(8192)];
    !head.contains(&0)
}

/// ELF-Magic.
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == b"\x7fELF"
}

/// Datei zum Lesen öffnen, **ohne** einem Symlink zu folgen (O_NOFOLLOW) und ohne an FIFOs zu blockieren;
/// per fstat geprüft, dass es eine normale Datei ist (Symlink-Wettlauf: lstat sieht eine harmlose Datei,
/// danach wird sie gegen einen Link auf /etc/shadow getauscht). Liefert Datei + Inode.
pub fn open_regular(path: &str) -> std::io::Result<(std::fs::File, u64)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "keine normale Datei"));
    }
    Ok((f, m.ino()))
}

/// Liest höchstens `limit` Bytes. `None`, wenn die Datei größer ist.
pub fn read_limited(path: &str, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
    Ok(read_limited_ino(path, limit)?.map(|(d, _)| d))
}

/// Wie `read_limited`, zusätzlich mit der Inode der tatsächlich gelesenen Datei.
pub fn read_limited_ino(path: &str, limit: u64) -> std::io::Result<Option<(Vec<u8>, u64)>> {
    use std::io::Read;
    let (f, ino) = open_regular(path)?;
    let mut buf = Vec::new();
    f.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        Ok(None)
    } else {
        Ok(Some((buf, ino)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlinks_are_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a.txt");
        std::fs::write(&f, "hallo").unwrap();
        let l = d.path().join("link.txt");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        assert_eq!(read_limited(f.to_str().unwrap(), 100).unwrap().unwrap(), b"hallo");
        assert!(read_limited(l.to_str().unwrap(), 100).is_err());
        assert!(read_limited(d.path().to_str().unwrap(), 100).is_err()); // Ordner
        assert!(read_limited(f.to_str().unwrap(), 2).unwrap().is_none());
    }
}
