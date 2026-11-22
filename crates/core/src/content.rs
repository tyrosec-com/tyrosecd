/// Rough text/binary detection: a NUL byte in the first 8 KiB = binary.
/// Deliberately no UTF-8 requirement: PHP files in Latin-1 are text.
pub fn is_text(data: &[u8]) -> bool {
    let head = &data[..data.len().min(8192)];
    !head.contains(&0)
}

/// ELF magic.
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == b"\x7fELF"
}

/// Open a file for reading **without** following a symlink (O_NOFOLLOW) and without blocking on FIFOs;
/// fstat verifies that it is a regular file (symlink race: lstat sees a harmless file,
/// which is then swapped for a link to /etc/shadow). Returns file + inode.
pub fn open_regular(path: &str) -> std::io::Result<(std::fs::File, u64)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok((f, m.ino()))
}

/// Reads at most `limit` bytes. `None` if the file is larger.
pub fn read_limited(path: &str, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
    Ok(read_limited_ino(path, limit)?.map(|(d, _)| d))
}

/// Like `read_limited`, additionally returning the inode of the file actually read.
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
        std::fs::write(&f, "hello").unwrap();
        let l = d.path().join("link.txt");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        assert_eq!(read_limited(f.to_str().unwrap(), 100).unwrap().unwrap(), b"hello");
        assert!(read_limited(l.to_str().unwrap(), 100).is_err());
        assert!(read_limited(d.path().to_str().unwrap(), 100).is_err()); // directory
        assert!(read_limited(f.to_str().unwrap(), 2).unwrap().is_none());
    }
}
