use std::io::Read;

use sha2::Digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sha256,
    Blake3,
}

impl std::str::FromStr for Algo {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha256" => Ok(Algo::Sha256),
            "blake3" => Ok(Algo::Blake3),
            _ => Err(format!("unknown hash algorithm: {s}")),
        }
    }
}

pub fn hash_bytes(algo: Algo, data: &[u8]) -> String {
    match algo {
        Algo::Sha256 => hex::encode(sha2::Sha256::digest(data)),
        Algo::Blake3 => blake3::hash(data).to_hex().to_string(),
    }
}

/// Hash of a file, streaming. Returns (hash, bytes read).
pub fn hash_file(algo: Algo, path: &str) -> std::io::Result<(String, u64)> {
    hash_reader(algo, std::fs::File::open(path)?)
}

/// Like `hash_file`, but without following a symlink, regular files only (see `content::open_regular`).
/// Additionally returns the inode of the file read.
pub fn hash_file_nofollow(algo: Algo, path: &str) -> std::io::Result<(String, u64, u64)> {
    let (f, ino) = crate::content::open_regular(path)?;
    let (h, n) = hash_reader(algo, f)?;
    Ok((h, n, ino))
}

fn hash_reader(algo: Algo, mut f: std::fs::File) -> std::io::Result<(String, u64)> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    match algo {
        Algo::Sha256 => {
            let mut h = sha2::Sha256::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                h.update(&buf[..n]);
            }
            Ok((hex::encode(h.finalize()), total))
        }
        Algo::Blake3 => {
            let mut h = blake3::Hasher::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                h.update(&buf[..n]);
            }
            Ok((h.finalize().to_hex().to_string(), total))
        }
    }
}

/// MD5 of a file (for WordPress checksums and dpkg md5sums).
pub fn md5_file(path: &str) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = md5::Md5::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

pub fn sha256_file(path: &str) -> std::io::Result<String> {
    hash_file(Algo::Sha256, path).map(|(h, _)| h)
}
