//! Safe Git check without the git program: `git status` as root used to run
//! commands from the repository configuration (core.fsmonitor, filters via .gitattributes, hooks). Here only
//! `.git/index` (DIRC v2/v3/v4) is read and compared with the working tree:
//! - no configuration, no hooks, no filters/attributes evaluated, no object store read,
//! - `.git` and `.git/index` opened without symlinks (O_NOFOLLOW), index at most 64 MiB, checksum verified,
//! - working-tree files opened component by component without symlinks (a symlinked directory counts, as in Git,
//!   as "deleted"), only regular files hashed, paths with `..`/`.git`/empty components skipped,
//! - size/mtime equal and not "racy" → unchanged; otherwise SHA-1 of `blob <len>\0<content>` against the index.
//!
//! Detects modified and deleted tracked files. Untracked files are left out (that would require evaluating
//! .gitignore). Repositories with content filters (Git LFS, line-ending conversion) may appear "modified" after
//! copies with a new mtime – the result then carries a note.

use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const MAX_INDEX: u64 = 64 << 20;
/// largest file that is hashed (larger ones with differing size/mtime count as modified, without hashing)
const MAX_HASH_FILE: u64 = 256 << 20;
/// hash budget per repository
const MAX_HASH_TOTAL: u64 = 2 << 30;
const MAX_ENTRIES: usize = 2_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub mtime_s: u32,
    pub mtime_ns: u32,
    pub mode: u32,
    pub size: u32,
    pub sha1: [u8; 20],
    /// conflict stage, skip-worktree, intent-to-add, assume-valid → do not compare
    pub skip: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Modified,
    Deleted,
    /// file ↔ symlink ↔ directory
    TypeChanged,
}

#[derive(Debug, Default)]
pub struct Status {
    pub changes: Vec<(String, Change)>,
    pub entries: usize,
    pub skipped: usize,
    pub hashed_bytes: u64,
    pub budget_exhausted: bool,
}

// ---------------------------------------------------------------- SHA-1 (only for Git blob IDs)

pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    len: usize,
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1 { h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0], buf: [0; 64], len: 0, total: 0 }
    }
}

impl Sha1 {
    fn block(&mut self, b: &[u8]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut bb, mut c, mut d, mut e] = self.h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((bb & c) | (!bb & d), 0x5A827999),
                20..=39 => (bb ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((bb & c) | (bb & d) | (c & d), 0x8F1BBCDC),
                _ => (bb ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = bb.rotate_left(30);
            bb = a;
            a = t;
        }
        for (h, v) in self.h.iter_mut().zip([a, bb, c, d, e]) {
            *h = h.wrapping_add(v);
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.len > 0 {
            let n = (64 - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len < 64 {
                return; // everything in the buffer
            }
            let b = self.buf;
            self.block(&b);
            self.len = 0;
        }
        while data.len() >= 64 {
            self.block(&data[..64]);
            data = &data[64..];
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.len = data.len();
    }

    pub fn finish(mut self) -> [u8; 20] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.len != 56 {
            self.update(&[0]);
        }
        let mut b = self.buf;
        b[56..].copy_from_slice(&bits.to_be_bytes());
        self.block(&b);
        let mut out = [0u8; 20];
        for (i, h) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&h.to_be_bytes());
        }
        out
    }
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut s = Sha1::default();
    s.update(data);
    s.finish()
}

/// Git blob ID of some content: SHA-1 over `blob <len>\0<content>`
pub fn blob_id(data: &[u8]) -> [u8; 20] {
    let mut s = Sha1::default();
    s.update(format!("blob {}\0", data.len()).as_bytes());
    s.update(data);
    s.finish()
}

// ---------------------------------------------------------------- reading the index

fn be32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
}

/// path from the index is harmless (relative, no empty/./.. components, no `.git`)
fn safe_rel(p: &str) -> bool {
    !p.is_empty() && !p.starts_with('/') && p.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && !c.eq_ignore_ascii_case(".git"))
}

/// Parse the index (DIRC v2/v3/v4). Verifies the trailing checksum (except with index.skipHash = all zeros).
pub fn parse_index(data: &[u8]) -> Result<Vec<Entry>, String> {
    if data.len() < 12 + 20 || &data[..4] != b"DIRC" {
        return Err("not a Git index".into());
    }
    let (body, sum) = data.split_at(data.len() - 20);
    if sum.iter().any(|b| *b != 0) && sha1(body) != sum {
        return Err("index checksum mismatch".into());
    }
    let version = be32(data, 4).unwrap();
    if !(2..=4).contains(&version) {
        return Err(format!("index version {version} not supported"));
    }
    let count = be32(data, 8).unwrap() as usize;
    if count > MAX_ENTRIES {
        return Err("too many entries".into());
    }
    let mut out = Vec::with_capacity(count.min(100_000));
    let mut pos = 12;
    let mut prev: Vec<u8> = Vec::new();
    let bad = || "index corrupt".to_string();
    for _ in 0..count {
        let start = pos;
        let f = |i: usize| be32(body, start + i * 4).ok_or_else(bad);
        let (mtime_s, mtime_ns, mode, size) = (f(2)?, f(3)?, f(6)?, f(9)?);
        let sha1: [u8; 20] = body.get(start + 40..start + 60).ok_or_else(bad)?.try_into().unwrap();
        let flags = u16::from_be_bytes(body.get(start + 60..start + 62).ok_or_else(bad)?.try_into().unwrap());
        pos = start + 62;
        let mut skip = flags & 0x8000 != 0 || (flags >> 12) & 0x3 != 0; // assume-valid, conflict stage
        if flags & 0x4000 != 0 {
            if version < 3 {
                return Err(bad());
            }
            let ext = u16::from_be_bytes(body.get(pos..pos + 2).ok_or_else(bad)?.try_into().unwrap());
            skip |= ext & 0x6000 != 0; // skip-worktree, intent-to-add
            pos += 2;
        }
        let name: Vec<u8> = if version == 4 {
            // prefix compression: varint (number of bytes removed from the previous path), then the rest up to NUL
            let mut c = *body.get(pos).ok_or_else(bad)?;
            pos += 1;
            let mut strip = (c & 0x7f) as usize;
            while c & 0x80 != 0 {
                c = *body.get(pos).ok_or_else(bad)?;
                pos += 1;
                strip = strip.checked_add(1).and_then(|v| v.checked_mul(128)).ok_or_else(bad)? | (c & 0x7f) as usize;
            }
            if strip > prev.len() {
                return Err(bad());
            }
            let end = pos + body.get(pos..).ok_or_else(bad)?.iter().position(|b| *b == 0).ok_or_else(bad)?;
            let mut n = prev[..prev.len() - strip].to_vec();
            n.extend_from_slice(&body[pos..end]);
            pos = end + 1;
            n
        } else {
            let end = pos + body.get(pos..).ok_or_else(bad)?.iter().position(|b| *b == 0).ok_or_else(bad)?;
            let n = body[pos..end].to_vec();
            // entry padded to 8 bytes (at least one NUL)
            pos = start + ((end - start + 8) & !7);
            n
        };
        if pos > body.len() {
            return Err(bad());
        }
        prev = name.clone();
        let path = String::from_utf8(name).map_err(|_| bad())?;
        out.push(Entry { path, mtime_s, mtime_ns, mode, size, sha1, skip });
    }
    Ok(out)
}

// ---------------------------------------------------------------- file system (only via descriptors, no symlinks)

fn cstr(s: &str) -> Option<CString> {
    CString::new(s).ok()
}

fn openat(dir: &OwnedFd, name: &str, flags: i32) -> Option<OwnedFd> {
    let c = cstr(name)?;
    // SAFETY: valid fd and C string; return value checked
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_dir_abs(path: &str) -> Option<OwnedFd> {
    // SAFETY: constant C string
    let root = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if root < 0 {
        return None;
    }
    let mut fd = unsafe { OwnedFd::from_raw_fd(root) };
    for part in path.split('/').filter(|c| !c.is_empty()) {
        fd = openat(&fd, part, libc::O_RDONLY | libc::O_DIRECTORY)?;
    }
    Some(fd)
}

fn fstat(fd: &OwnedFd) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd, st writable
    (unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0).then_some(st)
}

fn lstatat(dir: &OwnedFd, name: &str) -> Option<libc::stat> {
    let c = cstr(name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and C string
    (unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0).then_some(st)
}

fn is(st: &libc::stat, t: libc::mode_t) -> bool {
    st.st_mode & libc::S_IFMT == t
}

/// Read `.git/index` of a working tree: `.git` must be a real directory (no gitfile references,
/// no symlinks), `index` a regular file ≤ 64 MiB. → (content, mtime seconds of the index)
pub fn read_index(repo: &str) -> Result<(Vec<u8>, i64), String> {
    let r = open_dir_abs(repo).ok_or("repository directory cannot be opened safely")?;
    let git = openat(&r, ".git", libc::O_RDONLY | libc::O_DIRECTORY).ok_or(".git is not a directory (or is a symlink)")?;
    let idx = openat(&git, "index", libc::O_RDONLY | libc::O_NONBLOCK).ok_or("no index")?;
    let st = fstat(&idx).ok_or("index not readable")?;
    if !is(&st, libc::S_IFREG) || st.st_size as u64 > MAX_INDEX {
        return Err("index is not a regular file or too large".into());
    }
    let mut data = Vec::new();
    std::fs::File::from(idx).take(MAX_INDEX + 1).read_to_end(&mut data).map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_INDEX {
        return Err("index too large".into());
    }
    Ok((data, st.st_mtime))
}

/// Resolve a working-tree file without symlinks: (parent directory fd, lstat of the target) – None if a component is
/// missing or a directory component is not a real directory (Git: "beyond a symbolic link" = deleted)
fn locate(repo: &OwnedFd, rel: &str) -> Option<(OwnedFd, String, libc::stat)> {
    let parts: Vec<&str> = rel.split('/').collect();
    let (name, dirs) = parts.split_last()?;
    let mut fd = openat(repo, ".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    for d in dirs {
        fd = openat(&fd, d, libc::O_RDONLY | libc::O_DIRECTORY)?;
    }
    let st = lstatat(&fd, name)?;
    Some((fd, name.to_string(), st))
}

fn hash_file(dir: &OwnedFd, name: &str, expect_size: u64) -> Option<[u8; 20]> {
    let fd = openat(dir, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let st = fstat(&fd)?;
    if !is(&st, libc::S_IFREG) || st.st_size as u64 != expect_size {
        return None;
    }
    let mut s = Sha1::default();
    s.update(format!("blob {expect_size}\0").as_bytes());
    let mut f = std::fs::File::from(fd);
    let mut buf = vec![0u8; 64 << 10];
    let mut n_total = 0u64;
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        n_total += n as u64;
        if n_total > expect_size {
            return None;
        }
        s.update(&buf[..n]);
    }
    (n_total == expect_size).then(|| s.finish())
}

fn readlink_at(dir: &OwnedFd, name: &str) -> Option<Vec<u8>> {
    let c = cstr(name)?;
    let mut buf = vec![0u8; 4096];
    // SAFETY: valid fd/C string, buffer writable
    let n = unsafe { libc::readlinkat(dir.as_raw_fd(), c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    (n >= 0).then(|| {
        buf.truncate(n as usize);
        buf
    })
}

/// Compare working tree `repo` against its index
pub fn status(repo: &str) -> Result<Status, String> {
    let (data, index_mtime) = read_index(repo)?;
    let entries = parse_index(&data)?;
    let r = open_dir_abs(repo).ok_or("repository directory cannot be opened safely")?;
    let mut st = Status { entries: entries.len(), ..Default::default() };
    for e in &entries {
        let kind = e.mode & 0o170000;
        if e.skip || kind == 0o160000 || !safe_rel(&e.path) || !(kind == 0o100000 || kind == 0o120000) {
            st.skipped += 1; // submodules, conflicts, hidden entries, suspicious paths
            continue;
        }
        let Some((dir, name, s)) = locate(&r, &e.path) else {
            st.changes.push((e.path.clone(), Change::Deleted));
            continue;
        };
        if kind == 0o120000 {
            if !is(&s, libc::S_IFLNK) {
                st.changes.push((e.path.clone(), Change::TypeChanged));
            } else if !matches!(readlink_at(&dir, &name), Some(t) if blob_id(&t) == e.sha1) {
                st.changes.push((e.path.clone(), Change::Modified));
            }
            continue;
        }
        if !is(&s, libc::S_IFREG) {
            st.changes.push((e.path.clone(), Change::TypeChanged));
            continue;
        }
        let size = s.st_size as u64;
        // the index stores the size truncated to 32 bits; nanoseconds are not compared (as in Git without USE_NSEC)
        let racy = e.mtime_s as i64 >= index_mtime;
        if size as u32 == e.size && s.st_mtime as u32 == e.mtime_s && !racy {
            continue;
        }
        if size > MAX_HASH_FILE || st.hashed_bytes + size > MAX_HASH_TOTAL {
            if size as u32 != e.size {
                st.changes.push((e.path.clone(), Change::Modified));
            } else {
                st.budget_exhausted = true;
            }
            continue;
        }
        st.hashed_bytes += size;
        if hash_file(&dir, &name, size) != Some(e.sha1) {
            st.changes.push((e.path.clone(), Change::Modified));
        }
    }
    Ok(st)
}

/// repository uses content filters/line-ending attributes (text only read, nothing evaluated) – note for the result
pub fn has_content_filters(repo: &str) -> bool {
    let Some(r) = open_dir_abs(repo) else { return false };
    let read = |dir: &OwnedFd, name: &str| -> Option<String> {
        let fd = openat(dir, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let st = fstat(&fd)?;
        if !is(&st, libc::S_IFREG) {
            return None;
        }
        let mut s = String::new();
        std::fs::File::from(fd).take(1 << 20).read_to_string(&mut s).ok()?;
        Some(s)
    };
    let mut texts: Vec<String> = read(&r, ".gitattributes").into_iter().collect();
    if let Some(info) = openat(&r, ".git", libc::O_RDONLY | libc::O_DIRECTORY).and_then(|g| openat(&g, "info", libc::O_RDONLY | libc::O_DIRECTORY)) {
        texts.extend(read(&info, "attributes"));
    }
    texts.iter().any(|t| t.contains("filter=") || t.contains("eol=") || t.contains(" text") || t.contains("working-tree-encoding"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Minimal index writer (v2/v3/v4) for tests
    pub fn write_index(version: u32, entries: &[Entry], ext_flags: &[u16]) -> Vec<u8> {
        let mut out = b"DIRC".to_vec();
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        let mut prev = String::new();
        for (i, e) in entries.iter().enumerate() {
            let start = out.len();
            for v in [0, 0, e.mtime_s, e.mtime_ns, 0, 0, e.mode, 0, 0, e.size] {
                out.extend_from_slice(&v.to_be_bytes());
            }
            out.extend_from_slice(&e.sha1);
            let ext = ext_flags.get(i).copied().unwrap_or(0);
            let mut flags = (e.path.len().min(0xfff)) as u16;
            if ext != 0 {
                flags |= 0x4000;
            }
            out.extend_from_slice(&flags.to_be_bytes());
            if ext != 0 {
                out.extend_from_slice(&ext.to_be_bytes());
            }
            if version == 4 {
                let common = prev.bytes().zip(e.path.bytes()).take_while(|(a, b)| a == b).count();
                let mut strip = prev.len() - common;
                // varint (Git offset encoding)
                let mut v = vec![(strip & 0x7f) as u8];
                while strip >= 0x80 {
                    strip = (strip >> 7) - 1;
                    v.push(0x80 | (strip & 0x7f) as u8);
                }
                v.reverse();
                out.extend_from_slice(&v);
                out.extend_from_slice(&e.path.as_bytes()[common..]);
                out.push(0);
            } else {
                out.extend_from_slice(e.path.as_bytes());
                let len = out.len() - start;
                let padded = (len + 8) & !7;
                out.resize(start + padded, 0);
            }
            prev = e.path.clone();
        }
        let sum = sha1(&out);
        out.extend_from_slice(&sum);
        out
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        let mut s = Sha1::default();
        for _ in 0..1000 {
            s.update(&[b'a'; 1000]);
        }
        assert_eq!(hex(&s.finish()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        // Git blob IDs (git hash-object)
        assert_eq!(hex(&blob_id(b"")), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        assert_eq!(hex(&blob_id(b"hello\n")), "ce013625030ba8dba906f756967f9e9ca394464a");
    }

    fn entry(path: &str, content: &[u8], mtime: u32) -> Entry {
        Entry { path: path.into(), mtime_s: mtime, mtime_ns: 0, mode: 0o100644, size: content.len() as u32, sha1: blob_id(content), skip: false }
    }

    #[test]
    fn parse_all_versions() {
        let es = vec![entry("index.php", b"a", 1), entry("wp-admin/admin.php", b"b", 2), entry("wp-admin/admin-ajax.php", b"c", 3), entry("x", b"", 4)];
        for v in [2, 3, 4] {
            let mut ext = vec![0u16; es.len()];
            if v >= 3 {
                ext[3] = 0x4000; // skip-worktree
            }
            let parsed = parse_index(&write_index(v, &es, &ext)).unwrap();
            assert_eq!(parsed.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), es.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), "v{v}");
            assert_eq!(parsed[1].sha1, blob_id(b"b"));
            assert_eq!(parsed[2].mtime_s, 3);
            assert_eq!(parsed[3].skip, v >= 3);
        }
        // corrupt / wrong checksum / no index
        let mut d = write_index(2, &es, &[]);
        d[20] ^= 1;
        assert!(parse_index(&d).is_err());
        assert!(parse_index(b"DIRC").is_err());
        assert!(parse_index(&[0u8; 64]).is_err());
        let d = write_index(2, &es, &[]);
        assert!(parse_index(&d[..d.len() - 30]).is_err());
    }

    #[test]
    fn worktree_status() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("wp-admin")).unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        let files: &[(&str, &[u8])] = &[
            ("index.php", b"<?php echo 1;\n"),
            ("wp-admin/admin.php", b"<?php admin();\n"),
            ("same-stat.php", b"<?php ok();\n"),
            ("deleted.php", b"x"),
            ("linked/a.php", b"y"),
            ("../escape.php", b"z"),
        ];
        for (p, c) in files {
            if !p.starts_with("..") && !p.starts_with("linked/") && *p != "deleted.php" {
                std::fs::write(root.join(p), c).unwrap();
            }
        }
        // "linked" is a symlink to a directory with a matching file → counts as deleted (not followed)
        std::fs::write(root.join("outside/a.php"), b"y").unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join("linked")).unwrap();
        let mtime = |p: &str| std::fs::metadata(root.join(p)).map(|m| std::os::unix::fs::MetadataExt::mtime(&m) as u32).unwrap_or(1);
        let mut es: Vec<Entry> = files.iter().map(|(p, c)| entry(p, c, mtime(p))).collect();
        // file modified, same size, same mtime → would be missed without hashing; but the index is "racy"
        // (same second) → hash
        std::fs::write(root.join("index.php"), b"<?php evil(1)\n").unwrap();
        es[0].mtime_s = mtime("index.php");
        // different content of different size
        std::fs::write(root.join("wp-admin/admin.php"), b"<?php admin(); eval($_POST['x']);\n").unwrap();
        // symlink in the index, a file in the working tree
        es.push(Entry { mode: 0o120000, ..entry("link.php", b"target.php", 1) });
        std::fs::write(root.join("link.php"), b"target.php").unwrap();
        // submodule is skipped
        es.push(Entry { mode: 0o160000, ..entry("sub", b"", 1) });
        let idx = root.join(".git/index");
        std::fs::write(&idx, write_index(2, &es, &[])).unwrap();
        // index written in the same second as index.php ("racy") – fixed so the test does not depend on the clock
        let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(es[0].mtime_s as u64);
        std::fs::File::options().write(true).open(&idx).unwrap().set_modified(t).unwrap();
        let repo = root.to_string_lossy().into_owned();
        let s = status(&repo).unwrap();
        let mut ch: Vec<(String, Change)> = s.changes.clone();
        ch.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(ch, vec![
            ("deleted.php".to_string(), Change::Deleted),
            ("index.php".to_string(), Change::Modified),
            ("link.php".to_string(), Change::TypeChanged),
            ("linked/a.php".to_string(), Change::Deleted),
            ("wp-admin/admin.php".to_string(), Change::Modified),
        ]);
        assert_eq!(s.skipped, 2); // ../escape.php, submodule
        // unchanged (racy, but same content) → not reported
        assert!(!ch.iter().any(|(p, _)| p == "same-stat.php"));
        // .git as a symlink or index as a symlink → not read
        let d2 = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(root.join(".git"), d2.path().join(".git")).unwrap();
        assert!(status(&d2.path().to_string_lossy()).is_err());
        let d3 = tempfile::tempdir().unwrap();
        std::fs::create_dir(d3.path().join(".git")).unwrap();
        std::os::unix::fs::symlink(root.join(".git/index"), d3.path().join(".git/index")).unwrap();
        assert!(status(&d3.path().to_string_lossy()).is_err());
        // gitfile (worktree/submodule reference) is not followed
        let d4 = tempfile::tempdir().unwrap();
        std::fs::write(d4.path().join(".git"), format!("gitdir: {}/.git\n", repo)).unwrap();
        assert!(status(&d4.path().to_string_lossy()).is_err());
    }

    #[test]
    fn unchanged_stat_skips_hash() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        std::fs::create_dir(root.join(".git")).unwrap();
        std::fs::write(root.join("a.php"), b"<?php 1;").unwrap();
        let m = std::fs::metadata(root.join("a.php")).unwrap();
        let mt = std::os::unix::fs::MetadataExt::mtime(&m) as u32;
        // index with wrong hash, but matching size/mtime and index clearly newer → not hashed, not reported
        let e = Entry { sha1: [0; 20], ..entry("a.php", b"<?php 1;", mt) };
        let idx = root.join(".git/index");
        std::fs::write(&idx, write_index(2, &[e], &[])).unwrap();
        let later = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(mt as u64 + 10);
        std::fs::File::options().write(true).open(&idx).unwrap().set_modified(later).unwrap();
        let s = status(&root.to_string_lossy()).unwrap();
        assert!(s.changes.is_empty(), "{:?}", s.changes);
        assert_eq!(s.hashed_bytes, 0);
    }
}
