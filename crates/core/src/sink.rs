use std::io::Write;
use std::sync::Mutex;

use crate::event::Event;

/// Ziel für fertige Ereignisse (lokale Datei, Spool zur Zentrale, …).
pub trait Sink: Send + Sync {
    fn emit(&self, e: &Event);
}

/// Schreibt Ereignisse als JSON-Zeilen (Datei oder stdout), sofort geflusht.
/// Diff/Inhalt (binär) werden dabei nicht geschrieben.
pub struct JsonlSink {
    out: Mutex<Box<dyn Write + Send>>,
    pub count: std::sync::atomic::AtomicU64,
}

impl JsonlSink {
    pub fn open(path: Option<&str>) -> anyhow::Result<JsonlSink> {
        let out: Box<dyn Write + Send> = match path {
            None | Some("-") => Box::new(std::io::stdout()),
            Some(p) => {
                if let Some(dir) = std::path::Path::new(p).parent() {
                    std::fs::create_dir_all(dir)?;
                }
                Box::new(std::fs::OpenOptions::new().create(true).append(true).open(p)?)
            }
        };
        Ok(JsonlSink { out: Mutex::new(out), count: Default::default() })
    }
}

impl Sink for JsonlSink {
    fn emit(&self, e: &Event) {
        let mut line = serde_json::to_vec(e).unwrap_or_default();
        line.push(b'\n');
        let mut o = self.out.lock().unwrap();
        let _ = o.write_all(&line);
        let _ = o.flush();
        self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Mehrere Ziele zugleich.
pub struct MultiSink(pub Vec<Box<dyn Sink>>);

impl Sink for MultiSink {
    fn emit(&self, e: &Event) {
        for s in &self.0 {
            s.emit(e);
        }
    }
}
