//! Debounce/Coalesce: Rohereignisse pro Pfad sammeln und erst nach einer
//! Ruhezeit verarbeiten (Editoren, Temp-Datei + Rename, Deploys).

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::event::{Op, RawEvent};
use crate::processor::{Input, Processor};

struct Pending {
    first: RawEvent,
    last_ts: i64,
    op: Op,
    old_path: Option<String>,
    proc: Option<crate::procinfo::ProcInfo>,
}

pub struct Debouncer {
    pending: Mutex<HashMap<String, Pending>>,
    cv: Condvar,
    quiet_ns: i64,
    max_ns: i64,
    processor: Arc<Processor>,
}

/// Rangfolge beim Zusammenfassen: das „stärkste“ Ereignis gewinnt.
fn rank(op: Op) -> u8 {
    match op {
        Op::Attrib => 1,
        Op::WriteNochange => 1,
        Op::Modify => 2,
        Op::Rename => 3,
        Op::Create => 4,
        Op::Delete => 5,
        Op::Overflow => 6,
        Op::Exec => 0, // läuft nicht durch die Zusammenfassung (siehe push)
    }
}

impl Debouncer {
    pub fn new(processor: Arc<Processor>, quiet: Duration, max: Duration) -> Arc<Debouncer> {
        let d = Arc::new(Debouncer {
            pending: Mutex::new(HashMap::new()),
            cv: Condvar::new(),
            quiet_ns: quiet.as_nanos() as i64,
            max_ns: max.as_nanos() as i64,
            processor,
        });
        let w = d.clone();
        std::thread::Builder::new()
            .name("debounce".into())
            .spawn(move || w.run())
            .expect("Thread");
        d
    }

    pub fn push(&self, ev: RawEvent) {
        if ev.op == Op::Overflow || ev.op == Op::Exec {
            // sofort durchreichen; Programmstarts nie mit Dateiänderungen desselben Pfads zusammenfassen (sonst ginge
            // z. B. das CREATE einer ausführbaren Datei in /tmp im EXEC unter)
            let exec = ev.op == Op::Exec;
            self.processor.process(Input {
                ts_ns: ev.ts_ns,
                first_ts_ns: ev.ts_ns,
                backend: ev.backend,
                op: ev.op,
                path: ev.path,
                old_path: None,
                proc: if exec { ev.proc } else { None },
                note: ev.note,
                quiet_nochange: false,
            });
            return;
        }
        let mut g = self.pending.lock().unwrap();
        match g.get_mut(&ev.path) {
            Some(p) => {
                p.last_ts = ev.ts_ns;
                // Delete gefolgt von Create = Ersetzen → Modify
                let new_op = match (p.op, ev.op) {
                    (Op::Delete, Op::Create) | (Op::Delete, Op::Rename) => Op::Modify,
                    (Op::Create, Op::Delete) => Op::Delete,
                    (a, b) if rank(b) > rank(a) => b,
                    (a, _) => a,
                };
                p.op = new_op;
                if ev.old_path.is_some() {
                    p.old_path = ev.old_path.clone();
                }
                if (p.proc.is_none() || p.proc.as_ref().is_some_and(|x| x.gone))
                    && ev.proc.is_some() {
                        p.proc = ev.proc.clone();
                    }
            }
            None => {
                let op = ev.op;
                let old_path = ev.old_path.clone();
                let proc = ev.proc.clone();
                g.insert(
                    ev.path.clone(),
                    Pending { last_ts: ev.ts_ns, first: ev, op, old_path, proc },
                );
            }
        }
        drop(g);
        self.cv.notify_one();
    }

    pub fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    fn run(&self) {
        loop {
            let ready: Vec<Pending> = {
                let mut g = self.pending.lock().unwrap();
                while g.is_empty() {
                    g = self.cv.wait(g).unwrap();
                }
                drop(g);
                std::thread::sleep(Duration::from_millis(50));
                let mut g = self.pending.lock().unwrap();
                let now = crate::now_ns();
                let keys: Vec<String> = g
                    .iter()
                    .filter(|(_, p)| now - p.last_ts >= self.quiet_ns || now - p.first.ts_ns >= self.max_ns)
                    .map(|(k, _)| k.clone())
                    .collect();
                keys.into_iter().filter_map(|k| g.remove(&k)).collect()
            };
            for p in ready {
                self.processor.process(Input {
                    ts_ns: p.last_ts,
                    first_ts_ns: p.first.ts_ns,
                    backend: p.first.backend,
                    op: p.op,
                    path: p.first.path,
                    old_path: p.old_path,
                    proc: p.proc,
                    note: p.first.note,
                    quiet_nochange: false,
                });
            }
        }
    }
}
