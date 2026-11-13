use super::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, oneshot, RwLock},
};

pub const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
pub const QUEUE: usize = 256;

#[derive(Default)]
pub struct Store {
    pub records: VecDeque<Record>,
    pub nodes: BTreeMap<String, NodeStatus>,
    pub accepted: u64,
    pub revision: u64,
}

impl Store {
    pub fn contains(&self, event: &Event) -> bool {
        self.records
            .iter()
            .any(|r| r.event.event_id == event.event_id && r.event.node_id == event.node_id)
    }

    pub fn insert(&mut self, record: Record) {
        self.accepted += 1;
        self.revision += 1;
        let id = record.event.node_id.clone();
        if self.nodes.contains_key(&id) || self.nodes.len() < MAX_NODES {
            self.nodes
                .entry(id.clone())
                .or_insert_with(|| NodeStatus {
                    node: Node {
                        id: id.clone(),
                        name: id,
                        ip: String::new(),
                        version: String::new(),
                        last_seen: String::new(),
                    },
                    seen_at: record.received_at,
                    online: false,
                })
                .seen_at = record.received_at;
        }
        self.records.push_front(record);
        self.records.truncate(MAX_EVENTS);
    }

    pub fn snapshot(&self, rejected: u64, time: u64) -> Snapshot {
        let mut grouped: BTreeMap<String, (BTreeSet<String>, usize)> = BTreeMap::new();
        for r in &self.records {
            if time.saturating_sub(r.received_at) <= WINDOW_SECS {
                let entry = grouped.entry(r.event.incident.ip.clone()).or_default();
                entry.0.insert(r.event.node_id.clone());
                entry.1 += 1;
            }
        }
        let mut correlations: Vec<_> = grouped
            .into_iter()
            .filter(|(_, (nodes, _))| nodes.len() >= 2)
            .map(|(ip, (nodes, events))| Correlation {
                ip,
                nodes: nodes.into_iter().collect(),
                events,
            })
            .collect();
        correlations.sort_by(|a, b| b.events.cmp(&a.events).then(a.ip.cmp(&b.ip)));
        correlations.truncate(32);
        Snapshot {
            version: env!("CARGO_PKG_VERSION").into(),
            accepted: self.accepted,
            rejected,
            nodes: self
                .nodes
                .values()
                .cloned()
                .map(|mut n| {
                    n.online = time.saturating_sub(n.seen_at) <= 90;
                    n
                })
                .collect(),
            incidents: self.records.iter().take(100).cloned().collect(),
            correlations,
        }
    }
}

pub struct Pending {
    pub event: Event,
    pub reply: oneshot::Sender<std::result::Result<bool, &'static str>>,
}

#[derive(Clone)]
pub struct Journal {
    pub queue: mpsc::Sender<Pending>,
    pub store: Arc<RwLock<Store>>,
    pub rejected: Arc<AtomicU64>,
    pub writable: Arc<AtomicBool>,
}

pub fn replay(path: &Path) -> Result<(Store, u64)> {
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
    let mut store = Store::default();
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let size = file.metadata()?.len();
    if size > MAX_JOURNAL {
        return Err("Journal excede 64 MiB; arquiva-o antes de reiniciar".into());
    }
    // Only an unterminated final record is recoverable; corrupt complete lines fail closed.
    let mut valid = size;
    if size > 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut end = [0];
        file.read_exact(&mut end)?;
        if end[0] != b'\n' {
            let mut offset = size;
            valid = 0;
            let mut buffer = [0u8; 4096];
            while offset > 0 {
                let length = offset.min(buffer.len() as u64) as usize;
                offset -= length as u64;
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(&mut buffer[..length])?;
                if let Some(i) = buffer[..length].iter().rposition(|b| *b == b'\n') {
                    valid = offset + i as u64 + 1;
                    break;
                }
            }
        }
    }
    file.seek(SeekFrom::Start(0))?;
    for line in BufReader::new((&file).take(valid)).lines() {
        let line = line?;
        if line.len() > MAX_BODY {
            return Err("Registo demasiado grande no journal".into());
        }
        let record: Record = serde_json::from_str(&line)?;
        if !record.event.validate() {
            return Err("Registo inválido no journal".into());
        }
        store.insert(record);
    }
    // Truncate only after validating every complete record.
    if valid != size {
        file.set_len(valid)?;
        file.sync_data()?;
    }
    Ok((store, valid))
}

impl Journal {
    pub async fn open(path: &Path) -> Result<(Self, tokio::task::JoinHandle<()>)> {
        let (store, mut size) = replay(path)?;
        let store = Arc::new(RwLock::new(store));
        let rejected = Arc::new(AtomicU64::new(0));
        let writable = Arc::new(AtomicBool::new(size < MAX_JOURNAL));
        let (queue, mut receiver) = mpsc::channel::<Pending>(QUEUE);
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .await?;
        let writer_store = store.clone();
        let writer_rejected = rejected.clone();
        let writer_writable = writable.clone();
        let task = tokio::spawn(async move {
            let mut failed = false;
            while let Some(first) = receiver.recv().await {
                let mut batch = vec![first];
                while batch.len() < 64 {
                    match receiver.try_recv() {
                        Ok(item) => batch.push(item),
                        Err(_) => break,
                    }
                }
                let mut pending = Vec::new();
                let mut seen = BTreeSet::new();
                let mut bytes = Vec::new();
                {
                    let current = writer_store.read().await;
                    for item in batch {
                        if current.contains(&item.event) {
                            let _ = item.reply.send(Ok(false));
                            continue;
                        }
                        // Same ID in a batch: defer acknowledgement until the shared write succeeds.
                        let duplicate =
                            !seen.insert((item.event.node_id.clone(), item.event.event_id.clone()));
                        let record = Record {
                            received_at: now(),
                            event: item.event,
                        };
                        if !duplicate {
                            if serde_json::to_writer(&mut bytes, &record).is_err() {
                                failed = true;
                            }
                            bytes.push(b'\n');
                        }
                        pending.push((record, item.reply, duplicate));
                    }
                }
                if pending.is_empty() {
                    continue;
                }
                let overflow = size.saturating_add(bytes.len() as u64) > MAX_JOURNAL;
                let ok = !failed
                    && !overflow
                    && file.write_all(&bytes).await.is_ok()
                    && file.sync_data().await.is_ok();
                if !ok {
                    writer_writable.store(false, Ordering::Relaxed);
                    // A partial disk write must never be followed by further appends.
                    if !overflow {
                        failed = true;
                    }
                    for (_, reply, _) in pending {
                        writer_rejected.fetch_add(1, Ordering::Relaxed);
                        let _ = reply.send(Err(if overflow {
                            "journal_full"
                        } else {
                            "journal_unavailable"
                        }));
                    }
                    continue;
                }
                writer_writable.store(true, Ordering::Relaxed);
                size += bytes.len() as u64;
                let mut state = writer_store.write().await;
                for (record, reply, duplicate) in pending {
                    if !duplicate {
                        state.insert(record);
                    }
                    let _ = reply.send(Ok(!duplicate));
                }
            }
        });
        Ok((
            Self {
                queue,
                store,
                rejected,
                writable,
            },
            task,
        ))
    }
}
