//! Bounded detection delivery and shared admission control before spawning enrichment tasks.
use crate::models::Incident;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

static DROPPED: AtomicU64 = AtomicU64::new(0);
static WORK: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Clone)]
pub struct IncidentSender(mpsc::Sender<Incident>);

pub fn channel() -> (IncidentSender, mpsc::Receiver<Incident>) {
    let (sender, receiver) = mpsc::channel(1024);
    (IncidentSender(sender), receiver)
}

pub fn reject() {
    DROPPED.fetch_add(1, Ordering::Relaxed);
}
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

pub fn admit() -> Option<OwnedSemaphorePermit> {
    match WORK
        .get_or_init(|| Arc::new(Semaphore::new(64)))
        .clone()
        .try_acquire_owned()
    {
        Ok(permit) => Some(permit),
        Err(_) => {
            reject();
            None
        }
    }
}

impl IncidentSender {
    pub fn send(
        &self,
        incident: Incident,
    ) -> std::result::Result<(), mpsc::error::TrySendError<Incident>> {
        self.0.try_send(incident).inspect_err(|_| reject())
    }
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrichment_admission_releases_capacity() {
        let permits: Vec<_> = (0..64)
            .map(|_| admit().expect("available permit"))
            .collect();
        assert!(admit().is_none());
        drop(permits);
        assert!(admit().is_some());
    }

    #[test]
    fn overload_is_bounded_and_counted() {
        let before = dropped();
        let (sender, mut receiver) = channel();
        let event: Incident = serde_json::from_value(serde_json::json!({
            "timestamp":"", "ip":"127.0.0.1", "port":0, "service":"", "severity":"",
            "country":"", "city":"", "isp":"", "rdns":null, "payload":null,
            "threat_score":0, "hit_count":1
        }))
        .unwrap();
        for _ in 0..1024 {
            assert!(sender.send(event.clone()).is_ok());
        }
        assert!(sender.send(event.clone()).is_err());
        assert!(dropped() > before);
        receiver.try_recv().unwrap();
        assert!(sender.send(event).is_ok());
    }
}
