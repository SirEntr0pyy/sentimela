use super::store::{Journal, Store};
use super::*;
use reqwest::{Client, StatusCode};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sentimela-test-{}-{}-{}",
            std::process::id(),
            now(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("events.jsonl")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn event(node: &str, id: &str) -> Event {
    Event {
        node_id: node.into(),
        event_id: id.into(),
        incident: Incident {
            timestamp: "2026-11-13 12:00:00".into(),
            ip: "192.0.2.1".into(),
            port: 2222,
            service: "SSH".into(),
            severity: "CRÍTICO".into(),
            country: "Test".into(),
            city: String::new(),
            isp: String::new(),
            payload: None,
            rdns: None,
            threat_score: 85,
            hit_count: 1,
        },
    }
}
fn auth(client: &Client, url: &str) -> reqwest::RequestBuilder {
    client
        .post(format!("{url}/api/v1/incident"))
        .bearer_auth("t".repeat(32))
}

#[test]
fn correlation_window_and_memory_are_bounded() {
    let mut store = Store::default();
    store.insert(Record {
        received_at: 1000,
        event: event("a", "1"),
    });
    store.insert(Record {
        received_at: 1001,
        event: event("b", "2"),
    });
    assert_eq!(store.snapshot(0, 1001).correlations[0].nodes, ["a", "b"]);
    assert!(store.snapshot(0, 1700).correlations.is_empty());
    assert!(!store.snapshot(0, 1700).nodes[0].online);
    for i in 0..MAX_EVENTS + 100 {
        store.insert(Record {
            received_at: 2000,
            event: event("a", &format!("n{i}")),
        });
    }
    assert_eq!(store.records.len(), MAX_EVENTS);
    assert_eq!(store.snapshot(0, 2000).incidents.len(), 100);
}

#[test]
fn validates_input_and_terminal_controls() {
    let mut e = event("a", "1");
    assert!(e.validate());
    e.incident.ip = "not-an-ip".into();
    assert!(!e.validate());
    e.incident.ip = "192.0.2.1".into();
    e.incident.payload = Some("\x1b[2J".into());
    assert!(!e.validate());
    e.incident.payload = Some("x".repeat(2049));
    assert!(!e.validate());
    assert_eq!(terminal_text("\x1b[2J\r\nhello"), " [2J  hello");
    for url in [
        "http://192.0.2.1",
        "file:///etc/passwd",
        "http://user:secret@localhost",
        "https://example.com/?token=a",
    ] {
        assert!(client::validate_url(url).is_err(), "{url}");
    }
    assert!(client::validate_url("http://127.0.0.1:8765").is_ok());
    assert!(client::validate_url("http://[::1]:8765").is_ok());
    assert!(client::validate_url("https://example.com").is_ok());
}

#[tokio::test]
async fn http_auth_limits_durable_ingestion_and_replay() {
    let directory = Directory::new();
    let path = directory.journal();
    let (journal, writer) = Journal::open(&path).await.unwrap();
    let (url, server) = server::test_server(journal.clone()).await;
    let client = Client::new();
    assert_eq!(
        client
            .get(format!("{url}/api/v1/snapshot"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        auth(&client, &url)
            .body("{")
            .header("Content-Type", "application/json")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        auth(&client, &url)
            .body("x".repeat(MAX_BODY + 1))
            .header("Content-Type", "application/json")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut invalid = event("a", "1");
    invalid.incident.ip = "nope".into();
    assert_eq!(
        auth(&client, &url)
            .json(&invalid)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let first = event("a", "same-id");
    assert!(auth(&client, &url)
        .json(&first)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    // A successful HTTP response must correspond to a complete record on disk.
    let (disk, _) = store::replay(&path).unwrap();
    assert_eq!(disk.accepted, 1);
    assert!(auth(&client, &url)
        .json(&first)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()["duplicate"]
        .as_bool()
        .unwrap());
    assert!(auth(&client, &url)
        .json(&event("b", "same-id"))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let snapshot: Snapshot = client
        .get(format!("{url}/api/v1/snapshot"))
        .bearer_auth("t".repeat(32))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snapshot.accepted, 2);
    assert_eq!(snapshot.correlations.len(), 1);
    server.abort();
    let _ = server.await;
    drop(journal);
    tokio::time::timeout(Duration::from_secs(3), writer)
        .await
        .unwrap()
        .unwrap();
    let (recovered, _) = store::replay(&path).unwrap();
    assert_eq!(recovered.accepted, 2);
    assert!(recovered.contains(&first));
}

#[test]
fn recovers_only_a_torn_final_record() {
    use std::io::Write;
    let directory = Directory::new();
    let path = directory.journal();
    let mut bytes = serde_json::to_vec(&Record {
        received_at: now(),
        event: event("a", "1"),
    })
    .unwrap();
    bytes.push(b'\n');
    std::fs::write(&path, &bytes).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{torn")
        .unwrap();
    let (recovered, length) = store::replay(&path).unwrap();
    assert_eq!(recovered.accepted, 1);
    assert_eq!(length, bytes.len() as u64);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    std::fs::write(&path, b"{corrupt}\n").unwrap();
    assert!(store::replay(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"{corrupt}\n");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn disk_error_is_not_reported_as_success() {
    let directory = Directory::new();
    let path = directory.journal();
    std::os::unix::fs::symlink("/dev/full", &path).unwrap();
    let (journal, writer) = Journal::open(&path).await.unwrap();
    let (url, server) = server::test_server(journal.clone()).await;
    let client = Client::new();
    assert_eq!(
        auth(&client, &url)
            .json(&event("a", "1"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(journal.store.read().await.accepted, 0);
    assert!(!journal.writable.load(Ordering::Relaxed));
    assert_eq!(
        client
            .get(format!("{url}/api/v1/health"))
            .bearer_auth("t".repeat(32))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    server.abort();
    let _ = server.await;
    drop(journal);
    writer.await.unwrap();
}

#[tokio::test]
async fn heartbeat_refresh_and_node_limit() {
    let directory = Directory::new();
    let (journal, writer) = Journal::open(&directory.journal()).await.unwrap();
    let (url, server) = server::test_server(journal.clone()).await;
    let client = Client::new();
    for i in 0..MAX_NODES {
        let node = Node {
            id: format!("node-{i}"),
            name: "node".into(),
            ip: "127.0.0.1".into(),
            version: "test".into(),
            last_seen: String::new(),
        };
        assert_eq!(
            client
                .post(format!("{url}/api/v1/heartbeat"))
                .bearer_auth("t".repeat(32))
                .json(&node)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    let node = Node {
        id: "one-too-many".into(),
        name: String::new(),
        ip: String::new(),
        version: String::new(),
        last_seen: String::new(),
    };
    assert_eq!(
        client
            .post(format!("{url}/api/v1/heartbeat"))
            .bearer_auth("t".repeat(32))
            .json(&node)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    server.abort();
    let _ = server.await;
    drop(journal);
    writer.await.unwrap();
}

#[tokio::test]
async fn agent_reuses_id_and_retries_transient_errors() {
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::Arc;
    let received = Arc::new(tokio::sync::Mutex::new(Vec::<Event>::new()));
    async fn capture(
        State(events): State<Arc<tokio::sync::Mutex<Vec<Event>>>>,
        Json(event): Json<Event>,
    ) -> StatusCode {
        let mut events = events.lock().await;
        events.push(event);
        if events.len() < 3 {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server_received = received.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/api/v1/incident", post(capture))
                .with_state(server_received),
        )
        .await
        .unwrap();
    });
    let mut agent = Agent::start(AgentOptions {
        url,
        node: Node {
            id: "a".into(),
            name: "a".into(),
            ip: String::new(),
            version: String::new(),
            last_seen: String::new(),
        },
        secret: None,
    })
    .unwrap();
    let stats = agent.counters.clone();
    let mut original = event("a", "1").incident;
    original.payload = Some("界".repeat(2000));
    agent.send(&original);
    assert_eq!(original.payload.as_ref().unwrap().len(), 6000);
    agent.finish().await;
    let events = received.lock().await;
    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .all(|e| e.event_id == events[0].event_id && !e.event_id.is_empty()));
    let payload = events[0].incident.payload.as_ref().unwrap();
    assert!(payload.len() <= 2048);
    assert!(payload.ends_with("[payload truncated]"));
    assert!(events[0].validate());
    assert_eq!(stats.sent.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn unchanged_snapshots_skip_the_response_body() {
    let directory = Directory::new();
    let (journal, writer) = Journal::open(&directory.journal()).await.unwrap();
    let (url, server) = server::test_server(journal.clone()).await;
    let client = Client::new();
    let mut no_body = false;
    // One retry handles crossing the five-second status refresh boundary.
    for _ in 0..2 {
        let response = client
            .get(format!("{url}/api/v1/snapshot"))
            .bearer_auth("t".repeat(32))
            .send()
            .await
            .unwrap();
        let tag = response.headers().get("etag").unwrap().clone();
        let conditional = client
            .get(format!("{url}/api/v1/snapshot"))
            .bearer_auth("t".repeat(32))
            .header("If-None-Match", tag)
            .send()
            .await
            .unwrap();
        if conditional.status() == StatusCode::NOT_MODIFIED {
            assert!(conditional.bytes().await.unwrap().is_empty());
            no_body = true;
            break;
        }
    }
    assert!(no_body);
    server.abort();
    let _ = server.await;
    drop(journal);
    writer.await.unwrap();
}

#[tokio::test]
async fn heartbeats_repeat_without_incidents() {
    use axum::{routing::post, Router};
    use std::sync::Arc;
    let beats = Arc::new(AtomicU64::new(0));
    let count = beats.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/api/v1/heartbeat",
                post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let count = count.clone();
                    async move {
                        if serde_json::from_value::<Node>(body.clone()).is_err()
                            || body["incident_count"].as_u64().is_none()
                            || body["online"] != true
                            || body["last_seen"].as_str().unwrap_or("").is_empty()
                        {
                            return StatusCode::BAD_REQUEST;
                        }
                        count.fetch_add(1, Ordering::Relaxed);
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let agent = Agent::start_interval(
        AgentOptions {
            url,
            node: Node {
                id: "heartbeat-test".into(),
                name: String::new(),
                ip: String::new(),
                version: String::new(),
                last_seen: String::new(),
            },
            secret: None,
        },
        Duration::from_millis(20),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while beats.load(Ordering::Relaxed) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    agent.finish().await;
    task.abort();
}

#[tokio::test]
async fn full_journal_queue_returns_service_unavailable() {
    use std::sync::{atomic::AtomicBool, Arc};
    use tokio::sync::{mpsc, oneshot, RwLock};
    let (queue, _receiver) = mpsc::channel(1);
    let (reply, _result) = oneshot::channel();
    queue
        .try_send(store::Pending {
            event: event("a", "occupied"),
            reply,
        })
        .unwrap();
    let journal = Journal {
        queue,
        store: Arc::new(RwLock::new(Store::default())),
        rejected: Arc::new(AtomicU64::new(0)),
        writable: Arc::new(AtomicBool::new(true)),
    };
    let (url, server) = server::test_server(journal.clone()).await;
    let response = auth(&Client::new(), &url)
        .json(&event("a", "new"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(journal.rejected.load(Ordering::Relaxed), 1);
    assert_eq!(journal.store.read().await.accepted, 0);
    server.abort();
}
