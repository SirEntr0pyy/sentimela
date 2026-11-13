use super::*;
use reqwest::{redirect::Policy, Client, Url};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc;

pub struct AgentOptions {
    pub url: String,
    pub node: Node,
    pub secret: Option<String>,
}

pub fn validate_url(value: &str) -> Result<String> {
    let url = Url::parse(value)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("URL do hub inválido: usa http(s) sem credenciais, query ou fragmento".into());
    }
    // Plain HTTP is restricted to loopback to keep tokens off unencrypted networks.
    let local = url
        .host_str()
        .map(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    if url.scheme() == "http" && !local {
        return Err("Hub remoto requer HTTPS; para SSH usa http://127.0.0.1:8765".into());
    }
    Ok(value.trim_end_matches('/').to_owned())
}

pub fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(3))
        .connect_timeout(Duration::from_secs(2))
        .redirect(Policy::none())
        .pool_max_idle_per_host(1)
        .build()?)
}

impl AgentOptions {
    pub fn from_args(args: &[String]) -> Result<Option<Self>> {
        let Some(url) = option(args, "--hub")?.or_else(|| {
            std::env::var("SENTINELA_HUB_URL")
                .ok()
                .filter(|s| !s.is_empty())
        }) else {
            return Ok(None);
        };
        let id = option(args, "--node-id")?
            .or_else(|| std::env::var("SENTINELA_NODE_ID").ok())
            .unwrap_or_else(|| {
                std::env::var("HOSTNAME")
                    .or_else(|_| std::env::var("COMPUTERNAME"))
                    .unwrap_or_else(|_| "sentimela".into())
            });
        let node = Node {
            name: std::env::var("SENTINELA_NODE_NAME").unwrap_or_else(|_| id.clone()),
            id,
            ip: crate::network::get_all_local_ips(),
            version: env!("CARGO_PKG_VERSION").into(),
            last_seen: String::new(),
        };
        if !node.validate() {
            return Err(
                "Identidade do nó inválida; usa --node-id com letras, números, - _ . :".into(),
            );
        }
        Ok(Some(Self {
            url: validate_url(&url)?,
            node,
            secret: token()?,
        }))
    }
}

#[derive(Default)]
pub struct Counters {
    pub sent: AtomicU64,
    pub dropped: AtomicU64,
    pub failures: AtomicU64,
}

pub struct Agent {
    queue: mpsc::Sender<Event>,
    pub counters: Arc<Counters>,
    task: tokio::task::JoinHandle<()>,
    node_id: String,
    sequence: u64,
    session: String,
}

async fn post(client: &Client, url: &str, secret: Option<&str>, body: &impl Serialize) -> bool {
    for attempt in 0..3 {
        let mut request = client.post(url).json(body);
        if let Some(secret) = secret {
            request = request.bearer_auth(secret);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => return true,
            Ok(response)
                if !response.status().is_server_error() && response.status().as_u16() != 429 =>
            {
                return false
            }
            _ => {}
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
        }
    }
    false
}

impl Agent {
    pub fn start(options: AgentOptions) -> Result<Self> {
        Self::start_interval(options, Duration::from_secs(30))
    }

    pub(super) fn start_interval(options: AgentOptions, period: Duration) -> Result<Self> {
        let client = http_client()?;
        let (queue, mut receiver) = mpsc::channel::<Event>(256);
        let counters = Arc::new(Counters::default());
        let stats = counters.clone();
        let node_id = options.node.id.clone();
        let task = tokio::spawn(async move {
            let mut heartbeat = tokio::time::interval(period);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = heartbeat.tick() => {
                        let body = serde_json::json!({
                            "id": options.node.id,
                            "name": options.node.name,
                            "ip": options.node.ip,
                            "version": options.node.version,
                            "last_seen": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                            "incident_count": stats.sent.load(Ordering::Relaxed),
                            "online": true,
                        });
                        if !post(&client, &format!("{}/api/v1/heartbeat", options.url),
                            options.secret.as_deref(), &body).await {
                            stats.failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    event = receiver.recv() => {
                        let Some(event) = event else { break; };
                        if post(&client, &format!("{}/api/v1/incident", options.url),
                            options.secret.as_deref(), &event).await {
                            stats.sent.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
        Ok(Self {
            queue,
            counters,
            task,
            node_id,
            sequence: 0,
            session: format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
        })
    }

    pub fn send(&mut self, incident: &Incident) {
        self.sequence += 1;
        let mut captured = incident.clone();
        if let Some(payload) = captured.payload.as_mut() {
            const MARKER: &str = "\n[payload truncated]";
            if payload.len() > 2048 {
                let mut end = 2048 - MARKER.len();
                while !payload.is_char_boundary(end) {
                    end -= 1;
                }
                payload.truncate(end);
                payload.push_str(MARKER);
            }
        }
        let event = Event {
            node_id: self.node_id.clone(),
            event_id: format!("{}-{}", self.session, self.sequence),
            incident: captured,
        };
        // Bound both item count and serialized item size.
        if !event.validate() || self.queue.try_send(event).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub async fn finish(self) {
        drop(self.queue);
        let mut task = self.task;
        if tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .is_err()
        {
            task.abort();
            eprintln!("Telemetria: prazo de saída excedido; eventos pendentes podem perder-se.");
        }
        eprintln!(
            "Telemetria: enviados={} descartados={} falhas={}",
            self.counters.sent.load(Ordering::Relaxed),
            self.counters.dropped.load(Ordering::Relaxed),
            self.counters.failures.load(Ordering::Relaxed)
        );
    }
}
