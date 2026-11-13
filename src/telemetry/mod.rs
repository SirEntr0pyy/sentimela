//! Optional multi-host telemetry. No server starts unless explicitly requested.
mod client;
mod server;
mod store;
mod watch;

use crate::models::Incident;
pub use client::{Agent, AgentOptions};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
pub const MAX_BODY: usize = 16 * 1024;
pub const MAX_EVENTS: usize = 1024;
pub const MAX_NODES: usize = 128;
pub const WINDOW_SECS: u64 = 600;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub event_id: String,
    pub node_id: String,
    #[serde(flatten)]
    pub incident: Incident,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub version: String,
    #[serde(default)]
    pub last_seen: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub received_at: u64,
    pub event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node: Node,
    pub seen_at: u64,
    pub online: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Correlation {
    pub ip: String,
    pub nodes: Vec<String>,
    pub events: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: String,
    pub accepted: u64,
    pub rejected: u64,
    pub nodes: Vec<NodeStatus>,
    pub incidents: Vec<Record>,
    pub correlations: Vec<Correlation>,
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
}

fn text(value: &str, max: usize) -> bool {
    value.len() <= max
        && !value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
}

impl Event {
    pub fn validate(&self) -> bool {
        let i = &self.incident;
        (self.event_id.is_empty() || identifier(&self.event_id))
            && identifier(&self.node_id)
            && i.ip.parse::<std::net::IpAddr>().is_ok()
            && i.threat_score <= 100
            && text(&i.timestamp, 64)
            && text(&i.service, 256)
            && text(&i.severity, 32)
            && text(&i.country, 128)
            && text(&i.city, 128)
            && text(&i.isp, 256)
            && i.payload.as_deref().map(|s| text(s, 2048)).unwrap_or(true)
            && i.rdns.as_deref().map(|s| text(s, 256)).unwrap_or(true)
    }
}

impl Node {
    pub fn validate(&self) -> bool {
        identifier(&self.id)
            && text(&self.name, 128)
            && text(&self.ip, 256)
            && text(&self.version, 32)
            && text(&self.last_seen, 64)
    }
}

/// Strip controls before drawing untrusted network data in a terminal.
pub fn terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

pub fn option(args: &[String], name: &str) -> Result<Option<String>> {
    match args.iter().position(|v| v == name) {
        Some(i) => match args.get(i + 1) {
            Some(value) if !value.is_empty() && !value.starts_with("--") => Ok(Some(value.clone())),
            _ => Err(format!("{name} requer um valor").into()),
        },
        None => Ok(None),
    }
}

fn check_command_options(args: &[String], values: &[&str], flags: &[&str]) -> Result<()> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if values.contains(&arg.as_str()) {
            let value = iter
                .next()
                .ok_or_else(|| format!("{arg} requer um valor"))?;
            if value.starts_with("--") {
                return Err(format!("{arg} requer um valor").into());
            }
        } else if !flags.contains(&arg.as_str()) {
            return Err(format!("Opção desconhecida: {arg}").into());
        }
    }
    Ok(())
}

pub fn token() -> Result<Option<String>> {
    match std::env::var("SENTINELA_HUB_TOKEN") {
        Ok(value) if !value.is_empty() => {
            if !(32..=256).contains(&value.len()) || !value.bytes().all(|b| (33..=126).contains(&b))
            {
                return Err(
                    "SENTINELA_HUB_TOKEN requer 32 a 256 caracteres ASCII sem espaços".into(),
                );
            }
            Ok(Some(value))
        }
        _ => Ok(None),
    }
}

pub async fn command(args: &[String]) -> Result<bool> {
    match args.first().map(String::as_str) {
        Some("hub") => {
            check_command_options(
                args,
                &["--bind", "--journal"],
                &["--allow-remote", "--help", "-h"],
            )?;
            if args.iter().any(|s| s == "--help" || s == "-h") {
                println!("sentinela hub [--bind 127.0.0.1:8765] [--journal events.jsonl] [--allow-remote]\nRequer SENTINELA_HUB_TOKEN (32+ caracteres). HTTP local; usa túnel SSH ou proxy TLS.");
            } else {
                server::run(args).await?;
            }
            Ok(true)
        }
        Some("watch") => {
            check_command_options(args, &["--hub"], &["--help", "-h"])?;
            if args.iter().any(|s| s == "--help" || s == "-h") {
                println!("sentinela watch --hub http://127.0.0.1:8765\nToken: SENTINELA_HUB_TOKEN. j/p: navegar; /: pesquisa; Enter: detalhe; q: sair.");
            } else {
                watch::run(args).await?;
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests;
