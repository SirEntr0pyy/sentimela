use super::{
    store::{Journal, Pending},
    *,
};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::{oneshot, Semaphore};

#[derive(Clone)]
struct Context {
    journal: Journal,
    secret: Arc<String>,
    permits: Arc<Semaphore>,
    sequence: Arc<AtomicU64>,
}

pub fn router(journal: Journal, secret: String) -> Router {
    let context = Context {
        journal,
        secret: Arc::new(secret),
        permits: Arc::new(Semaphore::new(64)),
        sequence: Arc::new(AtomicU64::new(0)),
    };
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/incident", post(incident))
        .route("/api/v1/heartbeat", post(heartbeat))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(context.clone(), guard))
        .with_state(context)
}

async fn guard(State(context): State<Context>, request: Request, next: Next) -> Response {
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if !bool::from(provided.as_bytes().ct_eq(context.secret.as_bytes())) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(_permit) = context.permits.clone().try_acquire_owned() else {
        context.journal.rejected.fetch_add(1, Ordering::Relaxed);
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(Duration::from_secs(10), next.run(request)).await {
        Ok(mut response) => {
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            response
        }
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

async fn health(State(context): State<Context>) -> Response {
    let writable = context.journal.writable.load(Ordering::Relaxed);
    (if writable { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }, Json(serde_json::json!({
        "status": if writable { "ok" } else { "read_only" }, "version": env!("CARGO_PKG_VERSION"),
        "writable": writable,
        "queue_available": context.journal.queue.capacity(),
        "rejected": context.journal.rejected.load(Ordering::Relaxed),
    }))).into_response()
}

async fn snapshot(State(context): State<Context>, headers: HeaderMap) -> Response {
    let state = context.journal.store.read().await;
    // Time bucket also refreshes online status and expired correlations during idle periods.
    let tag = format!("\"{}-{}\"", state.revision, now() / 5);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(tag.as_str())
    {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, tag)]).into_response();
    }
    let value = state.snapshot(context.journal.rejected.load(Ordering::Relaxed), now());
    ([(header::ETAG, tag)], Json(value)).into_response()
}

async fn incident(State(context): State<Context>, Json(mut event): Json<Event>) -> Response {
    if !event.validate() {
        context.journal.rejected.fetch_add(1, Ordering::Relaxed);
        return (StatusCode::UNPROCESSABLE_ENTITY, "invalid_event").into_response();
    }
    if event.event_id.is_empty() {
        event.event_id = format!(
            "received-{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            context.sequence.fetch_add(1, Ordering::Relaxed)
        );
    }
    let (reply, result) = oneshot::channel();
    if context
        .journal
        .queue
        .try_send(Pending { event, reply })
        .is_err()
    {
        context.journal.rejected.fetch_add(1, Ordering::Relaxed);
        return (StatusCode::SERVICE_UNAVAILABLE, "journal_busy").into_response();
    }
    match result.await {
        Ok(Ok(fresh)) => {
            Json(serde_json::json!({"stored": true, "duplicate": !fresh})).into_response()
        }
        Ok(Err("journal_full")) => {
            (StatusCode::INSUFFICIENT_STORAGE, "journal_full").into_response()
        }
        _ => (StatusCode::SERVICE_UNAVAILABLE, "journal_unavailable").into_response(),
    }
}

async fn heartbeat(State(context): State<Context>, Json(node): Json<Node>) -> Response {
    if !node.validate() {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let mut state = context.journal.store.write().await;
    if state.nodes.len() >= MAX_NODES && !state.nodes.contains_key(&node.id) {
        return (StatusCode::SERVICE_UNAVAILABLE, "node_limit").into_response();
    }
    state.revision += 1;
    state.nodes.insert(
        node.id.clone(),
        NodeStatus {
            node,
            seen_at: now(),
            online: true,
        },
    );
    StatusCode::NO_CONTENT.into_response()
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

pub async fn run(args: &[String]) -> Result<()> {
    let secret = token()?
        .filter(|s| s.len() >= 32)
        .ok_or("Define SENTINELA_HUB_TOKEN com pelo menos 32 caracteres")?;
    let address: SocketAddr = option(args, "--bind")?
        .unwrap_or_else(|| "127.0.0.1:8765".into())
        .parse()?;
    if !address.ip().is_loopback() && !args.iter().any(|s| s == "--allow-remote") {
        return Err("Bind remoto requer --allow-remote e proxy TLS; prefere um túnel SSH".into());
    }
    let path = PathBuf::from(
        option(args, "--journal")?.unwrap_or_else(|| "sentimela-events.jsonl".into()),
    );
    let (journal, writer) = Journal::open(&path).await?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!(
        "Sentimela central {} | journal {} | Ctrl+C para sair",
        listener.local_addr()?,
        path.display()
    );
    // Stop accepting requests, finish active writes, then drain the bounded journal.
    let result = axum::serve(listener, router(journal.clone(), secret))
        .with_graceful_shutdown(shutdown_signal())
        .await;
    drop(journal);
    writer.await?;
    result?;
    Ok(())
}

// Use the same framework path for real HTTP integration tests.
#[cfg(test)]
pub async fn test_server(journal: Journal) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router(journal, "t".repeat(32)))
            .await
            .unwrap();
    });
    (format!("http://{address}"), task)
}
