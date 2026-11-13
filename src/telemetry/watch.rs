use super::*;
use crossterm::event::{self, Event as Input, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use std::{
    io::{self, IsTerminal},
    time::{Duration, Instant},
};
use tokio::sync::watch;

async fn fetch(
    client: &reqwest::Client,
    url: &str,
    secret: Option<&str>,
    etag: &mut Option<String>,
) -> Result<Option<Snapshot>> {
    let mut request = client.get(format!("{url}/api/v1/snapshot"));
    if let Some(secret) = secret {
        request = request.bearer_auth(secret);
    }
    if let Some(tag) = etag.as_ref() {
        request = request.header(reqwest::header::IF_NONE_MATCH, tag);
    }
    let mut response = request.send().await?.error_for_status()?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    let next_tag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err("Snapshot excede 2 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    if snapshot.incidents.len() > 100
        || snapshot.nodes.len() > MAX_NODES
        || snapshot.correlations.len() > 32
    {
        return Err("Snapshot excede os limites de apresentação".into());
    }
    *etag = next_tag;
    Ok(Some(snapshot))
}

pub async fn run(args: &[String]) -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("O painel watch requer um TTY; usa ssh -t".into());
    }
    let url = client::validate_url(
        &option(args, "--hub")?
            .or_else(|| std::env::var("SENTINELA_HUB_URL").ok())
            .ok_or("Usa watch --hub URL")?,
    )?;
    let secret = token()?;
    let http = client::http_client()?;
    let (sender, mut receiver) =
        watch::channel::<std::result::Result<Option<Snapshot>, String>>(Err("A ligar".into()));
    let worker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut etag = None;
        loop {
            interval.tick().await;
            let value = fetch(&http, &url, secret.as_deref(), &mut etag)
                .await
                .map_err(|e| e.to_string());
            if sender.send(value).is_err() {
                break;
            }
        }
    });
    // Always abort the network task when the viewer returns, including on errors.
    struct Worker(tokio::task::JoinHandle<()>);
    impl Drop for Worker {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _worker = Worker(worker);
    crossterm::terminal::enable_raw_mode()?;
    let _guard = crate::TerminalGuard;
    crossterm::execute!(io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let start = Instant::now();
    let mut last_seen = Instant::now();
    let mut snapshot: Option<Snapshot> = None;
    let mut error = Some("A ligar".to_string());
    let mut offset: usize = 0;
    let mut query = String::new();
    let mut searching = false;
    let mut detail = false;
    loop {
        if receiver.has_changed().unwrap_or(false) {
            match receiver.borrow_and_update().clone() {
                Ok(value) => {
                    if let Some(value) = value {
                        snapshot = Some(value);
                    }
                    error = None;
                    last_seen = Instant::now();
                }
                Err(message) => {
                    error = Some(message);
                }
            }
        }
        let query_lower = query.to_lowercase();
        let records: Vec<&Record> = snapshot
            .as_ref()
            .map(|s| {
                s.incidents
                    .iter()
                    .filter(|r| {
                        r.event.node_id.to_lowercase().contains(&query_lower)
                            || r.event
                                .incident
                                .matches_filter(crate::models::SeverityFilter::All, &query_lower)
                    })
                    .collect()
            })
            .unwrap_or_default();
        offset = offset.min(records.len().saturating_sub(1));
        let tick = (start.elapsed().as_millis() / 250) as u64;
        terminal.draw(|frame| {
            let area = frame.area();
            if detail {
                let body = records
                    .get(offset)
                    .map(|r| serde_json::to_string_pretty(r).unwrap_or_default())
                    .unwrap_or_default();
                frame.render_widget(
                    Paragraph::new(body).wrap(Wrap { trim: false }).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Incidente | Esc: voltar "),
                    ),
                    area,
                );
                return;
            }
            let chunks = Layout::vertical([
                Constraint::Length(2),
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(2),
            ])
            .split(area);
            let status = if let Some(e) = &error {
                format!(
                    "SEM LIGAÇÃO | {} | último dado há {}s",
                    terminal_text(e),
                    last_seen.elapsed().as_secs()
                )
            } else {
                "LIGADO | atualização 1s | eventos persistidos".into()
            };
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(
                        " SENTIMELA CENTRAL | SSH FIRST",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Line::from(crate::ui::marquee_scroll(
                        &status,
                        area.width as usize,
                        tick,
                    )),
                ]),
                chunks[0],
            );
            let (online, total, accepted, rejected, correlations) = snapshot
                .as_ref()
                .map(|s| {
                    (
                        s.nodes.iter().filter(|n| n.online).count(),
                        s.nodes.len(),
                        s.accepted,
                        s.rejected,
                        s.correlations.len(),
                    )
                })
                .unwrap_or_default();
            let threats = snapshot
                .as_ref()
                .map(|s| {
                    s.correlations
                        .iter()
                        .take(3)
                        .map(|c| format!("{} → {} nós", terminal_text(&c.ip), c.nodes.len()))
                        .collect::<Vec<_>>()
                        .join(" | ")
                })
                .unwrap_or_default();
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(format!(
                        " Nós {online}/{total} | Gravados {accepted} | Rejeitados {rejected}"
                    )),
                    Line::from(crate::ui::marquee_scroll(
                        &format!(" Multi-host {correlations} | {threats}"),
                        area.width as usize,
                        tick,
                    )),
                ]),
                chunks[1],
            );
            let mut lines = Vec::new();
            for (index, record) in records
                .iter()
                .skip(offset)
                .take(chunks[2].height as usize / 2)
                .enumerate()
            {
                let e = &record.event;
                let i = &e.incident;
                let selected = index == 0;
                let color = if i.threat_score >= 80 {
                    Color::Red
                } else {
                    Color::Yellow
                };
                let heading = format!(
                    "{} {} | {} | {}",
                    if selected { ">" } else { " " },
                    terminal_text(&e.node_id),
                    terminal_text(&i.ip),
                    terminal_text(&i.severity)
                );
                let target = format!(
                    "  :{} {} | score {} | {}",
                    i.port,
                    terminal_text(&i.service),
                    i.threat_score,
                    terminal_text(i.payload.as_deref().unwrap_or(""))
                );
                // Only animate the selected incident to keep SSH output economical.
                let step = if selected { tick } else { 0 };
                lines.push(Line::from(Span::styled(
                    crate::ui::marquee_scroll(&heading, area.width as usize, step),
                    Style::default().fg(color).add_modifier(if selected {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                )));
                lines.push(Line::from(crate::ui::marquee_scroll(
                    &target,
                    area.width as usize,
                    step,
                )));
            }
            if records.is_empty() {
                lines.push(Line::from(" Sem incidentes para este filtro."));
            }
            frame.render_widget(Paragraph::new(lines), chunks[2]);
            let hint = if searching {
                format!("/{query}█ | Enter: confirmar | Esc: limpar")
            } else {
                format!(
                    "j/p: navegar | /: pesquisar | Enter: detalhe | q: sair | {}/{}",
                    offset + usize::from(!records.is_empty()),
                    records.len()
                )
            };
            frame.render_widget(
                Paragraph::new(crate::ui::marquee_scroll(&hint, area.width as usize, tick)),
                chunks[3],
            );
        })?;
        if event::poll(Duration::from_millis(250))? {
            if let Input::Key(key) = event::read()? {
                if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                    continue;
                }
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }
                if detail {
                    if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                        detail = false;
                    }
                    continue;
                }
                if searching {
                    match key.code {
                        KeyCode::Esc => {
                            searching = false;
                            query.clear();
                        }
                        KeyCode::Enter => searching = false,
                        KeyCode::Backspace => {
                            query.pop();
                            offset = 0;
                        }
                        KeyCode::Char(c) if !c.is_control() && query.len() < 128 => {
                            query.push(c);
                            offset = 0;
                        }
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q' | 'Q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j' | 'n') => {
                        offset = (offset + 1).min(records.len().saturating_sub(1))
                    }
                    KeyCode::Up | KeyCode::Char('p') => offset = offset.saturating_sub(1),
                    KeyCode::PageDown => offset = (offset + 5).min(records.len().saturating_sub(1)),
                    KeyCode::PageUp => offset = offset.saturating_sub(5),
                    KeyCode::Home => offset = 0,
                    KeyCode::End => offset = records.len().saturating_sub(1),
                    KeyCode::Char('/') => searching = true,
                    KeyCode::Enter => detail = true,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
