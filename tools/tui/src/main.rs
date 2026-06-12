// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! rsk-tui — a self-contained ratatui device dashboard for rs-key.
//!
//! Talks to the key directly (CTAPHID over hidapi + the CCID applets over PC/SC,
//! see device.rs) — no external processes. A live overview plus in-band actions,
//! including a native seed backup (MSE channel + clientPIN token + BIP-39, all in
//! Rust). The SLIP-39 export and the picotool/BOOTSEL fuse rituals stay in `rsk`.
//!
//!     rsk-tui            # interactive dashboard
//!     rsk-tui --once     # print the gathered status once and exit (no TTY)

mod device;

use std::io;
use std::time::{Duration, Instant};

use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use zeroize::Zeroize;

use device::Status;

type Term = Terminal<CrosstermBackend<io::Stdout>>;

#[derive(Clone, Copy)]
enum Act {
    Refresh,
    LedGet,
    LedCycle,
    BackupExport,
    BackupRestore,
    BackupFinalize,
    RebootBootsel,
    RebootApp,
}

const ACTIONS: &[(&str, Act)] = &[
    ("Refresh status", Act::Refresh),
    ("LED · get", Act::LedGet),
    ("LED · cycle idle color", Act::LedCycle),
    ("Backup · export (BIP-39)", Act::BackupExport),
    ("Backup · restore (BIP-39)", Act::BackupRestore),
    ("Backup · finalize (seal window)", Act::BackupFinalize),
    ("Reboot → BOOTSEL", Act::RebootBootsel),
    ("Reboot → app", Act::RebootApp),
];

enum Pending {
    Export,          // input buf = PIN
    RestorePhrase,   // input buf = phrase
    Restore(String), // input buf = PIN, holds the phrase
    Finalize,        // input buf = the typed SEAL confirmation
}

enum Mode {
    Normal,
    Input {
        prompt: String,
        buf: String,
        mask: bool,
        then: Pending,
    },
    Reveal {
        body: String,
    },
}

struct App {
    status: Status,
    refreshed: Instant,
    list: ListState,
    log: String,
    mode: Mode,
}

impl App {
    fn new() -> Self {
        let mut list = ListState::default();
        list.select(Some(0));
        App {
            status: device::gather(),
            refreshed: Instant::now(),
            list,
            log: String::new(),
            mode: Mode::Normal,
        }
    }
    fn refresh(&mut self) {
        self.status = device::gather();
        self.refreshed = Instant::now();
    }
    fn move_sel(&mut self, d: i32) {
        let n = ACTIONS.len() as i32;
        let cur = self.list.selected().unwrap_or(0) as i32;
        self.list.select(Some((((cur + d) % n + n) % n) as usize));
    }
    fn pin_needed(&self) -> bool {
        self.status.client_pin == Some(true)
    }
}

fn status_lines(s: &Status) -> Vec<Line<'static>> {
    let dim = Style::default().fg(Color::DarkGray);
    let kv = |k: &str, v: String, c: Color| {
        Line::from(vec![
            Span::styled(format!("  {k:<13}"), dim),
            Span::styled(v, Style::default().fg(c)),
        ])
    };
    let mut out = vec![Line::from(Span::styled(
        "FIDO",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    if s.fido_present {
        out.push(kv(
            "firmware",
            s.fw.clone().unwrap_or_else(|| "—".into()),
            Color::Green,
        ));
        out.push(kv("versions", s.versions.join(", "), Color::Cyan));
        out.push(kv(
            "clientPin",
            s.client_pin
                .map(|b| b.to_string())
                .unwrap_or_else(|| "—".into()),
            Color::Cyan,
        ));
        if let Some(a) = &s.aaguid {
            out.push(kv(
                "aaguid",
                a.chars().take(16).collect::<String>() + "…",
                Color::DarkGray,
            ));
        }
        if let Some((sealed, has_seed)) = s.backup {
            out.push(kv(
                "backup",
                format!("sealed={sealed}  has_seed={has_seed}"),
                if sealed { Color::Yellow } else { Color::Green },
            ));
        }
        if let Some((locked, unlocked)) = s.lock {
            out.push(kv(
                "seed lock",
                match (locked, unlocked) {
                    (false, _) => "off".into(),
                    (true, true) => "LOCKED (unlocked this session)".into(),
                    (true, false) => "LOCKED — FIDO ops disabled until unlock".into(),
                },
                if locked { Color::Yellow } else { Color::Green },
            ));
        }
    } else {
        out.push(Line::from(Span::styled(
            "  not found",
            Style::default().fg(Color::Red),
        )));
    }
    out.push(Line::from(""));
    out.push(Line::from(Span::styled(
        "Secure boot",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    match s.secure_boot {
        Some((enabled, locked, bootkey)) => {
            let (txt, col) = if locked {
                ("LOCKED", Color::Green)
            } else if enabled {
                ("ENABLED", Color::Yellow)
            } else {
                ("not enabled", Color::Red)
            };
            out.push(kv("state", txt.into(), col));
            out.push(kv(
                "enabled/lock",
                format!("{enabled} / {locked}"),
                Color::Cyan,
            ));
            out.push(kv("bootkey", format!("{bootkey:#x}"), Color::DarkGray));
        }
        None => out.push(Line::from(Span::styled(
            "  (CCID unavailable — reader busy?)",
            Style::default().fg(Color::DarkGray),
        ))),
    }
    out
}

fn centered(area: Rect, pct_x: u16, lines: u16) -> Rect {
    let w = area.width * pct_x / 100;
    let x = area.x + (area.width - w) / 2;
    let y = area.y + area.height.saturating_sub(lines) / 2;
    Rect {
        x,
        y,
        width: w,
        height: lines.min(area.height),
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(f.area());

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " rs-key ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  device dashboard "),
        Span::styled(
            format!("(refreshed {}s ago)", app.refreshed.elapsed().as_secs()),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, rows[0]);

    let body =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(rows[1]);
    f.render_widget(
        Paragraph::new(status_lines(&app.status))
            .block(Block::default().borders(Borders::ALL).title(" status "))
            .wrap(Wrap { trim: true }),
        body[0],
    );
    let items: Vec<ListItem> = ACTIONS.iter().map(|(l, _)| ListItem::new(*l)).collect();
    f.render_stateful_widget(
        List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" actions "))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ "),
        body[1],
        &mut app.list,
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            format!(" {}", app.log),
            Style::default().fg(Color::Yellow),
        )),
        rows[2],
    );
    let hint = match app.mode {
        Mode::Normal => " ↑/↓ or j/k: select   ↵: run   r: refresh   q: quit ",
        Mode::Input { .. } => " type input   ↵: confirm   esc: cancel ",
        Mode::Reveal { .. } => " write it down, then press any key to clear ",
    };
    f.render_widget(
        Paragraph::new(Span::styled(hint, Style::default().fg(Color::DarkGray))),
        rows[3],
    );

    match &app.mode {
        Mode::Input {
            prompt, buf, mask, ..
        } => {
            let shown = if *mask {
                "•".repeat(buf.chars().count())
            } else {
                buf.clone()
            };
            let area = centered(f.area(), 72, 6);
            f.render_widget(Clear, area);
            f.render_widget(
                Paragraph::new(vec![Line::from(""), Line::from(format!("  {shown}_"))])
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(format!(" {prompt} ")),
                    )
                    .wrap(Wrap { trim: true }),
                area,
            );
        }
        Mode::Reveal { body } => {
            let area = centered(f.area(), 86, 9);
            f.render_widget(Clear, area);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(
                        "  WRITE THIS DOWN — the only backup of your FIDO seed.",
                        Style::default().fg(Color::Yellow),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("  {body}"),
                        Style::default().fg(Color::Green),
                    )),
                ])
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" seed · BIP-39 "),
                )
                .wrap(Wrap { trim: true }),
                area,
            );
        }
        Mode::Normal => {}
    }
}

fn run_blocking(
    app: &mut App,
    term: &mut Term,
    msg: &str,
    f: impl FnOnce() -> Result<String, String>,
) -> io::Result<Result<String, String>> {
    app.log = msg.into();
    term.draw(|fr| ui(fr, app))?;
    Ok(f())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--once") {
        for line in status_lines(&device::gather()) {
            println!(
                "{}",
                line.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            );
        }
        return Ok(());
    }
    if let Some(i) = args.iter().position(|a| a == "--selftest") {
        match device::export_selftest(args.get(i + 1).map(String::as_str)) {
            Ok(s) => println!("export selftest OK: {s}"),
            Err(e) => {
                eprintln!("export selftest FAILED: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // Restore the terminal on EVERY exit path — q/Esc/Ctrl-C, an io error
    // propagating out of the event loop, or a panic (device I/O can panic) —
    // otherwise the shell is left in raw mode with no echo.
    let prev_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        prev_panic(info);
    }));
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let res = run(&mut term);
    restore_terminal();
    res
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
}

fn zeroize_mode(mode: Mode) {
    match mode {
        Mode::Reveal { mut body } => body.zeroize(),
        Mode::Input { mut buf, then, .. } => {
            buf.zeroize();
            if let Pending::Restore(mut phrase) = then {
                phrase.zeroize();
            }
        }
        Mode::Normal => {}
    }
}

fn run(term: &mut Term) -> io::Result<()> {
    let mut app = App::new();
    loop {
        term.draw(|f| ui(f, &mut app))?;
        if !event::poll(Duration::from_millis(400))? {
            if matches!(app.mode, Mode::Normal) && app.refreshed.elapsed() >= Duration::from_secs(3)
            {
                app.refresh();
            }
            continue;
        }
        let Event::Key(k) = event::read()? else {
            continue;
        };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        // raw mode swallows SIGINT — Ctrl-C arrives as a plain key event
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            zeroize_mode(std::mem::replace(&mut app.mode, Mode::Normal));
            return Ok(());
        }
        match &mut app.mode {
            Mode::Reveal { .. } => {
                zeroize_mode(std::mem::replace(&mut app.mode, Mode::Normal));
                app.log = "seed cleared from the screen".into();
            }
            Mode::Input { buf, .. } => match k.code {
                KeyCode::Esc => {
                    zeroize_mode(std::mem::replace(&mut app.mode, Mode::Normal));
                    app.log = "cancelled".into();
                }
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) => buf.push(c),
                KeyCode::Enter => {
                    let Mode::Input { buf, then, .. } =
                        std::mem::replace(&mut app.mode, Mode::Normal)
                    else {
                        unreachable!()
                    };
                    dispatch(&mut app, term, buf, then)?;
                }
                _ => {}
            },
            Mode::Normal => match k.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('r') => {
                    app.refresh();
                    app.log = "status refreshed".into();
                }
                KeyCode::Down | KeyCode::Char('j') => app.move_sel(1),
                KeyCode::Up | KeyCode::Char('k') => app.move_sel(-1),
                KeyCode::Enter => {
                    let (_, act) = ACTIONS[app.list.selected().unwrap_or(0)];
                    start_action(&mut app, term, act)?;
                }
                _ => {}
            },
        }
    }
}

fn start_action(app: &mut App, term: &mut Term, act: Act) -> io::Result<()> {
    match act {
        Act::Refresh => {
            app.refresh();
            app.log = "status refreshed".into();
        }
        Act::LedGet => {
            app.log = device::led_get().unwrap_or_else(|e| format!("LED get failed: {e}"))
        }
        Act::LedCycle => {
            app.log = device::led_cycle_idle().unwrap_or_else(|e| format!("LED set failed: {e}"))
        }
        Act::RebootBootsel => {
            app.log = device::reboot(true).unwrap_or_else(|e| format!("reboot failed: {e}"))
        }
        Act::RebootApp => {
            app.log = device::reboot(false).unwrap_or_else(|e| format!("reboot failed: {e}"))
        }
        Act::BackupExport => {
            if app.pin_needed() {
                app.mode = Mode::Input {
                    prompt: "FIDO2 PIN".into(),
                    buf: String::new(),
                    mask: true,
                    then: Pending::Export,
                };
            } else {
                export(app, term, None)?;
            }
        }
        Act::BackupRestore => {
            app.mode = Mode::Input {
                prompt: "BIP-39 phrase (24 words)".into(),
                buf: String::new(),
                mask: false,
                then: Pending::RestorePhrase,
            };
        }
        Act::BackupFinalize => {
            if app.status.backup.map(|(sealed, _)| sealed).unwrap_or(false) {
                app.log = "already sealed — a factory reset reopens the window".into();
            } else {
                app.mode = Mode::Input {
                    prompt: "seal export window — irreversible until reset; type SEAL".into(),
                    buf: String::new(),
                    mask: false,
                    then: Pending::Finalize,
                };
            }
        }
    }
    Ok(())
}

fn dispatch(app: &mut App, term: &mut Term, mut buf: String, then: Pending) -> io::Result<()> {
    match then {
        Pending::Export => export(app, term, Some(&buf))?,
        Pending::RestorePhrase => {
            if app.pin_needed() {
                app.mode = Mode::Input {
                    prompt: "FIDO2 PIN".into(),
                    buf: String::new(),
                    mask: true,
                    then: Pending::Restore(buf),
                };
                return Ok(());
            }
            restore(app, term, &buf, None)?;
        }
        Pending::Restore(phrase) => restore(app, term, &phrase, Some(&buf))?,
        Pending::Finalize => {
            if buf.trim() == "SEAL" {
                let r = run_blocking(
                    app,
                    term,
                    "sealing — touch the device if it asks…",
                    device::backup_finalize,
                )?;
                app.log = match r {
                    Ok(m) => m,
                    Err(e) => format!("finalize failed: {e}"),
                };
                app.refresh();
            } else {
                app.log = "finalize cancelled (type SEAL to confirm)".into();
            }
        }
    }
    buf.zeroize();
    Ok(())
}

fn export(app: &mut App, term: &mut Term, pin: Option<&str>) -> io::Result<()> {
    let pin = pin.map(String::from);
    match run_blocking(
        app,
        term,
        "exporting — touch the device if it asks…",
        || device::backup_export(pin.as_deref()),
    )? {
        Ok(words) => {
            app.mode = Mode::Reveal { body: words };
            app.log = "seed exported".into();
        }
        Err(e) => app.log = format!("export failed: {e}"),
    }
    Ok(())
}

fn restore(app: &mut App, term: &mut Term, phrase: &str, pin: Option<&str>) -> io::Result<()> {
    let (phrase, pin) = (phrase.to_string(), pin.map(String::from));
    let r = run_blocking(
        app,
        term,
        "restoring — touch the device if it asks…",
        || device::backup_restore(&phrase, pin.as_deref()),
    )?;
    app.log = match r {
        Ok(m) => m,
        Err(e) => format!("restore failed: {e}"),
    };
    app.refresh();
    Ok(())
}
