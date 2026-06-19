// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! App state, modes, navigation, and the modal/confirmation flow.
//!
//! Everything here is pure state manipulation — no terminal, no blocking device
//! I/O. [`App::begin_action`] and [`App::submit_modal`] drive the multi-step
//! flows (typed confirmation → PIN → run) and are unit-tested directly against a
//! [`MockProvider`](crate::device::MockProvider).

use std::time::Instant;

use zeroize::{Zeroize, Zeroizing};

use crate::device::DeviceProvider;
use crate::model::*;
use crate::theme::Theme;

/// What the event loop should do after handling input.
#[derive(Debug, PartialEq, Eq)]
pub enum Flow {
    /// Nothing more — just redraw.
    Continue,
    /// Run this action (with whatever inputs are staged) via `actions::run`.
    Run(Action),
}

/// A step in a multi-stage modal flow — the continuation once the current modal
/// is submitted.
#[derive(Clone, Copy, Debug)]
pub enum Step {
    ExportConfirmed,
    RestorePhrase,
    RestoreConfirmed,
    FinalizeConfirmed,
    RebootApp,
    RebootBootsel,
    /// PIN collected (or skipped) — now run this action. The single continuation
    /// for every PIN-gated action; opened via `App::gate_pin`.
    PinThenRun(Action),
}

pub enum Modal {
    /// Free-text or masked input.
    Input {
        title: String,
        prompt: String,
        buf: String,
        mask: bool,
        then: Step,
    },
    /// Typed confirmation: the user must type `want` exactly (e.g. "SEAL").
    Confirm {
        title: String,
        body: String,
        want: &'static str,
        buf: String,
        then: Step,
    },
    /// Simple yes/no (Enter/y = yes).
    YesNo {
        title: String,
        body: String,
        then: Step,
    },
    /// A secret shown once, then zeroized. Never logged.
    Reveal {
        title: String,
        body: Zeroizing<String>,
    },
    /// Non-secret informational / result modal.
    Message {
        title: String,
        body: String,
        level: LogLevel,
    },
}

/// The `/` action search palette.
pub struct Search {
    pub query: String,
    pub sel: usize,
}

pub enum AppMode {
    Normal,
    Modal(Modal),
    Search(Search),
}

/// One row of a section's menu.
pub struct MenuItem {
    pub label: String,
    pub hint: String,
    pub health: Health,
    pub kind: MenuKind,
}

pub enum MenuKind {
    /// A device operation the TUI can run.
    Run(Action),
    /// CLI-only / informational pointer. Selecting it explains; never faked.
    Note { title: String, body: String },
    /// Currently unavailable; selecting it explains why.
    Disabled(String),
}

pub struct App {
    pub provider: Box<dyn DeviceProvider>,
    pub theme: Theme,
    pub snapshot: DeviceSnapshot,
    pub refreshed: Instant,
    pub section: Section,
    pub menu_sel: usize,
    pub mode: AppMode,
    pub log: EventLog,
    pub status: String,
    pub status_level: LogLevel,
    /// Secrets collected across a modal flow; consumed by `actions::run`.
    pub staging: ActionInput,
    pub should_quit: bool,
}

impl App {
    pub fn new(mut provider: Box<dyn DeviceProvider>, theme: Theme) -> Self {
        let snapshot = provider.snapshot();
        let mut app = App {
            provider,
            theme,
            snapshot,
            refreshed: Instant::now(),
            section: Section::Overview,
            menu_sel: 0,
            mode: AppMode::Normal,
            log: EventLog::default(),
            status: String::new(),
            status_level: LogLevel::Info,
            staging: ActionInput::default(),
            should_quit: false,
        };
        if app.snapshot.demo {
            app.log(LogLevel::Info, "demo mode — no hardware, simulated device");
        } else if app.snapshot.any_device() {
            app.log(
                LogLevel::Good,
                format!("connected: {}", app.snapshot.summary()),
            );
        } else {
            app.log(LogLevel::Warn, "no device detected — plug in an RS-Key");
        }
        app
    }

    // ---- logging (the one place action text lands; redaction lives here) ----

    /// Push a log line + update the status bar. Any live PIN/phrase substring is
    /// redacted as a defensive backstop on top of never passing secrets here.
    pub fn log(&mut self, level: LogLevel, text: impl Into<String>) {
        let text = text.into();
        let mut secrets: Vec<&str> = Vec::new();
        if let Some(p) = &self.staging.pin {
            secrets.push(p);
        }
        if let Some(p) = &self.staging.phrase {
            secrets.push(p);
        }
        match &self.mode {
            AppMode::Modal(Modal::Input { buf, .. })
            | AppMode::Modal(Modal::Confirm { buf, .. }) => secrets.push(buf),
            _ => {}
        }
        // `self.log` is a distinct field from staging/mode, so these borrows are
        // disjoint and the borrow checker accepts the simultaneous access.
        self.log.push(level, text.clone(), &secrets);
        self.status = text;
        self.status_level = level;
    }

    /// Set the status bar without adding a log entry (transient "working…").
    pub fn set_status(&mut self, level: LogLevel, text: impl Into<String>) {
        self.status = text.into();
        self.status_level = level;
    }

    // ---- snapshot ----

    pub fn refresh(&mut self) {
        self.snapshot = self.provider.snapshot();
        self.refreshed = Instant::now();
    }

    pub fn pin_set(&self) -> bool {
        self.snapshot.pin_set()
    }

    // ---- navigation ----

    pub fn next_section(&mut self) {
        let i = Section::ALL
            .iter()
            .position(|s| *s == self.section)
            .unwrap_or(0);
        self.set_section(Section::ALL[(i + 1) % Section::ALL.len()]);
    }

    pub fn prev_section(&mut self) {
        let n = Section::ALL.len();
        let i = Section::ALL
            .iter()
            .position(|s| *s == self.section)
            .unwrap_or(0);
        self.set_section(Section::ALL[(i + n - 1) % n]);
    }

    pub fn set_section(&mut self, s: Section) {
        self.section = s;
        self.menu_sel = 0;
    }

    pub fn move_menu(&mut self, delta: i32) {
        let n = self.menu().len() as i32;
        if n == 0 {
            return;
        }
        let cur = self.menu_sel as i32;
        self.menu_sel = (((cur + delta) % n + n) % n) as usize;
    }

    // ---- menus ----

    /// The menu for the current section, computed from the live snapshot.
    pub fn menu(&self) -> Vec<MenuItem> {
        menu_for(self.section, &self.snapshot)
    }

    /// Enter on the highlighted menu row.
    pub fn activate_menu(&mut self) -> Flow {
        let menu = self.menu();
        let Some(item) = menu.into_iter().nth(self.menu_sel) else {
            return Flow::Continue;
        };
        match item.kind {
            MenuKind::Run(action) => self.begin_action(action),
            MenuKind::Note { title, body } => {
                self.open_message(title, body, LogLevel::Info);
                Flow::Continue
            }
            MenuKind::Disabled(reason) => {
                self.open_message("unavailable".into(), reason, LogLevel::Warn);
                Flow::Continue
            }
        }
    }

    // ---- the action / confirmation flow ----

    /// Begin an action: either run it immediately or open the first modal of a
    /// confirmation flow.
    pub fn begin_action(&mut self, action: Action) -> Flow {
        match action {
            Action::Refresh | Action::LedGet | Action::LedCycle => Flow::Run(action),
            Action::Verify => self.gate_pin(Action::Verify),
            Action::AuditRead => self.gate_pin(Action::AuditRead),
            Action::RebootApp => {
                self.mode = AppMode::Modal(Modal::YesNo {
                    title: "reboot to app".into(),
                    body: "Restart the firmware now? The device will briefly disconnect.".into(),
                    then: Step::RebootApp,
                });
                Flow::Continue
            }
            Action::RebootBootsel => {
                self.open_confirm(
                    "reboot to BOOTSEL".into(),
                    "Drops the device into firmware-update (mass-storage) mode — it leaves \
                     the USB bus until reflashed or re-plugged."
                        .into(),
                    "BOOTSEL",
                    Step::RebootBootsel,
                );
                Flow::Continue
            }
            Action::BackupExport => {
                self.open_confirm(
                    "export seed".into(),
                    "Reveals your FIDO seed as a 24-word phrase on this screen. Anyone who \
                     reads it can clone your identity. Make sure nobody is watching."
                        .into(),
                    "EXPORT",
                    Step::ExportConfirmed,
                );
                Flow::Continue
            }
            Action::BackupRestore => {
                self.mode = AppMode::Modal(Modal::Input {
                    title: "restore seed".into(),
                    prompt: "BIP-39 phrase (24 words)".into(),
                    buf: String::new(),
                    mask: false,
                    then: Step::RestorePhrase,
                });
                Flow::Continue
            }
            Action::BackupFinalize => {
                if self.snapshot.sealed() {
                    self.open_message(
                        "already sealed".into(),
                        "The export window is already sealed. A factory reset reopens it.".into(),
                        LogLevel::Info,
                    );
                } else {
                    self.open_confirm(
                        "seal backup window".into(),
                        "Permanently disables seed export until a factory reset. Make sure you \
                         have a backup first."
                            .into(),
                        "SEAL",
                        Step::FinalizeConfirmed,
                    );
                }
                Flow::Continue
            }
        }
    }

    /// Enter inside a modal.
    pub fn submit_modal(&mut self) -> Flow {
        let mode = std::mem::replace(&mut self.mode, AppMode::Normal);
        let AppMode::Modal(modal) = mode else {
            self.mode = mode;
            return Flow::Continue;
        };
        match modal {
            Modal::Reveal { mut body, .. } => {
                body.zeroize();
                self.log(LogLevel::Info, "seed cleared from the screen");
                Flow::Continue
            }
            Modal::Message { .. } => Flow::Continue,
            Modal::YesNo { then, .. } => self.advance(then),
            Modal::Confirm {
                want,
                mut buf,
                then,
                ..
            } => {
                let ok = buf.trim() == want;
                buf.zeroize();
                if ok {
                    self.advance(then)
                } else {
                    self.clear_staging();
                    self.log(
                        LogLevel::Warn,
                        format!("cancelled — type {want} to confirm"),
                    );
                    Flow::Continue
                }
            }
            Modal::Input { mut buf, then, .. } => {
                match then {
                    Step::RestorePhrase => self.staging.phrase = Some(Zeroizing::new(buf.clone())),
                    Step::PinThenRun(_) => self.staging.pin = Some(Zeroizing::new(buf.clone())),
                    // Input modals only ever collect a restore phrase or a PIN.
                    other => debug_assert!(false, "unexpected Input step: {other:?}"),
                }
                buf.zeroize();
                self.advance(then)
            }
        }
    }

    /// Advance a confirmation flow to its next modal or to the run.
    fn advance(&mut self, step: Step) -> Flow {
        match step {
            Step::ExportConfirmed => self.gate_pin(Action::BackupExport),
            Step::RestorePhrase => {
                self.open_confirm(
                    "restore seed".into(),
                    "Overwrites this device's current seed with the phrase you entered. All \
                     credentials derived from the old seed stop working."
                        .into(),
                    "RESTORE",
                    Step::RestoreConfirmed,
                );
                Flow::Continue
            }
            Step::RestoreConfirmed => self.gate_pin(Action::BackupRestore),
            Step::FinalizeConfirmed => Flow::Run(Action::BackupFinalize),
            Step::RebootApp => Flow::Run(Action::RebootApp),
            Step::RebootBootsel => Flow::Run(Action::RebootBootsel),
            Step::PinThenRun(action) => Flow::Run(action),
        }
    }

    // ---- modal helpers ----

    /// The single PIN chokepoint: if the device has a clientPIN, open the masked
    /// PIN prompt and run `action` once it is entered; otherwise run `action`
    /// straight away. Every PIN-gated action routes through here, so "does this
    /// need a PIN?" lives in exactly one place (mirrors the CLI's `resolve_pin`).
    fn gate_pin(&mut self, action: Action) -> Flow {
        if self.pin_set() {
            self.open_pin(Step::PinThenRun(action));
            Flow::Continue
        } else {
            Flow::Run(action)
        }
    }

    fn open_pin(&mut self, then: Step) {
        self.mode = AppMode::Modal(Modal::Input {
            title: "authenticate".into(),
            prompt: "FIDO2 PIN".into(),
            buf: String::new(),
            mask: true,
            then,
        });
    }

    fn open_confirm(&mut self, title: String, body: String, want: &'static str, then: Step) {
        self.mode = AppMode::Modal(Modal::Confirm {
            title,
            body,
            want,
            buf: String::new(),
            then,
        });
    }

    pub fn open_message(&mut self, title: String, body: String, level: LogLevel) {
        self.mode = AppMode::Modal(Modal::Message { title, body, level });
    }

    pub fn open_reveal(&mut self, title: String, body: Zeroizing<String>) {
        self.mode = AppMode::Modal(Modal::Reveal { title, body });
    }

    /// Esc / Ctrl-C cleanup: zeroize any in-flight secret and return to Normal.
    pub fn cancel_modal(&mut self) {
        let mode = std::mem::replace(&mut self.mode, AppMode::Normal);
        if let AppMode::Modal(modal) = mode {
            match modal {
                Modal::Input { mut buf, .. } | Modal::Confirm { mut buf, .. } => buf.zeroize(),
                Modal::Reveal { mut body, .. } => body.zeroize(),
                _ => {}
            }
        }
        self.clear_staging();
    }

    pub fn clear_staging(&mut self) {
        // Zeroizing wipes on drop.
        self.staging = ActionInput::default();
    }

    // ---- search palette ----

    pub fn open_search(&mut self) {
        self.mode = AppMode::Search(Search {
            query: String::new(),
            sel: 0,
        });
    }

    /// Actions whose label matches the query (case-insensitive substring).
    pub fn search_results(query: &str) -> Vec<Action> {
        let q = query.trim().to_ascii_lowercase();
        Action::ALL
            .iter()
            .copied()
            .filter(|a| q.is_empty() || a.label().to_ascii_lowercase().contains(&q))
            .collect()
    }
}

/// Build the menu rows for a section from the snapshot.
fn menu_for(section: Section, snap: &DeviceSnapshot) -> Vec<MenuItem> {
    let run = |label: &str, hint: &str, action: Action| MenuItem {
        label: label.into(),
        hint: hint.into(),
        health: Health::Ok,
        kind: MenuKind::Run(action),
    };
    let note = |label: &str, hint: &str, title: &str, body: &str| MenuItem {
        label: label.into(),
        hint: hint.into(),
        health: Health::NotApplicable,
        kind: MenuKind::Note {
            title: title.into(),
            body: body.into(),
        },
    };
    match section {
        Section::Overview => vec![
            run("Refresh status", "re-read all channels", Action::Refresh),
            run(
                "Verify device identity",
                "signed challenge · touch",
                Action::Verify,
            ),
        ],
        Section::Fido => vec![
            run("Refresh status", "re-read getInfo", Action::Refresh),
            note(
                "Set / change PIN",
                "CLI",
                "FIDO PIN",
                "Auth-changing writes stay in the CLI:\n  rsk fido set-pin\n  rsk fido change-pin",
            ),
            note(
                "List resident passkeys",
                "CLI · PIN",
                "list passkeys",
                "Resident-credential enumeration needs the PIN + credMgmt:\n  rsk fido list-passkeys --pin …",
            ),
            note(
                "Factory reset FIDO",
                "CLI · destructive",
                "FIDO reset",
                "Destructive — erases the seed, every passkey, and the PIN:\n  rsk fido reset   (touch within 10 s of plug-in)",
            ),
        ],
        Section::OpenPgp => vec![
            note(
                "Card status",
                "external",
                "OpenPGP card",
                "Presence is shown above. Full card data (key fingerprints, PIN\nretries, cardholder): gpg --card-status",
            ),
            note(
                "Factory reset",
                "CLI · destructive",
                "OpenPGP reset",
                "Destructive — blocks the PINs, then TERMINATE + ACTIVATE:\n  rsk openpgp reset",
            ),
        ],
        Section::Piv => vec![
            note(
                "Card status",
                "external",
                "PIV applet",
                "Presence is shown above. Full data: ykman piv info, or OpenSC\n  pkcs11-tool --list-objects",
            ),
            note(
                "Factory reset",
                "CLI · destructive",
                "PIV reset",
                "Destructive — needs PIN + PUK blocked first:\n  ykman piv reset",
            ),
        ],
        Section::OathOtp => vec![
            note(
                "OATH codes",
                "external",
                "OATH (TOTP/HOTP)",
                "Presence is shown above. Manage credentials with:\n  ykman oath accounts …",
            ),
            note(
                "Yubico-OTP slots",
                "CLI · write",
                "OTP slots",
                "Slot programming is a write — use the CLI:\n  rsk otp …   (or ykman otp)",
            ),
        ],
        Section::Backup => {
            let mut v = vec![MenuItem {
                label: "Export seed (BIP-39)".into(),
                hint: "touch · reveals 24 words".into(),
                health: if snap.sealed() {
                    Health::Warn
                } else {
                    Health::Ok
                },
                kind: MenuKind::Run(Action::BackupExport),
            }];
            v.push(run(
                "Restore seed (BIP-39)",
                "touch · overwrites seed",
                Action::BackupRestore,
            ));
            if snap.sealed() {
                v.push(MenuItem {
                    label: "Finalize — seal export window".into(),
                    hint: "already sealed".into(),
                    health: Health::NotApplicable,
                    kind: MenuKind::Disabled(
                        "The export window is already sealed. A factory reset reopens it.".into(),
                    ),
                });
            } else {
                v.push(run(
                    "Finalize — seal export window",
                    "touch · irreversible",
                    Action::BackupFinalize,
                ));
            }
            v.push(note(
                "SLIP-39 (Shamir T-of-N)",
                "CLI",
                "SLIP-39 backup",
                "SLIP-39 export/restore (split shares) stays in the CLI:\n  rsk backup export --scheme slip39",
            ));
            v
        }
        Section::Led => vec![
            run("Read LED state", "GET LED", Action::LedGet),
            run("Cycle idle color", "SET LED", Action::LedCycle),
        ],
        Section::Audit => vec![
            run("Read journal", "AUDIT_READ · PIN if set", Action::AuditRead),
            run(
                "Verify identity (checkpoint)",
                "touch · ECDSA verify",
                Action::Verify,
            ),
            note(
                "Full chain verify",
                "CLI",
                "audit verify",
                "rsk audit verify cross-checks the exported window against the\nsigned head and can pin the key with --expect-key.",
            ),
        ],
        Section::Reboot => vec![
            run("Reboot → app", "warm restart", Action::RebootApp),
            run(
                "Reboot → BOOTSEL",
                "firmware-update mode · confirm",
                Action::RebootBootsel,
            ),
            note(
                "Seed soft-lock",
                "CLI · PIN · touch",
                "soft-lock",
                "Engage / unlock / disengage the seed soft-lock:\n  rsk lock engage | unlock | disengage",
            ),
            note(
                "Org attestation",
                "CLI · PIN · touch",
                "attestation",
                "Import / clear an org attestation key + chain:\n  rsk fido attest import | clear",
            ),
            note(
                "Secure boot / OTP fuses",
                "CLI · irreversible",
                "production fuses",
                "Irreversible production rituals stay CLI-only:\n  rsk secure-boot …   rsk otp …\nSee docs/production.md before running any of these.",
            ),
        ],
        Section::Help => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockProvider;

    fn app() -> App {
        App::new(Box::new(MockProvider::new()), Theme { ascii: true })
    }

    #[test]
    fn section_cycling_wraps() {
        let mut a = app();
        assert_eq!(a.section, Section::Overview);
        a.prev_section();
        assert_eq!(a.section, Section::Help);
        a.next_section();
        assert_eq!(a.section, Section::Overview);
    }

    #[test]
    fn menu_selection_wraps_and_resets_on_section_change() {
        let mut a = app();
        a.set_section(Section::Backup);
        assert_eq!(a.menu_sel, 0);
        let n = a.menu().len();
        assert!(n >= 3);
        a.move_menu(-1);
        assert_eq!(a.menu_sel, n - 1);
        a.move_menu(1);
        assert_eq!(a.menu_sel, 0);
        a.set_section(Section::Led);
        assert_eq!(a.menu_sel, 0);
    }

    #[test]
    fn finalize_requires_typed_seal() {
        let mut a = app();
        let flow = a.begin_action(Action::BackupFinalize);
        assert_eq!(flow, Flow::Continue);
        // Wrong text cancels, does not run.
        if let AppMode::Modal(Modal::Confirm { buf, .. }) = &mut a.mode {
            *buf = "seal".into(); // lowercase ≠ SEAL
        } else {
            panic!("expected confirm modal");
        }
        assert_eq!(a.submit_modal(), Flow::Continue);
        assert!(matches!(a.mode, AppMode::Normal));

        // Correct text runs it.
        a.begin_action(Action::BackupFinalize);
        if let AppMode::Modal(Modal::Confirm { buf, .. }) = &mut a.mode {
            *buf = "SEAL".into();
        } else {
            panic!("expected confirm modal");
        }
        assert_eq!(a.submit_modal(), Flow::Run(Action::BackupFinalize));
    }

    #[test]
    fn export_flow_confirm_then_pin_then_run() {
        let mut a = app(); // mock has client_pin = true
        assert_eq!(a.begin_action(Action::BackupExport), Flow::Continue);
        // Typed EXPORT confirmation.
        if let AppMode::Modal(Modal::Confirm { buf, want, .. }) = &mut a.mode {
            assert_eq!(*want, "EXPORT");
            *buf = "EXPORT".into();
        } else {
            panic!("expected EXPORT confirm");
        }
        // → opens a masked PIN input.
        assert_eq!(a.submit_modal(), Flow::Continue);
        match &mut a.mode {
            AppMode::Modal(Modal::Input { mask, buf, .. }) => {
                assert!(*mask);
                *buf = "1234".into();
            }
            _ => panic!("expected PIN input"),
        }
        // → runs the export with the staged PIN.
        assert_eq!(a.submit_modal(), Flow::Run(Action::BackupExport));
        assert_eq!(a.staging.pin.as_deref().map(String::as_str), Some("1234"));
    }

    #[test]
    fn export_without_pin_skips_straight_to_run() {
        let mut a = app();
        a.snapshot.fido.client_pin = Some(false);
        a.begin_action(Action::BackupExport);
        if let AppMode::Modal(Modal::Confirm { buf, .. }) = &mut a.mode {
            *buf = "EXPORT".into();
        } else {
            panic!("expected confirm");
        }
        assert_eq!(a.submit_modal(), Flow::Run(Action::BackupExport));
    }

    #[test]
    fn verify_gates_pin_through_the_chokepoint() {
        let mut a = app(); // mock has client_pin = true
        // A directly-gated action (no typed confirm first) opens the masked PIN.
        assert_eq!(a.begin_action(Action::Verify), Flow::Continue);
        match &mut a.mode {
            AppMode::Modal(Modal::Input { mask, buf, .. }) => {
                assert!(*mask);
                *buf = "1234".into();
            }
            _ => panic!("expected PIN input"),
        }
        // The single PinThenRun continuation routes back to the right action.
        assert_eq!(a.submit_modal(), Flow::Run(Action::Verify));
        assert_eq!(a.staging.pin.as_deref().map(String::as_str), Some("1234"));
    }

    #[test]
    fn verify_without_pin_runs_directly() {
        let mut a = app();
        a.snapshot.fido.client_pin = Some(false);
        // No clientPIN → the chokepoint runs the action with no prompt.
        assert_eq!(a.begin_action(Action::Verify), Flow::Run(Action::Verify));
        assert!(matches!(a.mode, AppMode::Normal));
    }

    #[test]
    fn reboot_bootsel_needs_typed_confirmation() {
        let mut a = app();
        a.begin_action(Action::RebootBootsel);
        match &mut a.mode {
            AppMode::Modal(Modal::Confirm { want, buf, .. }) => {
                assert_eq!(*want, "BOOTSEL");
                *buf = "BOOTSEL".into();
            }
            _ => panic!("expected BOOTSEL confirm"),
        }
        assert_eq!(a.submit_modal(), Flow::Run(Action::RebootBootsel));
    }

    #[test]
    fn cancel_zeroizes_and_returns_to_normal() {
        let mut a = app();
        a.begin_action(Action::BackupRestore);
        if let AppMode::Modal(Modal::Input { buf, .. }) = &mut a.mode {
            *buf = "secret words".into();
        }
        a.cancel_modal();
        assert!(matches!(a.mode, AppMode::Normal));
        assert!(a.staging.phrase.is_none());
    }

    #[test]
    fn search_filters_actions() {
        let all = App::search_results("");
        assert_eq!(all.len(), Action::ALL.len());
        let led = App::search_results("led");
        assert!(
            led.iter()
                .all(|a| a.label().to_ascii_lowercase().contains("led"))
        );
        assert!(!led.is_empty());
        assert!(App::search_results("zzz-no-match").is_empty());
    }
}
