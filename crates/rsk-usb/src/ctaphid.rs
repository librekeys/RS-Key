// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAPHID transport. Frames are 64-byte HID reports:
//! - INIT frame:  cid(4) | cmd(1, bit7=1) | bcnt_hi(1) | bcnt_lo(1) | data(57)
//! - CONT frame:  cid(4) | seq(1, bit7=0) | data(59)
//!
//! [`Reassembler`] (RX) and [`TxFrames`] (TX) are pure and HAL-free — unit-tested
//! and fuzzed on the host; [`CtapHid`] is the async wrapper around them. Native
//! commands (INIT, PING, WINK, LOCK, VERSION, UUID, CANCEL) are answered in the
//! transport; MSG (U2F APDU) and CBOR (CTAP2) route to a [`MsgHandler`].

use core::future::Future;

use embassy_futures::select::{Either, select};
use embassy_time::Timer;
use embassy_usb::class::hid::{HidReader, HidWriter};
use embassy_usb::driver::Driver;

pub const HID_RPT_SIZE: usize = 64;
const INIT_DATA: usize = HID_RPT_SIZE - 7; // 57
const CONT_DATA: usize = HID_RPT_SIZE - 5; // 59

const CID_BROADCAST: u32 = 0xffff_ffff;
const TYPE_INIT: u8 = 0x80;

// Command constants keep the TYPE_INIT bit set.
const CTAPHID_PING: u8 = TYPE_INIT | 0x01;
const CTAPHID_MSG: u8 = TYPE_INIT | 0x03;
const CTAPHID_LOCK: u8 = TYPE_INIT | 0x04;
const CTAPHID_INIT: u8 = TYPE_INIT | 0x06;
const CTAPHID_WINK: u8 = TYPE_INIT | 0x08;
const CTAPHID_CBOR: u8 = TYPE_INIT | 0x10;
const CTAPHID_CANCEL: u8 = TYPE_INIT | 0x11;
const CTAPHID_SYNC: u8 = TYPE_INIT | 0x3c;
const CTAPHID_ERROR: u8 = TYPE_INIT | 0x3f;
const CTAPHID_VERSION: u8 = TYPE_INIT | 0x61;
const CTAPHID_UUID: u8 = TYPE_INIT | 0x62;
const CTAPHID_KEEPALIVE: u8 = TYPE_INIT | 0x3b; // 0xBB
const CTAPHID_VENDOR_FIRST: u8 = TYPE_INIT | 0x40;

// Low-level CTAP1 error codes.
const ERR_INVALID_CMD: u8 = 0x01;
const ERR_INVALID_LEN: u8 = 0x03;
const ERR_INVALID_SEQ: u8 = 0x04;
const ERR_MSG_TIMEOUT: u8 = 0x05;
const ERR_CHANNEL_BUSY: u8 = 0x06;
const ERR_INVALID_CHANNEL: u8 = 0x0b;
// CTAP2_ERR_KEEPALIVE_CANCEL
const ERR_KEEPALIVE_CANCEL: u8 = 0x2d;

// KEEPALIVE status byte: the authenticator is still processing the request.
const STATUS_PROCESSING: u8 = 0x01;
// KEEPALIVE status byte: waiting for a user-presence touch (clients show "touch
// your security key"); selected over PROCESSING via the `up_pending` hook.
const STATUS_UPNEEDED: u8 = 0x02;
// Stream a KEEPALIVE this often while the worker runs a long synchronous op
// (slow P-521, flash GC) — well under any host CTAP timeout.
const KEEPALIVE_MS: u64 = 100;
// Abort an in-progress reassembly if the next frame is this late.
const RX_TIMEOUT_MS: u64 = 500;
// Abandon a response if the host stops draining the IN endpoint for this long.
// `HidWriter::write` only completes once the host reads the report, so a client
// that walks away mid-response would otherwise block the transport task forever
// (it then stops reading OUT → every further host write NAKs → the whole FIDO
// interface wedges until a replug). The host polls FIDO HID every few ms, so a
// gap this long means it is gone.
const TX_TIMEOUT_MS: u64 = 500;

const CTAPHID_IF_VERSION: u8 = 2;
const CAPFLAG_WINK: u8 = 0x01;
const CAPFLAG_CBOR: u8 = 0x04;

// Device version reported in CTAPHID_INIT / CTAPHID_VERSION — the shared firmware
// version (default 5.7.4). ykman/yubikit read these three bytes from the INIT
// response as the device firmware version and require >= 4.1.0 before they will
// read the YubiKey Management DeviceInfo over the FIDO interface.
const VERSION_MAJOR: u8 = rsk_sdk::FIRMWARE_VERSION.0;
const VERSION_MINOR: u8 = rsk_sdk::FIRMWARE_VERSION.1;
const VERSION_BUILD: u8 = rsk_sdk::FIRMWARE_VERSION.2;

// The single fixed channel id handed out by CTAPHID_INIT.
const ALLOCATED_CID: u32 = 0x0100_0000;

// 16-byte device UUID returned by CTAPHID_UUID ("rs-key" + version).
// TODO: derive from chip serial.
const DEVICE_UUID: [u8; 16] = [
    0x72, 0x73, 0x2d, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Maximum CTAPHID message: one INIT frame + up to 128 CONT frames.
pub const CTAP_MAX_MESSAGE: usize = INIT_DATA + 128 * CONT_DATA; // 7609

/// Standard FIDO U2F / CTAPHID HID report descriptor (usage page 0xF1D0,
/// 64-byte IN/OUT reports).
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01, //       Usage (CTAPHID)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Data In)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data,Var,Abs)
    0x09, 0x21, //         Usage (Data Out)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data,Var,Abs)
    0xC0, //             End Collection
];

/// Routes reassembled CTAPHID_MSG / CTAPHID_CBOR messages to the applet layer,
/// keeping this transport HAL-free. `firmware` implements it by handing the
/// message to a compute worker on a lower-priority executor, so this transport
/// task stays responsive and streams keepalives while slow crypto/flash runs.
#[allow(async_fn_in_trait)] // crate-internal, single-threaded executor — no Send bound needed
pub trait MsgHandler {
    /// Handle a U2F (ISO-7816) command APDU, writing the response APDU (body +
    /// SW1 SW2) into `out`; returns its length.
    async fn handle_msg(&mut self, apdu: &[u8], out: &mut [u8]) -> usize;

    /// Handle a CTAP2 CBOR message (`command_byte ‖ params`), writing the response
    /// (status byte + optional CBOR) into `out`; returns its length.
    async fn handle_cbor(&mut self, data: &[u8], out: &mut [u8]) -> usize;

    /// Handle a vendor-specific CTAPHID command — `cmd` is the *logical* command
    /// number (the `TYPE_INIT` bit already stripped). Used for the YubiKey
    /// Management DeviceInfo read that `ykman` / Yubico Authenticator issue over
    /// the FIDO interface. Write the response body into `out` and return its
    /// length, or `None` to reject with `CTAPHID_ERROR(ERR_INVALID_CMD)`. The
    /// default rejects every vendor command.
    async fn handle_vendor(&mut self, _cmd: u8, _data: &[u8], _out: &mut [u8]) -> Option<usize> {
        None
    }

    /// Called when a `CTAPHID_INIT` starts a fresh logical session, so the handler
    /// can drop any applet it had selected over this (MSG) transport. U2F/CTAP1 has
    /// no SELECT and must not inherit a prior vendor-AID selection; without this a
    /// sticky selection silently routes U2F REGISTER/AUTHENTICATE/VERSION to the
    /// vendor applet (→ `0x6D00`). Default: no-op.
    fn reset_app_selection(&mut self) {}
}

/// What the transport should do after [`Reassembler::feed`] consumes a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Frame consumed: the message is still incomplete, or a stray continuation
    /// (no transaction in progress) was ignored.
    None,
    /// Reply with `CTAPHID_ERROR(code)` on channel `cid`.
    Error(u32, u8),
    /// Message `(cid, cmd)` is complete; its payload is [`Reassembler::message`].
    Message(u32, u8),
}

/// Stateful CTAPHID frame reassembler — the pure core of the RX path.
///
/// Performs the channel/length/sequence checks: feed it whole 64-byte reports
/// and act on the returned [`Outcome`]. Holds the message buffer so it carries
/// no borrows and is trivial to unit-test and fuzz.
pub struct Reassembler {
    msg: [u8; CTAP_MAX_MESSAGE],
    cid: u32,
    cmd: u8,
    bcnt: usize,
    cur: usize,
    seq: u8,
    in_tx: bool,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub const fn new() -> Self {
        Self {
            msg: [0u8; CTAP_MAX_MESSAGE],
            cid: 0,
            cmd: 0,
            bcnt: 0,
            cur: 0,
            seq: 0,
            in_tx: false,
        }
    }

    /// Payload of the most recently completed message (`msg[..bcnt]`). Valid
    /// until the next [`feed`](Self::feed).
    pub fn message(&self) -> &[u8] {
        &self.msg[..self.bcnt]
    }

    /// Whether a multi-frame message is mid-reassembly (awaiting continuations).
    pub fn in_progress(&self) -> bool {
        self.in_tx
    }

    /// The channel of the in-progress transaction (for a timeout reply).
    pub fn current_cid(&self) -> u32 {
        self.cid
    }

    /// Drop an in-progress reassembly (e.g. on a receive timeout).
    pub fn abort(&mut self) {
        self.in_tx = false;
    }

    /// Wipe the buffered message — MSG/CBOR payloads carry PINs and key
    /// material, and the buffer otherwise holds them until the next message.
    pub fn scrub(&mut self) {
        use zeroize::Zeroize;
        self.msg[..self.bcnt].zeroize();
        self.bcnt = 0;
    }

    /// Consume one HID report. `f` is always a full 64-byte report; the caller
    /// drops short USB reads before calling.
    pub fn feed(&mut self, f: &[u8; HID_RPT_SIZE]) -> Outcome {
        let cid = u32::from_le_bytes([f[0], f[1], f[2], f[3]]);
        let type_byte = f[4];
        let is_init = type_byte & TYPE_INIT != 0;

        // Channel validation.
        if cid == 0 || (cid == CID_BROADCAST && !(is_init && type_byte == CTAPHID_INIT)) {
            return Outcome::Error(cid, ERR_INVALID_CHANNEL);
        }

        if is_init {
            let cmd = type_byte;
            let bcnt = ((f[5] as usize) << 8) | f[6] as usize;
            if bcnt > CTAP_MAX_MESSAGE {
                return Outcome::Error(cid, ERR_INVALID_LEN);
            }
            // Mid-transaction on a different channel → busy.
            if self.in_tx && self.cid != cid && cmd != CTAPHID_INIT {
                return Outcome::Error(cid, ERR_CHANNEL_BUSY);
            }
            // Same channel, mid-transaction: only CTAPHID_INIT may resync; any
            // other init-type frame where a continuation was expected is a
            // sequence error.
            if self.in_tx && self.cid == cid && cmd != CTAPHID_INIT {
                self.in_tx = false;
                return Outcome::Error(cid, ERR_INVALID_SEQ);
            }
            self.cid = cid;
            self.cmd = cmd;
            self.bcnt = bcnt;
            self.seq = 0;
            let n = bcnt.min(INIT_DATA);
            self.msg[..n].copy_from_slice(&f[7..7 + n]);
            self.cur = n;
            self.in_tx = bcnt > INIT_DATA;
        } else {
            // Continuation frame.
            if !self.in_tx {
                return Outcome::None; // stray CONT with no INIT
            }
            if cid != self.cid {
                return Outcome::Error(cid, ERR_CHANNEL_BUSY);
            }
            let seq = type_byte & !TYPE_INIT;
            if seq != self.seq {
                self.in_tx = false;
                return Outcome::Error(cid, ERR_INVALID_SEQ);
            }
            // `saturating_sub`: the in_tx state machine keeps cur < bcnt, but a
            // saturating subtraction makes the no-underflow self-evident across
            // refactors (a wrapped count here would index past the message).
            let n = CONT_DATA.min(self.bcnt.saturating_sub(self.cur));
            self.msg[self.cur..self.cur + n].copy_from_slice(&f[5..5 + n]);
            self.cur += n;
            self.seq = self.seq.wrapping_add(1);
        }

        if self.cur >= self.bcnt {
            self.in_tx = false;
            Outcome::Message(self.cid, self.cmd)
        } else {
            Outcome::None
        }
    }
}

/// Splits an outgoing message into 64-byte HID frames (one INIT then CONT
/// frames), the pure mirror of the RX path. Always yields at least the INIT
/// frame, even for an empty payload.
pub struct TxFrames<'a> {
    cid: [u8; 4],
    cmd: u8,
    data: &'a [u8],
    off: usize,
    seq: u8,
    started: bool,
}

impl<'a> TxFrames<'a> {
    pub fn new(cid: u32, cmd: u8, data: &'a [u8]) -> Self {
        Self {
            cid: cid.to_le_bytes(),
            cmd,
            data,
            off: 0,
            seq: 0,
            started: false,
        }
    }
}

impl Iterator for TxFrames<'_> {
    type Item = [u8; HID_RPT_SIZE];

    fn next(&mut self) -> Option<Self::Item> {
        let total = self.data.len();
        let mut frame = [0u8; HID_RPT_SIZE];
        frame[0..4].copy_from_slice(&self.cid);

        if !self.started {
            self.started = true;
            frame[4] = self.cmd; // already carries the TYPE_INIT bit
            frame[5] = (total >> 8) as u8;
            frame[6] = (total & 0xff) as u8;
            let n = total.min(INIT_DATA);
            frame[7..7 + n].copy_from_slice(&self.data[..n]);
            self.off = n;
            return Some(frame);
        }

        if self.off >= total {
            return None;
        }

        frame[4] = self.seq & !TYPE_INIT;
        let n = CONT_DATA.min(total - self.off);
        frame[5..5 + n].copy_from_slice(&self.data[self.off..self.off + n]);
        self.off += n;
        self.seq = self.seq.wrapping_add(1);
        Some(frame)
    }
}

/// CTAPHID transport bound to a 64-byte IN/OUT HID interface, dispatching MSG to `H`.
pub struct CtapHid<'d, D: Driver<'d>, H: MsgHandler> {
    reader: HidReader<'d, D, HID_RPT_SIZE>,
    writer: HidWriter<'d, D, HID_RPT_SIZE>,
    handler: H,
    asm: Reassembler,
    /// Response scratch the handler writes into (then framed onto the wire). A full
    /// CTAPHID message worth, so even a max-size response fits.
    scratch: [u8; CTAP_MAX_MESSAGE],
    /// Whether the worker is currently blocked waiting for a user-presence touch —
    /// selects the `KEEPALIVE` status byte (`UPNEEDED` vs `PROCESSING`). The firmware
    /// reads its worker flag; a `|| false` stand-in keeps the status at `PROCESSING`.
    up_pending: fn() -> bool,
}

impl<'d, D: Driver<'d>, H: MsgHandler> CtapHid<'d, D, H> {
    pub fn new(
        reader: HidReader<'d, D, HID_RPT_SIZE>,
        writer: HidWriter<'d, D, HID_RPT_SIZE>,
        handler: H,
        up_pending: fn() -> bool,
    ) -> Self {
        Self {
            reader,
            writer,
            handler,
            asm: Reassembler::new(),
            scratch: [0; CTAP_MAX_MESSAGE],
            up_pending,
        }
    }

    /// Read frames forever, reassemble messages, answer native commands. While a
    /// multi-frame message is mid-reassembly, the wait for the next frame is bound
    /// to [`RX_TIMEOUT_MS`]; on timeout the transaction is aborted with
    /// `CTAPHID_ERROR(MSG_TIMEOUT)`.
    pub async fn run(&mut self) -> ! {
        let mut frame = [0u8; HID_RPT_SIZE];
        loop {
            if self.asm.in_progress() {
                match select(
                    self.reader.read(&mut frame),
                    Timer::after_millis(RX_TIMEOUT_MS),
                )
                .await
                {
                    Either::First(Ok(n)) if n >= 5 => self.on_frame(&frame).await,
                    Either::First(_) => {}
                    Either::Second(_) => {
                        let cid = self.asm.current_cid();
                        self.asm.abort();
                        write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_MSG_TIMEOUT])
                            .await;
                    }
                }
            } else {
                match self.reader.read(&mut frame).await {
                    Ok(n) if n >= 5 => self.on_frame(&frame).await,
                    _ => {}
                }
            }
        }
    }

    async fn on_frame(&mut self, f: &[u8; HID_RPT_SIZE]) {
        match self.asm.feed(f) {
            Outcome::None => {}
            Outcome::Error(cid, code) => {
                write_message(&mut self.writer, cid, CTAPHID_ERROR, &[code]).await;
            }
            Outcome::Message(cid, cmd) => self.dispatch(cid, cmd).await,
        }
    }

    async fn dispatch(&mut self, cid: u32, cmd: u8) {
        match cmd {
            CTAPHID_INIT => {
                // A fresh session: drop any applet selected over this transport so
                // U2F (which has no SELECT) can't inherit a prior vendor selection.
                self.handler.reset_app_selection();
                // resp: nonce(8) | newcid(4) | iface(1) | major | minor | build | caps
                let nonce = self.asm.message();
                let mut resp = [0u8; 17];
                let k = nonce.len().min(8);
                resp[..k].copy_from_slice(&nonce[..k]);
                resp[8..12].copy_from_slice(&ALLOCATED_CID.to_le_bytes());
                resp[12] = CTAPHID_IF_VERSION;
                resp[13] = VERSION_MAJOR;
                resp[14] = VERSION_MINOR;
                resp[15] = VERSION_BUILD;
                resp[16] = CAPFLAG_WINK | CAPFLAG_CBOR;
                write_message(&mut self.writer, cid, CTAPHID_INIT, &resp).await;
            }
            CTAPHID_PING | CTAPHID_SYNC => {
                write_message(&mut self.writer, cid, cmd, self.asm.message()).await;
            }
            CTAPHID_WINK => {
                write_message(&mut self.writer, cid, CTAPHID_WINK, &[]).await;
            }
            CTAPHID_LOCK => {
                // Accept and ignore the lock for now.
                write_message(&mut self.writer, cid, CTAPHID_LOCK, &[]).await;
            }
            CTAPHID_VERSION => {
                write_message(
                    &mut self.writer,
                    cid,
                    CTAPHID_VERSION,
                    &[VERSION_MAJOR, VERSION_MINOR, VERSION_BUILD, 0],
                )
                .await;
            }
            CTAPHID_UUID => {
                write_message(&mut self.writer, cid, CTAPHID_UUID, &DEVICE_UUID).await;
            }
            CTAPHID_CANCEL => {
                write_message(
                    &mut self.writer,
                    cid,
                    CTAPHID_ERROR,
                    &[ERR_KEEPALIVE_CANCEL],
                )
                .await;
            }
            CTAPHID_MSG => {
                self.run_with_keepalive(cid, false).await;
            }
            CTAPHID_CBOR => {
                // A CBOR message must carry at least the command byte.
                if self.asm.message().is_empty() {
                    write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_INVALID_LEN]).await;
                } else {
                    self.run_with_keepalive(cid, true).await;
                }
            }
            cmd if cmd >= CTAPHID_VENDOR_FIRST => {
                self.run_vendor(cid, cmd).await;
            }
            _ => {
                write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_INVALID_CMD]).await;
            }
        }
    }

    /// Hand the reassembled message to the (async) handler — which forwards it to
    /// the compute worker on a lower-priority executor — streaming a
    /// `CTAPHID_KEEPALIVE` every [`KEEPALIVE_MS`] while it runs, then frame the
    /// response. `is_cbor` selects CBOR vs MSG (U2F). The handler future borrows
    /// `handler`/`asm`/`scratch`; the keepalive uses `writer` — disjoint fields, so
    /// `select` drives both concurrently and the keepalive keeps flowing while the
    /// worker blocks on slow crypto / flash GC.
    async fn run_with_keepalive(&mut self, cid: u32, is_cbor: bool) {
        let Self {
            handler,
            writer,
            asm,
            scratch,
            up_pending,
            ..
        } = self;
        let up_pending = *up_pending;
        let data = asm.message();
        let n = {
            let mut fut = core::pin::pin!(async {
                if is_cbor {
                    handler.handle_cbor(data, scratch).await
                } else {
                    handler.handle_msg(data, scratch).await
                }
            });
            loop {
                match select(fut.as_mut(), Timer::after_millis(KEEPALIVE_MS)).await {
                    Either::First(n) => break n,
                    Either::Second(_) => {
                        let status = if up_pending() {
                            STATUS_UPNEEDED
                        } else {
                            STATUS_PROCESSING
                        };
                        write_message(writer, cid, CTAPHID_KEEPALIVE, &[status]).await;
                    }
                }
            }
        };
        let cmd = if is_cbor { CTAPHID_CBOR } else { CTAPHID_MSG };
        write_message(writer, cid, cmd, &scratch[..n]).await;
        // Request and response both carried secrets (PINs, tokens, key blobs).
        use zeroize::Zeroize;
        scratch[..n].zeroize();
        asm.scrub();
    }

    /// Serve a vendor CTAPHID command through the handler (the worker, which owns
    /// flash). Mirrors [`Self::run_with_keepalive`]'s field split; vendor commands
    /// are quick flash reads, so no keepalive is streamed. The handler sees the
    /// logical command number (`TYPE_INIT` stripped); on success we reply with the
    /// original command byte, otherwise `CTAPHID_ERROR(ERR_INVALID_CMD)`.
    async fn run_vendor(&mut self, cid: u32, cmd: u8) {
        let Self {
            handler,
            writer,
            asm,
            scratch,
            ..
        } = self;
        let data = asm.message();
        match handler.handle_vendor(cmd & !TYPE_INIT, data, scratch).await {
            Some(n) => write_message(writer, cid, cmd, &scratch[..n]).await,
            None => write_message(writer, cid, CTAPHID_ERROR, &[ERR_INVALID_CMD]).await,
        }
    }
}

/// One outgoing 64-byte HID report. The future completes only once the host
/// drains the report from the IN endpoint — exactly where the FIDO interface can
/// wedge (see [`write_frames`]). Splitting it behind a trait lets a host test
/// substitute a sink that never completes, proving the timeout abandons a stalled
/// write instead of blocking the transport task forever.
#[allow(async_fn_in_trait)] // crate-internal, single-threaded executor — no Send bound needed
trait FrameSink {
    async fn write_frame(&mut self, frame: &[u8; HID_RPT_SIZE]);
}

impl<'d, D: Driver<'d>> FrameSink for HidWriter<'d, D, HID_RPT_SIZE> {
    async fn write_frame(&mut self, frame: &[u8; HID_RPT_SIZE]) {
        // A write error (endpoint disabled / reset) ends the response the same as
        // a timeout: there is nothing more to send for this transaction.
        let _ = self.write(frame).await;
    }
}

/// Frame `data` into one INIT frame plus CONT frames and write them out, bounding
/// each frame write by a fresh `timeout` future.
///
/// If the host abandons the transaction mid-response (a cancelled/timed-out
/// client, or a wedged host HID handle), an unbounded `write().await` would block
/// this transport task forever — it would stop draining the OUT endpoint, NAKing
/// every further host write and wedging the whole FIDO interface until a replug.
/// On timeout we abandon the rest of the response and return to reading.
///
/// Generic over the sink and a timeout-future factory so the abandon-on-stall
/// path is exercised on the host without a USB driver or an embassy time driver
/// (see the `write_frames_*` tests).
async fn write_frames<S, T, F>(sink: &mut S, cid: u32, cmd: u8, data: &[u8], mut timeout: F)
where
    S: FrameSink,
    F: FnMut() -> T,
    T: Future<Output = ()>,
{
    for frame in TxFrames::new(cid, cmd, data) {
        match select(sink.write_frame(&frame), timeout()).await {
            Either::First(_) => {}
            Either::Second(_) => return, // host stopped draining IN — abandon response
        }
    }
}

/// [`write_frames`] with the production timeout: bound every frame to
/// [`TX_TIMEOUT_MS`] of host-drain time.
async fn write_message<'d, D: Driver<'d>>(
    writer: &mut HidWriter<'d, D, HID_RPT_SIZE>,
    cid: u32,
    cmd: u8,
    data: &[u8],
) {
    write_frames(writer, cid, cmd, data, || {
        Timer::after_millis(TX_TIMEOUT_MS)
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build an INIT report: cid | cmd | bcnt_hi | bcnt_lo | data...
    fn init_frame(cid: u32, cmd: u8, bcnt: u16, data: &[u8]) -> [u8; HID_RPT_SIZE] {
        let mut f = [0u8; HID_RPT_SIZE];
        f[0..4].copy_from_slice(&cid.to_le_bytes());
        f[4] = cmd;
        f[5] = (bcnt >> 8) as u8;
        f[6] = (bcnt & 0xff) as u8;
        let n = data.len().min(INIT_DATA);
        f[7..7 + n].copy_from_slice(&data[..n]);
        f
    }

    // Build a CONT report: cid | seq | data...
    fn cont_frame(cid: u32, seq: u8, data: &[u8]) -> [u8; HID_RPT_SIZE] {
        let mut f = [0u8; HID_RPT_SIZE];
        f[0..4].copy_from_slice(&cid.to_le_bytes());
        f[4] = seq & !TYPE_INIT;
        let n = data.len().min(CONT_DATA);
        f[5..5 + n].copy_from_slice(&data[..n]);
        f
    }

    #[test]
    fn single_frame_init() {
        let mut asm = Reassembler::new();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let out = asm.feed(&init_frame(CID_BROADCAST, CTAPHID_INIT, 8, &nonce));
        assert_eq!(out, Outcome::Message(CID_BROADCAST, CTAPHID_INIT));
        assert_eq!(asm.message(), &nonce);
    }

    #[test]
    fn single_frame_ping() {
        let mut asm = Reassembler::new();
        let payload = [0xAA; 20];
        let out = asm.feed(&init_frame(0x0100_0000, CTAPHID_PING, 20, &payload));
        assert_eq!(out, Outcome::Message(0x0100_0000, CTAPHID_PING));
        assert_eq!(asm.message(), &payload);
    }

    #[test]
    fn multi_frame_reassembly() {
        let mut asm = Reassembler::new();
        let cid = 0x0100_0000;
        // 57 (INIT) + 59 (CONT0) + 10 (CONT1) = 126 bytes.
        let mut payload = [0u8; 126];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            asm.feed(&init_frame(cid, CTAPHID_PING, 126, &payload[..INIT_DATA])),
            Outcome::None
        );
        assert_eq!(
            asm.feed(&cont_frame(
                cid,
                0,
                &payload[INIT_DATA..INIT_DATA + CONT_DATA]
            )),
            Outcome::None
        );
        assert_eq!(
            asm.feed(&cont_frame(cid, 1, &payload[INIT_DATA + CONT_DATA..])),
            Outcome::Message(cid, CTAPHID_PING)
        );
        assert_eq!(asm.message(), &payload);
    }

    #[test]
    fn zero_length_message() {
        let mut asm = Reassembler::new();
        let out = asm.feed(&init_frame(0x0100_0000, CTAPHID_WINK, 0, &[]));
        assert_eq!(out, Outcome::Message(0x0100_0000, CTAPHID_WINK));
        assert_eq!(asm.message(), &[] as &[u8]);
    }

    #[test]
    fn scrub_wipes_message_and_next_message_still_works() {
        let mut asm = Reassembler::new();
        let cid = 0x0100_0000;
        let secret = [0x5A; 32];
        asm.feed(&init_frame(cid, CTAPHID_CBOR, 32, &secret));
        assert_eq!(asm.message(), &secret);
        asm.scrub();
        assert!(asm.message().is_empty());
        // The buffer behind the old message is zeroed, not just hidden.
        assert!(asm.msg[..32].iter().all(|&b| b == 0));
        // A fresh message reassembles normally after a scrub.
        let next = [0xC3; 16];
        let out = asm.feed(&init_frame(cid, CTAPHID_PING, 16, &next));
        assert_eq!(out, Outcome::Message(cid, CTAPHID_PING));
        assert_eq!(asm.message(), &next);
    }

    #[test]
    fn invalid_channel_zero() {
        let mut asm = Reassembler::new();
        let out = asm.feed(&init_frame(0, CTAPHID_PING, 0, &[]));
        assert_eq!(out, Outcome::Error(0, ERR_INVALID_CHANNEL));
    }

    #[test]
    fn broadcast_non_init_rejected() {
        let mut asm = Reassembler::new();
        let out = asm.feed(&init_frame(CID_BROADCAST, CTAPHID_PING, 0, &[]));
        assert_eq!(out, Outcome::Error(CID_BROADCAST, ERR_INVALID_CHANNEL));
    }

    #[test]
    fn bcnt_too_large() {
        let mut asm = Reassembler::new();
        // Header claims more than CTAP_MAX_MESSAGE (7609 < 0xFFFF).
        let out = asm.feed(&init_frame(0x0100_0000, CTAPHID_PING, 0xFFFF, &[]));
        assert_eq!(out, Outcome::Error(0x0100_0000, ERR_INVALID_LEN));
    }

    #[test]
    fn stray_cont_ignored() {
        let mut asm = Reassembler::new();
        let out = asm.feed(&cont_frame(0x0100_0000, 0, &[1, 2, 3]));
        assert_eq!(out, Outcome::None);
    }

    #[test]
    fn wrong_seq_aborts() {
        let mut asm = Reassembler::new();
        let cid = 0x0100_0000;
        let payload = [7u8; 100];
        assert_eq!(
            asm.feed(&init_frame(cid, CTAPHID_PING, 100, &payload[..INIT_DATA])),
            Outcome::None
        );
        // Expected seq is 0; send 1.
        assert_eq!(
            asm.feed(&cont_frame(cid, 1, &payload[INIT_DATA..])),
            Outcome::Error(cid, ERR_INVALID_SEQ)
        );
        // Transaction aborted: a further CONT is now stray.
        assert_eq!(
            asm.feed(&cont_frame(cid, 1, &payload[INIT_DATA..])),
            Outcome::None
        );
    }

    #[test]
    fn init_frame_mid_transaction_is_invalid_seq() {
        let mut asm = Reassembler::new();
        let cid = 0x0100_0000;
        let payload = [0xABu8; INIT_DATA];
        // Start a 200-byte PING (needs continuations).
        assert_eq!(
            asm.feed(&init_frame(cid, CTAPHID_PING, 200, &payload)),
            Outcome::None
        );
        assert!(asm.in_progress());
        // A non-INIT init-type frame on the same channel where a CONT was expected
        // → INVALID_SEQ, and the transaction is aborted.
        assert_eq!(
            asm.feed(&init_frame(cid, CTAPHID_PING, 200, &payload)),
            Outcome::Error(cid, ERR_INVALID_SEQ)
        );
        assert!(!asm.in_progress());
        // CTAPHID_INIT mid-transaction resyncs instead of erroring.
        assert_eq!(
            asm.feed(&init_frame(cid, CTAPHID_PING, 200, &payload)),
            Outcome::None
        );
        assert_eq!(
            asm.feed(&init_frame(cid, CTAPHID_INIT, 8, &[1u8; 8])),
            Outcome::Message(cid, CTAPHID_INIT)
        );
    }

    #[test]
    fn cont_wrong_cid_busy() {
        let mut asm = Reassembler::new();
        let payload = [7u8; 100];
        assert_eq!(
            asm.feed(&init_frame(
                0x0100_0000,
                CTAPHID_PING,
                100,
                &payload[..INIT_DATA]
            )),
            Outcome::None
        );
        let out = asm.feed(&cont_frame(0x0200_0000, 0, &payload[INIT_DATA..]));
        assert_eq!(out, Outcome::Error(0x0200_0000, ERR_CHANNEL_BUSY));
    }

    #[test]
    fn init_other_channel_busy() {
        let mut asm = Reassembler::new();
        let payload = [7u8; 100];
        // Start a multi-frame transaction on channel A.
        assert_eq!(
            asm.feed(&init_frame(
                0x0100_0000,
                CTAPHID_PING,
                100,
                &payload[..INIT_DATA]
            )),
            Outcome::None
        );
        // A non-INIT command on channel B while busy → busy.
        assert_eq!(
            asm.feed(&init_frame(0x0200_0000, CTAPHID_PING, 0, &[])),
            Outcome::Error(0x0200_0000, ERR_CHANNEL_BUSY)
        );
        // But INIT itself on channel B is allowed (resyncs).
        let nonce = [9u8; 8];
        assert_eq!(
            asm.feed(&init_frame(0x0200_0000, CTAPHID_INIT, 8, &nonce)),
            Outcome::Message(0x0200_0000, CTAPHID_INIT)
        );
    }

    #[test]
    fn max_length_message() {
        let mut asm = Reassembler::new();
        let cid = 0x0100_0000;
        let payload = [0x5Au8; CTAP_MAX_MESSAGE];
        let mut out = asm.feed(&init_frame(
            cid,
            CTAPHID_PING,
            CTAP_MAX_MESSAGE as u16,
            &payload[..INIT_DATA],
        ));
        assert_eq!(out, Outcome::None);
        let mut off = INIT_DATA;
        let mut seq = 0u8;
        while off < CTAP_MAX_MESSAGE {
            let end = (off + CONT_DATA).min(CTAP_MAX_MESSAGE);
            out = asm.feed(&cont_frame(cid, seq, &payload[off..end]));
            off = end;
            seq = seq.wrapping_add(1);
        }
        assert_eq!(out, Outcome::Message(cid, CTAPHID_PING));
        assert_eq!(asm.message().len(), CTAP_MAX_MESSAGE);
        assert!(asm.message().iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn tx_single_frame() {
        let data = [0xAB; 10];
        let frames: Vec<_> = TxFrames::new(0x0100_0000, CTAPHID_PING, &data).collect();
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        assert_eq!(u32::from_le_bytes([f[0], f[1], f[2], f[3]]), 0x0100_0000);
        assert_eq!(f[4], CTAPHID_PING);
        assert_eq!(((f[5] as usize) << 8) | f[6] as usize, 10);
        assert_eq!(&f[7..17], &data);
    }

    #[test]
    fn tx_empty_still_emits_init() {
        let frames: Vec<_> = TxFrames::new(0x0100_0000, CTAPHID_WINK, &[]).collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][4], CTAPHID_WINK);
        assert_eq!(frames[0][5], 0);
        assert_eq!(frames[0][6], 0);
    }

    #[test]
    fn tx_multi_frame_seq_increments() {
        let data = [0xCD; 200];
        let frames: Vec<_> = TxFrames::new(0x0100_0000, CTAPHID_MSG, &data).collect();
        // 200 = 57 (INIT) + 59 + 59 + 25 → 4 frames.
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0][4], CTAPHID_MSG);
        assert_eq!(frames[1][4], 0); // seq 0
        assert_eq!(frames[2][4], 1); // seq 1
        assert_eq!(frames[3][4], 2); // seq 2
    }

    // Drive every payload length through TX framing then RX reassembly.
    #[test]
    fn roundtrip() {
        for &len in &[0usize, 1, 56, 57, 58, 116, 200, 1000, CTAP_MAX_MESSAGE] {
            let cid = 0x0100_0000;
            let cmd = CTAPHID_PING;
            let mut data = [0u8; CTAP_MAX_MESSAGE];
            for (i, b) in data[..len].iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            let mut asm = Reassembler::new();
            let mut last = Outcome::None;
            for frame in TxFrames::new(cid, cmd, &data[..len]) {
                last = asm.feed(&frame);
            }
            assert_eq!(last, Outcome::Message(cid, cmd), "len={len}");
            assert_eq!(asm.message(), &data[..len], "len={len}");
        }
    }

    // ---- TX abandon-on-stall: regression guard for the USB-wedge fix (63cde79) ----

    // Bounded manual poll with a no-op waker: returns None if `fut` is still
    // pending after `max_polls`, so a TX path that fails to abandon a stalled
    // frame surfaces as a failed assertion instead of hanging the test runner.
    fn poll_bounded<F: core::future::Future>(fut: F, max_polls: usize) -> Option<F::Output> {
        use core::task::{Context, Poll};
        let mut cx = Context::from_waker(core::task::Waker::noop());
        let mut fut = core::pin::pin!(fut);
        for _ in 0..max_polls {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return Some(v);
            }
        }
        None
    }

    // A sink whose every frame write never completes — models the host that has
    // stopped draining the IN endpoint (the wedge condition).
    struct StallSink {
        attempts: usize,
    }
    impl FrameSink for StallSink {
        async fn write_frame(&mut self, _frame: &[u8; HID_RPT_SIZE]) {
            self.attempts += 1;
            core::future::pending::<()>().await
        }
    }

    // A sink that accepts every frame immediately — models a host that keeps draining.
    struct CountingSink {
        written: usize,
    }
    impl FrameSink for CountingSink {
        async fn write_frame(&mut self, _frame: &[u8; HID_RPT_SIZE]) {
            self.written += 1;
        }
    }

    #[test]
    fn write_frames_abandons_when_host_stalls() {
        let mut sink = StallSink { attempts: 0 };
        let data = [0xAB; 200]; // multi-frame: a non-abandoning path would attempt >1 frame
        // Timeout is always ready, so the stalled write must lose the race and the
        // response is abandoned after the very first undeliverable frame.
        let done = poll_bounded(
            write_frames(&mut sink, 0x0100_0000, CTAPHID_PING, &data, || {
                core::future::ready(())
            }),
            10_000,
        );
        assert!(
            done.is_some(),
            "write_frames hung on a stalled host — the IN-endpoint timeout no longer abandons the write (USB-wedge regression)"
        );
        assert_eq!(
            sink.attempts, 1,
            "must abandon after the first stalled frame, not keep retrying"
        );
    }

    #[test]
    fn write_frames_writes_every_frame_when_host_drains() {
        let mut sink = CountingSink { written: 0 };
        let data = [0xCD; 200]; // 57 + 59 + 59 + 25 → 4 frames
        // Timeout never fires, so each write wins its race and all frames go out.
        let done = poll_bounded(
            write_frames(&mut sink, 0x0100_0000, CTAPHID_MSG, &data, || {
                core::future::pending::<()>()
            }),
            10_000,
        );
        assert!(done.is_some(), "write_frames stalled with a draining host");
        assert_eq!(
            sink.written, 4,
            "every frame written when the host keeps draining"
        );
    }
}
