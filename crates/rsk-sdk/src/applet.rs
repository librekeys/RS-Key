// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `Applet` trait plus AID-based SELECT and APDU dispatch.

use zeroize::Zeroize;

use crate::apdu::Apdu;
use crate::sw::Sw;

/// A response buffer an applet writes its RAPDU body into. The status word is
/// appended by the dispatcher.
pub struct ResBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> ResBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        ResBuf { buf, len: 0 }
    }
    pub fn clear(&mut self) {
        self.len = 0;
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
    /// Append one byte; returns false if the buffer is full.
    pub fn push(&mut self, b: u8) -> bool {
        if self.len < self.buf.len() {
            self.buf[self.len] = b;
            self.len += 1;
            true
        } else {
            false
        }
    }
    /// Append a slice; returns false (and writes nothing) if it would overflow.
    pub fn extend(&mut self, data: &[u8]) -> bool {
        if self.len + data.len() <= self.buf.len() {
            self.buf[self.len..self.len + data.len()].copy_from_slice(data);
            self.len += data.len();
            true
        } else {
            false
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    /// Shorten the body to `n` bytes (no-op when already `≤ n`).
    pub fn truncate(&mut self, n: usize) {
        if n < self.len {
            self.len = n;
        }
    }
}

/// A selectable smartcard applet.
///
/// `C` is a shared context (the file system in `firmware`) the dispatcher threads
/// into every call, so applets hold no `static mut` device state.
pub trait Applet<C> {
    /// The application identifier, without a length prefix. SELECT matches when
    /// this is a prefix of the requested AID.
    fn aid(&self) -> &'static [u8];
    /// Called on SELECT. `reselect` is true when this applet was already current.
    /// `res` receives the SELECT response body (e.g. an OpenPGP FCI); leave it
    /// empty for applets that return no data.
    fn select(&mut self, reselect: bool, ctx: &mut C, res: &mut ResBuf) -> Sw;
    /// Handle a non-SELECT command APDU.
    fn process(&mut self, apdu: &Apdu, ctx: &mut C, res: &mut ResBuf) -> Sw;
    /// Called when another applet is selected.
    fn deselect(&mut self, _ctx: &mut C) {}
    /// Whether the dispatcher may apply ISO 7816-4 outgoing response chaining
    /// (a `61xx` status + GET RESPONSE `0xC0` follow-ups) when a response body
    /// exceeds the command's short `Le`. Default off — only applets whose host
    /// stacks speak standard GET RESPONSE opt in (OpenPGP for `gpg`/`scdaemon`,
    /// PIV for OpenSC/`ykman`). OATH has its own SEND REMAINING (`0xA5`) scheme
    /// and stays off; the vendor/rescue tools use extended `Le` so never need it.
    fn response_chaining(&self) -> bool {
        false
    }
}

const CHAIN_BUF_SIZE: usize = 2038;
/// Holds the unsent tail of a response while the host fetches it with GET
/// RESPONSE. Sized to the largest response buffer a caller passes (the CCID
/// handler's 2046-byte body cap).
const RESP_CHAIN_CAP: usize = 2048;

/// Routes APDUs to applets: SELECT-by-AID, command chaining (CLA bit 0x10),
/// outgoing response chaining (`61xx` / GET RESPONSE), and dispatch to the
/// current applet.
pub struct Dispatcher {
    current: Option<usize>,
    chaining: bool,
    chain: [u8; CHAIN_BUF_SIZE],
    chain_len: usize,
    /// Outgoing response chaining: when an opted-in applet's body exceeds the
    /// command's short `Le`, the first `Le` bytes ship with `61xx` and this
    /// holds the remainder for the GET RESPONSE (`0xC0`) follow-ups.
    pending: [u8; RESP_CHAIN_CAP],
    pending_len: usize,
    pending_off: usize,
    pending_sw: Sw,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispatcher {
    pub const fn new() -> Self {
        Dispatcher {
            current: None,
            chaining: false,
            chain: [0u8; CHAIN_BUF_SIZE],
            chain_len: 0,
            pending: [0u8; RESP_CHAIN_CAP],
            pending_len: 0,
            pending_off: 0,
            pending_sw: Sw::OK,
        }
    }

    /// Index of the currently selected applet, if any.
    pub fn current(&self) -> Option<usize> {
        self.current
    }

    /// Drop any selected applet. Used when a fresh logical session begins (a
    /// CTAPHID_INIT): U2F/CTAP1 has no SELECT of its own and must not inherit a
    /// vendor-AID selection left over from an earlier session on this transport.
    pub fn clear_selection(&mut self) {
        self.current = None;
    }

    /// Process one raw command APDU against `applets` (in registration order),
    /// threading the shared `ctx` into the dispatched applet, writing the
    /// response body into `res` and returning the status word.
    pub fn process<C>(
        &mut self,
        raw: &[u8],
        applets: &mut [&mut dyn Applet<C>],
        ctx: &mut C,
        res: &mut ResBuf,
    ) -> Sw {
        res.clear();
        let apdu = match Apdu::parse(raw) {
            Ok(a) => a,
            Err(_) => return Sw::WRONG_LENGTH,
        };

        // GET RESPONSE (0xC0): hand back the next slice of a chained response
        // before touching the applets — it is a transport command, not theirs.
        if apdu.ins == 0xC0 && self.pending_off < self.pending_len {
            return self.serve_pending(apdu.ne, res);
        }
        // Any other command abandons a partially-read chained response.
        self.clear_pending();

        // Command chaining: accumulate and acknowledge.
        if apdu.is_chaining() {
            if !self.chaining {
                self.chain_len = 0;
            }
            if self.chain_len + apdu.nc >= self.chain.len() {
                // The accumulated segments may already hold key material.
                self.chain[..self.chain_len].zeroize();
                self.chain_len = 0;
                self.chaining = false;
                return Sw::CLA_NOT_SUPPORTED;
            }
            self.chain[self.chain_len..self.chain_len + apdu.nc].copy_from_slice(apdu.data);
            self.chain_len += apdu.nc;
            self.chaining = true;
            return Sw::OK;
        }
        // A non-chained APDU after chaining segments is the final one: append its
        // data and dispatch the reassembled command (needed by OpenPGP RSA IMPORT,
        // whose extended header list exceeds 255 bytes). Chained commands always
        // target the current applet — SELECT is never chained.
        if self.chaining {
            if self.chain_len + apdu.nc > self.chain.len() {
                self.chain[..self.chain_len].zeroize();
                self.chain_len = 0;
                self.chaining = false;
                return Sw::WRONG_LENGTH;
            }
            self.chain[self.chain_len..self.chain_len + apdu.nc].copy_from_slice(apdu.data);
            let total = self.chain_len + apdu.nc;
            self.chaining = false;
            self.chain_len = 0;
            let combined = Apdu {
                cla: apdu.cla,
                ins: apdu.ins,
                p1: apdu.p1,
                p2: apdu.p2,
                nc: total,
                ne: apdu.ne,
                data: &self.chain[..total],
            };
            let chain_ok = self
                .current
                .map(|i| applets[i].response_chaining())
                .unwrap_or(false);
            let sw = match self.current {
                Some(i) => applets[i].process(&combined, ctx, res),
                None => Sw::FILE_NOT_FOUND,
            };
            // A chained command can carry private-key IMPORT data.
            self.chain[..total].zeroize();
            return self.maybe_chain(sw, apdu.ne, chain_ok, res);
        }

        // SELECT by AID.
        if apdu.ins == 0xA4 && apdu.p1 == 0x04 && (apdu.p2 == 0x00 || apdu.p2 == 0x04) {
            let found = applets.iter().position(|app| {
                let aid = app.aid();
                apdu.data.len() >= aid.len() && &apdu.data[..aid.len()] == aid
            });
            return match found {
                Some(i) => {
                    let reselect = self.current == Some(i);
                    if let Some(c) = self.current
                        && c != i
                    {
                        applets[c].deselect(ctx);
                    }
                    self.current = Some(i);
                    let chain_ok = applets[i].response_chaining();
                    let sw = applets[i].select(reselect, ctx, res);
                    self.maybe_chain(sw, apdu.ne, chain_ok, res)
                }
                None => Sw::FILE_NOT_FOUND,
            };
        }

        // Dispatch to the selected applet.
        match self.current {
            Some(i) => {
                let chain_ok = applets[i].response_chaining();
                let sw = applets[i].process(&apdu, ctx, res);
                self.maybe_chain(sw, apdu.ne, chain_ok, res)
            }
            None => Sw::FILE_NOT_FOUND,
        }
    }

    /// Drop any held GET RESPONSE remainder, scrubbing it (it can be PSO output).
    fn clear_pending(&mut self) {
        if self.pending_len > 0 {
            self.pending[..self.pending_len].zeroize();
        }
        self.pending_len = 0;
        self.pending_off = 0;
    }

    /// Serve the next chunk of a chained response to a GET RESPONSE (`0xC0`).
    /// Returns `61xx` while bytes remain, then the original status word.
    fn serve_pending(&mut self, ne: usize, res: &mut ResBuf) -> Sw {
        let want = if ne == 0 { 256 } else { ne };
        let remaining = self.pending_len - self.pending_off;
        let take = want.min(remaining);
        res.extend(&self.pending[self.pending_off..self.pending_off + take]);
        self.pending_off += take;
        let left = self.pending_len - self.pending_off;
        if left > 0 {
            Sw::new(0x61, if left > 0xFF { 0 } else { left as u8 })
        } else {
            let sw = self.pending_sw;
            self.clear_pending();
            sw
        }
    }

    /// If an opted-in applet's success body overruns the command's short `Le`,
    /// hold the tail for GET RESPONSE and ship the first `Le` bytes with `61xx`.
    /// Otherwise the response (and status) pass through unchanged — so extended
    /// `Le` consumers (ykman, our APDU tests) and non-chaining applets are
    /// byte-for-byte unaffected.
    fn maybe_chain(&mut self, sw: Sw, ne: usize, chaining_ok: bool, res: &mut ResBuf) -> Sw {
        if !chaining_ok || ne == 0 || !sw.is_ok() || res.len() <= ne {
            return sw;
        }
        let tail_len = res.len() - ne;
        if tail_len > self.pending.len() {
            // Cannot buffer the remainder; leave the response intact (legacy).
            return sw;
        }
        self.pending[..tail_len].copy_from_slice(&res.as_slice()[ne..]);
        self.pending_len = tail_len;
        self.pending_off = 0;
        self.pending_sw = sw;
        res.truncate(ne);
        Sw::new(0x61, if tail_len > 0xFF { 0 } else { tail_len as u8 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo {
        selected: bool,
    }
    // Context-free applet: the unit type stands in for "no file system".
    impl Applet<()> for Echo {
        fn aid(&self) -> &'static [u8] {
            &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
        }
        fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
            self.selected = true;
            Sw::OK
        }
        fn process(&mut self, apdu: &Apdu, _ctx: &mut (), res: &mut ResBuf) -> Sw {
            if apdu.ins == 0x10 {
                res.extend(apdu.data);
                Sw::OK
            } else {
                Sw::INS_NOT_SUPPORTED
            }
        }
    }

    #[test]
    fn select_then_dispatch() {
        let mut echo = Echo { selected: false };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 64];
        let mut res = ResBuf::new(&mut out);

        // Unknown command before any selection.
        assert_eq!(
            disp.process(&[0x00, 0x10, 0, 0], &mut applets, &mut (), &mut res),
            Sw::FILE_NOT_FOUND
        );

        // SELECT by AID.
        let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
        sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
        assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);
        assert_eq!(disp.current(), Some(0));

        // Now an echo command.
        let cmd = [0x00, 0x10, 0x00, 0x00, 0x03, 0xDE, 0xAD, 0xBE];
        assert_eq!(disp.process(&cmd, &mut applets, &mut (), &mut res), Sw::OK);
        assert_eq!(res.as_slice(), &[0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn clear_selection_drops_the_applet() {
        // Models the CTAPHID_INIT fix: after a SELECT sticks, clear_selection()
        // must drop it so the next command is NOT routed to the old applet (the
        // U2F-hijack bug — a sticky vendor SELECT swallowed U2F traffic).
        let mut echo = Echo { selected: false };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 64];
        let mut res = ResBuf::new(&mut out);

        let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
        sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
        assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);
        assert_eq!(disp.current(), Some(0));

        disp.clear_selection();
        assert_eq!(disp.current(), None);

        // The same command that worked while selected now finds nothing selected.
        let cmd = [0x00, 0x10, 0x00, 0x00, 0x03, 0xDE, 0xAD, 0xBE];
        assert_eq!(
            disp.process(&cmd, &mut applets, &mut (), &mut res),
            Sw::FILE_NOT_FOUND
        );
    }

    #[test]
    fn command_chaining_reassembles() {
        let mut echo = Echo { selected: false };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 64];
        let mut res = ResBuf::new(&mut out);

        let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
        sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
        assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

        // Two chaining segments (CLA bit 0x10) are acknowledged with no body…
        assert_eq!(
            disp.process(
                &[0x10, 0x10, 0, 0, 0x02, 0xAA, 0xBB],
                &mut applets,
                &mut (),
                &mut res
            ),
            Sw::OK
        );
        assert!(res.is_empty());
        assert_eq!(
            disp.process(
                &[0x10, 0x10, 0, 0, 0x02, 0xCC, 0xDD],
                &mut applets,
                &mut (),
                &mut res
            ),
            Sw::OK
        );
        // …then the final non-chained segment dispatches the reassembled command.
        assert_eq!(
            disp.process(
                &[0x00, 0x10, 0, 0, 0x01, 0xEE],
                &mut applets,
                &mut (),
                &mut res
            ),
            Sw::OK
        );
        assert_eq!(res.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn select_unknown_aid() {
        let mut echo = Echo { selected: false };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 16];
        let mut res = ResBuf::new(&mut out);
        let sel = [0x00, 0xA4, 0x04, 0x00, 0x02, 0x12, 0x34];
        assert_eq!(
            disp.process(&sel, &mut applets, &mut (), &mut res),
            Sw::FILE_NOT_FOUND
        );
    }

    // Returns `body_len` bytes (value = index & 0xFF) for GET DATA (INS 0xCA);
    // `chain` toggles opt-in to dispatcher response chaining.
    struct Chunky {
        body_len: usize,
        chain: bool,
    }
    impl Applet<()> for Chunky {
        fn aid(&self) -> &'static [u8] {
            &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x02]
        }
        fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
            Sw::OK
        }
        fn response_chaining(&self) -> bool {
            self.chain
        }
        fn process(&mut self, apdu: &Apdu, _ctx: &mut (), res: &mut ResBuf) -> Sw {
            if apdu.ins == 0xCA {
                for i in 0..self.body_len {
                    res.push((i & 0xFF) as u8);
                }
                Sw::OK
            } else {
                Sw::INS_NOT_SUPPORTED
            }
        }
    }

    fn select_chunky(disp: &mut Dispatcher, applets: &mut [&mut dyn Applet<()>], res: &mut ResBuf) {
        let sel = [
            0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x02,
        ];
        assert_eq!(disp.process(&sel, applets, &mut (), res), Sw::OK);
    }

    #[test]
    fn short_le_response_is_chained_with_get_response() {
        let mut c = Chunky {
            body_len: 269,
            chain: true,
        };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 512];
        let mut res = ResBuf::new(&mut out);
        select_chunky(&mut disp, &mut applets, &mut res);

        // GET DATA, short Le=256 → first 256 bytes + 61 0D (13 more available).
        let sw = disp.process(
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res,
        );
        assert_eq!(sw, Sw::new(0x61, 0x0D));
        assert_eq!(res.len(), 256);
        let mut got = res.as_slice().to_vec();

        // GET RESPONSE (Le=256) → remaining 13 bytes + 9000.
        let sw = disp.process(
            &[0x00, 0xC0, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res,
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(res.len(), 13);
        got.extend_from_slice(res.as_slice());

        let want: Vec<u8> = (0..269).map(|i| (i & 0xFF) as u8).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn get_response_honours_a_smaller_le() {
        let mut c = Chunky {
            body_len: 300,
            chain: true,
        };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 512];
        let mut res = ResBuf::new(&mut out);
        select_chunky(&mut disp, &mut applets, &mut res);

        // 300 > 256 → 256 + 61 2C (44 left).
        let sw = disp.process(
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res,
        );
        assert_eq!(sw, Sw::new(0x61, 44));
        // Ask for only 20 of the 44 → 20 bytes + 61 18 (24 left).
        let sw = disp.process(
            &[0x00, 0xC0, 0x00, 0x00, 0x14],
            &mut applets,
            &mut (),
            &mut res,
        );
        assert_eq!(sw, Sw::new(0x61, 24));
        assert_eq!(res.len(), 20);
        // Drain the rest.
        let sw = disp.process(
            &[0x00, 0xC0, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res,
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(res.len(), 24);
    }

    #[test]
    fn extended_le_response_is_not_chained() {
        let mut c = Chunky {
            body_len: 269,
            chain: true,
        };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 512];
        let mut res = ResBuf::new(&mut out);
        select_chunky(&mut disp, &mut applets, &mut res);
        // Extended Le (65536) ≥ body → whole body, status unchanged.
        let sw = disp.process(
            &[0x00, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res,
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(res.len(), 269);
    }

    #[test]
    fn opt_out_applet_is_never_chained() {
        let mut c = Chunky {
            body_len: 269,
            chain: false,
        };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 512];
        let mut res = ResBuf::new(&mut out);
        select_chunky(&mut disp, &mut applets, &mut res);
        // Short Le, but opted out → full body returned, no 61xx.
        let sw = disp.process(
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res,
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(res.len(), 269);
        // A stray GET RESPONSE with nothing pending falls through to the applet.
        let sw = disp.process(
            &[0x00, 0xC0, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res,
        );
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
    }
}
