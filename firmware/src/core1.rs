// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The RP2350's second core as a prime-search engine for RSA keygen.
//!
//! RSA generation is the longest operation the device ever runs (each prime is
//! hundreds of rejected candidates), and the search is embarrassingly
//! parallel: candidates are independent random draws. Core1 runs a bare loop —
//! no executor: it sleeps in WFE until core0 posts a job, then draws and tests
//! candidates with its own per-job HMAC-DRBG, posting found primes back.
//! Core0 keeps testing its own candidates between polls and feeds both streams
//! through one [`RsaKeygen`] pool, so the cores race for `p` and `q` — the
//! expected wall time roughly halves (and with it the longest CCID transaction
//! a host ever has to sit through).
//!
//! Safety boundaries:
//! - **Flash/XIP**: embassy-rp's flash driver brackets every erase/program
//!   with `multicore::pause_core1()` (a RAM-resident FIFO-IRQ handshake), so
//!   this loop's XIP fetches can never collide with a flash write. The
//!   inter-core FIFO stays reserved for that protocol — this mailbox is
//!   critical-section statics plus SEV/WFE.
//! - **Heap**: both cores allocate bignums; the global allocator is
//!   critical-section-guarded (a cross-core hardware spinlock), so
//!   allocations serialize.
//! - **Secrets**: the DRBG seed and every prime in transit are zeroized at
//!   each hand-off, and `BUSY` is raised in the same critical section that
//!   takes the job — `run_rsa_search`'s wind-down ("job gone ∧ ¬BUSY ⇒ core1
//!   is out, nothing more will be posted") has no window for a late find.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_rp::Peri;
use embassy_rp::multicore::{Stack, spawn_core1};
use embassy_rp::peripherals::CORE1;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use rsk_crypto::HmacDrbg;
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{RsaKeygen, RsaPrivateKey, RsaStep};
use static_cell::StaticCell;
use zeroize::Zeroize;

extern crate alloc;
use alloc::boxed::Box;

/// One prime in transit, little-endian (an RSA-4096 half = 256 bytes).
const MAX_HALF: usize = 256;

/// Core1's per-job DRBG seed: 40 bytes of entropy from the main TRNG-backed
/// RNG ‖ an 8-byte domain tag — the entropy ‖ nonce ‖ personalization
/// concatenation of SP 800-90A 10.1.2.3, sized like `FidoRng`'s 48-byte seed.
const SEED_LEN: usize = 48;
const SEED_TAG: &[u8; 8] = b"rsk-rsa2";

struct Job {
    half_bytes: usize,
    seed: [u8; SEED_LEN],
}

/// A found prime in transit from core1 to core0.
struct Found {
    le: [u8; MAX_HALF],
    len: usize,
}

/// The core0 ↔ core1 mailbox: the posted job and up to two found primes.
struct Mailbox {
    job: Option<Job>,
    found: [Option<Found>; 2],
}

static MAILBOX: Mutex<CriticalSectionRawMutex, RefCell<Mailbox>> =
    Mutex::new(RefCell::new(Mailbox {
        job: None,
        found: [None, None],
    }));
/// Core0 → core1: the pool is complete, abandon the current search.
static STOP: AtomicBool = AtomicBool::new(false);
/// Core1 → core0: a search is running (raised atomically with taking the job).
static BUSY: AtomicBool = AtomicBool::new(false);

/// Core1's stack. The deep frame is `passes_fermat_base2` → `modexp_priv`
/// (~6 KiB of fixed buffers); 16 KiB leaves comfortable headroom for the
/// Baillie-PSW bignum work on top.
static CORE1_STACK: StaticCell<Stack<16384>> = StaticCell::new();

/// Boot the engine (idle in WFE until the first job). Called once from `main`;
/// from that point embassy-rp's flash driver pauses/resumes core1 around every
/// erase/program.
pub fn spawn(core1: Peri<'static, CORE1>) {
    spawn_core1(core1, CORE1_STACK.init_with(Stack::new), || core1_main());
}

/// Scrub and drop any primes still sitting in the mailbox.
fn scrub_found(mb: &mut Mailbox) {
    for slot in &mut mb.found {
        if let Some(mut f) = slot.take() {
            f.le.zeroize();
        }
    }
}

// --------------------------------------------------------------- core1 side --

/// Core1 entry: wait for a job, search until satisfied or told to stop, repeat.
fn core1_main() -> ! {
    loop {
        // Take the job and raise BUSY in ONE critical section — the wind-down
        // in `run_rsa_search` relies on never observing "job taken, BUSY not
        // yet visible".
        let job = MAILBOX.lock(|mb| {
            let job = mb.borrow_mut().job.take();
            if job.is_some() {
                BUSY.store(true, Ordering::Relaxed);
            }
            job
        });
        let Some(mut job) = job else {
            // Sleep until core0 signals. Spurious wakes — any event, including
            // the flash-pause FIFO interrupt — just re-poll.
            cortex_m::asm::wfe();
            continue;
        };
        search(&job);
        job.seed.zeroize();
        BUSY.store(false, Ordering::Release);
        cortex_m::asm::sev();
    }
}

/// Core1's RNG: the per-job HMAC-DRBG (state zeroizes on drop).
struct DrbgRng(HmacDrbg);
impl Rng for DrbgRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// Draw and test candidates until the pool is satisfied or core0 says stop.
fn search(job: &Job) {
    // The same paranoia as core0's gate: if the asm modexp known-answer test
    // fails on THIS core, contribute nothing (core0's own `usable()` gate has
    // already refused the whole operation if its KAT failed).
    if !RsaKeygen::new(job.half_bytes * 16).usable() {
        return;
    }
    let mut rng = DrbgRng(HmacDrbg::new(&job.seed));
    while !STOP.load(Ordering::Acquire) {
        let mut le = [0u8; MAX_HALF];
        let Some(len) = RsaKeygen::try_candidate_le(&mut rng, job.half_bytes, &mut le) else {
            continue;
        };
        let pool_full = MAILBOX.lock(|mb| {
            let mut mb = mb.borrow_mut();
            if let Some(slot) = mb.found.iter_mut().find(|s| s.is_none()) {
                *slot = Some(Found { le, len });
            }
            mb.found.iter().all(|s| s.is_some())
        });
        le.zeroize();
        if pool_full {
            // Two primes delivered from this side alone — the pool is complete
            // whatever core0 found; stop burning cycles and wait for the next job.
            break;
        }
    }
}

// --------------------------------------------------------------- core0 side --

/// Run the RSA prime search on both cores and assemble the key. Blocks the
/// worker exactly like the old single-core loop did (the interrupt executor
/// keeps USB + keepalives flowing); core1 is parked again by the time this
/// returns. `None` is the old `RsaStep::Failed`: an unusable size / failed
/// modexp self-test, or key assembly failure.
pub fn run_rsa_search(nbits: usize, rng: &mut dyn Rng) -> Option<Box<RsaPrivateKey>> {
    let mut kg = RsaKeygen::new(nbits);
    if !kg.usable() {
        return None;
    }

    // Post the job: stale finds scrubbed, fresh DRBG seed for core1.
    let mut job = Job {
        half_bytes: kg.half_bytes(),
        seed: [0u8; SEED_LEN],
    };
    rng.fill(&mut job.seed[..SEED_LEN - SEED_TAG.len()]);
    job.seed[SEED_LEN - SEED_TAG.len()..].copy_from_slice(SEED_TAG);
    STOP.store(false, Ordering::Release);
    MAILBOX.lock(|mb| {
        let mut mb = mb.borrow_mut();
        scrub_found(&mut mb);
        mb.job = Some(job);
    });
    cortex_m::asm::sev();

    // `Some(Some(key))` = assembled, `Some(None)` = the old `Failed`.
    let mut outcome: Option<Option<Box<RsaPrivateKey>>> = None;
    while outcome.is_none() {
        // Core1's finds first (cheap to drain)…
        let mut batch = MAILBOX.lock(|mb| {
            let mut mb = mb.borrow_mut();
            [mb.found[0].take(), mb.found[1].take()]
        });
        let mut had_finds = false;
        for f in batch.iter_mut().filter_map(Option::as_mut) {
            had_finds = true;
            if outcome.is_none() {
                match kg.offer_le(&mut f.le[..f.len]) {
                    RsaStep::More => {}
                    RsaStep::Done(k) => outcome = Some(Some(k)),
                    RsaStep::Failed => outcome = Some(None),
                }
            } else {
                // A find that arrived after the verdict — scrub, don't use.
                f.le.zeroize();
            }
        }
        if had_finds {
            continue; // re-poll before sinking into a slow own candidate
        }
        // …then one own candidate (the slow part, one Baillie-PSW).
        let mut le = [0u8; MAX_HALF];
        if let Some(len) = RsaKeygen::try_candidate_le(rng, kg.half_bytes(), &mut le) {
            match kg.offer_le(&mut le[..len]) {
                RsaStep::More => {}
                RsaStep::Done(k) => outcome = Some(Some(k)),
                RsaStep::Failed => outcome = Some(None),
            }
        }
        le.zeroize();
    }

    // Wind down: un-post the job if core1 never took it, then stop a running
    // search, wait for it to wind out, and scrub whatever it still found.
    MAILBOX.lock(|mb| {
        if let Some(mut j) = mb.borrow_mut().job.take() {
            j.seed.zeroize();
        }
    });
    STOP.store(true, Ordering::Release);
    cortex_m::asm::sev();
    while BUSY.load(Ordering::Acquire) {
        // Bounded by one candidate test on core1 (its loop checks STOP between
        // candidates); USB stays alive on the interrupt executor meanwhile.
        core::hint::spin_loop();
    }
    MAILBOX.lock(|mb| scrub_found(&mut mb.borrow_mut()));
    STOP.store(false, Ordering::Release);
    outcome.flatten()
}
