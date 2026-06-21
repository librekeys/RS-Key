// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Composite USB device: FIDO CTAPHID + CCID smart-card + emulated keyboard.
//! Two-executor split: USB + the transports run on a high-priority interrupt
//! executor, the [`worker::Worker`] (slow synchronous applet dispatch) on the
//! thread executor — so keepalives keep flowing during long crypto. The second
//! core joins in for RSA keygen only ([`core1`]): both cores race the prime
//! search while the transports keep the host alive.
#![no_std]
#![no_main]

use core::cell::RefCell;

use embassy_executor::{InterruptExecutor, Spawner};
use embassy_rp::bind_interrupts;
use embassy_rp::dma::InterruptHandler as DmaIrq;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::interrupt;
use embassy_rp::interrupt::{InterruptExt, Priority};
use embassy_rp::peripherals::{DMA_CH0, PIO0, TRNG, USB};
use embassy_rp::pio::InterruptHandler as PioIrq;
// The `ws2812` LED backend drives the addressable LED over the PIO. Any non-`none`
// build compiles all three hardware backends so the driver is runtime-selectable
// from the phy record (PicoForge); a `none` build pulls in none of them. DMA_CH0
// and the PIO0/DMA IRQs stay bound unconditionally (the type is used by
// `bind_interrupts!` below — harmless when no backend uses it).
#[cfg(not(led_kind = "none"))]
use embassy_rp::pio::Pio;
#[cfg(not(led_kind = "none"))]
use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
use embassy_rp::trng::{Config as TrngConfig, InterruptHandler as TrngIrq, Trng};
use embassy_rp::usb::{Driver as UsbDriver, InterruptHandler as UsbIrq};
use embassy_time::Timer;
use embassy_usb::class::hid::{
    Config as HidConfig, HidBootProtocol, HidReaderWriter, HidSubclass, HidWriter,
    State as HidState,
};
use embassy_usb::{Builder, Config as UsbConfig, UsbDevice};
use static_cell::StaticCell;

use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_usb::ccid::{ATR_FIDO, Ccid};
use rsk_usb::ctaphid::{CtapHid, FIDO_REPORT_DESCRIPTOR};

mod ccid_handler;
mod core1;
mod flash_storage;
mod handler;
mod led;
mod otp_kbd;
mod otp_keys;
mod presence;
mod rescue_platform;
mod vendor;
mod worker;

use flash_storage::{FLASH_SIZE, FlashStorage};
use handler::{FidoRng, Store};
use presence::BootselPresence;
use worker::{ClientCcid, ClientCtap, Worker};

use panic_halt as _;

use embedded_alloc::LlffHeap as Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

const HEAP_SIZE: usize = 128 * 1024;

#[unsafe(link_section = ".start_block")]
#[used]
static IMAGE_DEF: embassy_rp::block::ImageDef = embassy_rp::block::ImageDef::secure_exe();

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => PioIrq<PIO0>;
    DMA_IRQ_0 => DmaIrq<DMA_CH0>;
    USBCTRL_IRQ => UsbIrq<USB>;
    TRNG_IRQ => TrngIrq<TRNG>;
});

const fn env_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    let mut acc = 0u16;
    let mut i = 0;
    while i < b.len() {
        acc = acc * 10 + (b[i] - b'0') as u16;
        i += 1;
    }
    acc
}
const USB_VID: u16 = env_u16(env!("PK_USB_VID"));
const USB_PID: u16 = env_u16(env!("PK_USB_PID"));
const USB_MANUFACTURER: &str = env!("PK_USB_MANUFACTURER");
const USB_PRODUCT: &str = env!("PK_USB_PRODUCT");

const fn env_u32(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut acc = 0u32;
    let mut i = 0;
    while i < b.len() {
        acc = acc * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    acc
}
const XOSC_DELAY_MULT: u32 = env_u32(env!("PK_XOSC_DELAY_MULT"));

// Build-time LED defaults. The runtime `EF_PHY` record (PicoForge / `rsk hw`)
// overrides each at boot; absent that, the LED behaves exactly as the build
// flags say. Only a non-`none` build renders an LED, so these exist only there.
// The wire-order default lives in `led` (the `LED_RG_SWAP` atomic seeds from the
// `led_order` cfg). `BUILD_DRIVER` maps the build LED_KIND onto the phy driver
// numbering (1=gpio, 2=pimoroni, 3=ws2812).
#[cfg(not(led_kind = "none"))]
const BUILD_LED_PIN: u8 = env_u16(env!("PK_LED_PIN")) as u8;
#[cfg(led_kind = "ws2812")]
const BUILD_DRIVER: u8 = 3;
#[cfg(led_kind = "gpio")]
const BUILD_DRIVER: u8 = 1;
#[cfg(led_kind = "pimoroni")]
const BUILD_DRIVER: u8 = 2;

type Drv = UsbDriver<'static, USB>;

static EXECUTOR_HIGH: InterruptExecutor = InterruptExecutor::new();

#[interrupt]
unsafe fn SWI_IRQ_1() {
    unsafe { EXECUTOR_HIGH.on_interrupt() }
}

static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
static MSOS_DESC: StaticCell<[u8; 64]> = StaticCell::new();
static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
static HID_STATE: StaticCell<HidState> = StaticCell::new();
static KBD_STATE: StaticCell<HidState> = StaticCell::new();
static OTP_HID_HANDLER: StaticCell<otp_kbd::OtpHidHandler> = StaticCell::new();
static USB_HANDLER: StaticCell<led::StatusHandler> = StaticCell::new();
static FS: StaticCell<RefCell<Store>> = StaticCell::new();
static FLASH_CELL: StaticCell<RefCell<flash_storage::AsyncFlash>> = StaticCell::new();
static RNG_CELL: StaticCell<RefCell<FidoRng>> = StaticCell::new();
static PRESENCE: StaticCell<RefCell<BootselPresence>> = StaticCell::new();
static RESCUE_PLATFORM: StaticCell<RefCell<rescue_platform::RescuePlatform>> = StaticCell::new();
static PHY_PRODUCT: StaticCell<[u8; 32]> = StaticCell::new();

struct SendUsb(UsbDevice<'static, Drv>);
unsafe impl Send for SendUsb {}

#[embassy_executor::task]
async fn usb_task(mut device: SendUsb) {
    device.0.run().await;
}

#[embassy_executor::task]
async fn ctap_task(mut ctap: CtapHid<'static, Drv, ClientCtap>) {
    ctap.run().await;
}

#[embassy_executor::task]
async fn ccid_task(mut ccid: Ccid<'static, Drv, ClientCcid>) {
    ccid.run().await;
}

unsafe extern "C" {
    static __kvmain_start: u32;
    static __kvmain_end: u32;
    static __kvcnt_start: u32;
    static __kvcnt_end: u32;
}

fn kvmain_range() -> core::ops::Range<u32> {
    let start = core::ptr::addr_of!(__kvmain_start) as u32;
    let end = core::ptr::addr_of!(__kvmain_end) as u32;
    start..end
}

fn kvcnt_range() -> core::ops::Range<u32> {
    let start = core::ptr::addr_of!(__kvcnt_start) as u32;
    let end = core::ptr::addr_of!(__kvcnt_end) as u32;
    start..end
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let mut config = embassy_rp::config::Config::default();
    if let Some(xosc) = config.clocks.xosc.as_mut() {
        xosc.delay_multiplier = XOSC_DELAY_MULT;
    }
    let p = embassy_rp::init(config);

    {
        use core::mem::MaybeUninit;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }

    let serial_id = embassy_rp::otp::get_chipid().unwrap_or(0).to_le_bytes();
    let serial_hash = rsk_crypto::sha256(&serial_id);

    let (otp_mkek, otp_devk) = otp_keys::read_keys();
    otp_keys::sw_lock_key_page();

    let flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
    let flash_cell = FLASH_CELL.init(RefCell::new(flash_storage::wrap_flash(flash)));
    let storage = FlashStorage::new(flash_cell, kvmain_range(), kvcnt_range());
    let mut fs = Fs::new(storage, &[]);
    fs.scan(); // recover dynamic files (counter, resident creds) from flash

    let mut usb_vid = USB_VID;
    let mut usb_pid = USB_PID;
    let mut usb_product = USB_PRODUCT;
    let mut usb_itf = rsk_rescue::phy::USB_ITF_ALL;
    // The phy record drives USB identity (here) and the LED hardware (pin/driver/
    // wire order, applied at the spawn site below) — keep it in scope for both.
    let phy = rsk_rescue::phy::load(&mut fs);
    if let Some(phy) = &phy {
        if let Some((vid, pid)) = phy.vid_pid {
            (usb_vid, usb_pid) = (vid, pid);
        }
        if let Some(s) = phy.usb_product.as_ref().and_then(|prod| prod.as_str()) {
            let buf = PHY_PRODUCT.init([0; 32]);
            buf[..s.len()].copy_from_slice(s.as_bytes());
            if let Ok(stored) = core::str::from_utf8(&buf[..s.len()]) {
                usb_product = stored;
            }
        }
        usb_itf = rsk_rescue::phy::effective_usb_itf(phy);
    }

    // Provision/recover all persistent state BEFORE attaching to USB. `builder.build()`
    // below asserts the bus pull-up (embassy `driver.start` -> `set_pullup_en`), so the
    // host starts enumerating the instant we attach. The task that answers control
    // transfers (`usb_task` -> `device.run()`) must then be spawned with no blocking
    // work in between — otherwise the host enumerates into a device that is attached
    // but mute and times out the first descriptor request. That window (heaviest on a
    // fresh device: seed + attestation cert + OpenPGP DEK + flash writes) was the
    // "blink red / not recognised until several replugs" report on a Waveshare RP2350.
    let mut trng_cfg = TrngConfig::default();
    // The default sample_count (25) is too low for some RP2350 ROSC units: the
    // TRNG's autocorrelation health-check fails, the hardware soft-resets and
    // re-samples in a loop, so seeding the DRBG (48 B, `FidoRng::new`) blocked
    // ~90 s on EVERY boot on one Waveshare RP2350 unit (variable 30–105 s). A
    // higher sample_count decorrelates consecutive ROSC samples so the check
    // passes the first time (~1.5 s boot, HW-verified). Entropy quality is
    // unchanged — the NIST health checks stay enabled, the source is unchanged.
    trng_cfg.sample_count = 1000;
    let trng = Trng::new(p.TRNG, Irqs, trng_cfg);
    let mut rng = FidoRng::new(trng);

    let dev = Device {
        serial_hash: &serial_hash,
        serial_id: &serial_id,
        otp_key: otp_mkek.as_ref(),
    };
    let _ = rsk_fido::seed::migrate_keydev_boot(&dev, &mut fs);
    rsk_rescue::keydev::migrate_kbase(&dev, &mut fs);
    rsk_piv::migrate_kbase(&dev, &mut fs, &mut rng);
    rsk_oath::migrate_seal(&dev, &mut fs, &mut rng);
    rsk_fido::credential::migrate_rp_seal(&dev, &mut fs);
    let _ = rsk_fido::seed::ensure_seed(&dev, &mut fs, &mut rng);
    let _ = rsk_openpgp::scan_files(&dev, &mut fs, &mut rng);
    // PHY carries the boot-default LED brightness + steady (PicoForge's global LED
    // knobs) and the RS-Key wire-order tag. Apply them BEFORE `load_led_config` so
    // a per-status `EF_LED_CONF` (set via `rsk led`) overrides brightness/steady;
    // the wire order is not in EF_LED_CONF, so it stands.
    #[cfg(not(led_kind = "none"))]
    if let Some(phy) = &phy {
        if let Some(b) = phy.led_brightness {
            led::set_all_brightness(b);
        }
        led::set_steady(phy.opts & rsk_rescue::phy::OPT_LED_STEADY != 0);
        if let Some(order) = phy.led_order {
            led::set_rg_swap(order != 0);
        }
    }
    vendor::load_led_config(&mut fs);
    rsk_otp::power_up_bump(&mut fs);

    let fs_ref = FS.init(RefCell::new(fs));
    let rng_ref = RNG_CELL.init(RefCell::new(rng));

    let driver = UsbDriver::new(p.USB, Irqs);
    Timer::after_millis(200).await;

    let mut config = UsbConfig::new(usb_vid, usb_pid);
    config.manufacturer = Some(USB_MANUFACTURER);
    config.product = Some(usb_product);
    config.serial_number = Some("rs-key-0001");
    config.max_power = 100;
    config.max_packet_size_0 = 64;
    config.device_release = 0x077E; // bcdDevice: our build counter

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        MSOS_DESC.init([0; 64]),
        CONTROL_BUF.init([0; 64]),
    );

    let hid = (usb_itf & rsk_rescue::phy::USB_ITF_HID != 0).then(|| {
        HidReaderWriter::<_, 64, 64>::new(
            &mut builder,
            HID_STATE.init(HidState::new()),
            HidConfig {
                report_descriptor: FIDO_REPORT_DESCRIPTOR,
                request_handler: None,
                poll_ms: 5,
                max_packet_size: 64,
                hid_subclass: HidSubclass::No,
                hid_boot_protocol: HidBootProtocol::None,
            },
        )
    });

    let ccid = (usb_itf & rsk_rescue::phy::USB_ITF_CCID != 0)
        .then(|| Ccid::new(&mut builder, ClientCcid, ATR_FIDO));

    let kbd = (usb_itf & rsk_rescue::phy::USB_ITF_KB != 0).then(|| {
        HidWriter::<_, 8>::new(
            &mut builder,
            KBD_STATE.init(HidState::new()),
            HidConfig {
                report_descriptor: otp_kbd::KEYBOARD_REPORT_DESCRIPTOR,
                request_handler: Some(OTP_HID_HANDLER.init(otp_kbd::OtpHidHandler)),
                poll_ms: 10,
                max_packet_size: 8,
                hid_subclass: HidSubclass::No,
                hid_boot_protocol: HidBootProtocol::None,
            },
        )
    });

    // Go green (idle) the moment the host configures us, not on the first applet
    // command — a healthy, enumerated key with no PC/SC client talking to it would
    // otherwise sit on the red boot status. (See `led::StatusHandler`.)
    builder.handler(USB_HANDLER.init(led::StatusHandler));

    // Attach to the host (pull-up) and immediately start servicing it: no blocking
    // work between `build()` and the `usb_task` spawn (see the init note above).
    let usb = builder.build();
    let ctap = hid.map(|h| {
        let (reader, writer) = h.split();
        CtapHid::new(
            reader,
            writer,
            ClientCtap,
            presence::up_pending,
            presence::request_cancel,
        )
    });

    interrupt::SWI_IRQ_1.set_priority(Priority::P2);
    let hp = EXECUTOR_HIGH.start(interrupt::SWI_IRQ_1);
    hp.spawn(usb_task(SendUsb(usb)).unwrap());
    if let Some(ctap) = ctap {
        hp.spawn(ctap_task(ctap).unwrap());
    }
    if let Some(ccid) = ccid {
        hp.spawn(ccid_task(ccid).unwrap());
    }
    if let Some(kbd) = kbd {
        hp.spawn(otp_kbd::kbd_task(kbd).unwrap());
    }

    // LED backend, selected at runtime from the phy record (PicoForge-compatible),
    // defaulting to the build LED_KIND / LED_PIN. A non-`none` build compiles all
    // three hardware backends so the driver + pin can change without reflashing; a
    // `none` build is headless (the status engine still runs — vendor SET/GET LED
    // keep working — but nothing renders it). The runtime pin reaches the PIO state
    // machine via a `match` that moves the shared `sm0`/`DMA_CH0` across its
    // mutually-exclusive arms (every `PioWs2812` erases the pin type, so all arms
    // share one type) — embassy has no `PioPin for AnyPin`, but it doesn't need one.
    #[cfg(not(led_kind = "none"))]
    {
        use embassy_rp::gpio::{Level, Output};
        use embassy_rp::pwm::Pwm;

        // PHY led_gpio overrides the build LED_PIN; an out-of-range pin is ignored.
        let led_gpio = phy
            .as_ref()
            .and_then(|p| p.led_gpio)
            .filter(|&g| g <= 29)
            .unwrap_or(BUILD_LED_PIN);
        // PHY led_driver (1=gpio, 2=pimoroni, 3=ws2812) overrides the build kind;
        // anything else (unset, or the N/A esp32 value) keeps the build default.
        let led_driver = match phy.as_ref().and_then(|p| p.led_driver) {
            Some(d @ 1..=3) => d,
            _ => BUILD_DRIVER,
        };

        match led_driver {
            1 => {
                // `gpio`: a plain on/off LED on `led_gpio`. `Output<'static>` erases
                // the pin, so every arm is the same type.
                macro_rules! gpio_pin {
                    ($pin:expr) => {
                        Output::new($pin, Level::Low)
                    };
                }
                let led = match led_gpio {
                    0 => gpio_pin!(p.PIN_0),
                    1 => gpio_pin!(p.PIN_1),
                    2 => gpio_pin!(p.PIN_2),
                    3 => gpio_pin!(p.PIN_3),
                    4 => gpio_pin!(p.PIN_4),
                    5 => gpio_pin!(p.PIN_5),
                    6 => gpio_pin!(p.PIN_6),
                    7 => gpio_pin!(p.PIN_7),
                    8 => gpio_pin!(p.PIN_8),
                    9 => gpio_pin!(p.PIN_9),
                    10 => gpio_pin!(p.PIN_10),
                    11 => gpio_pin!(p.PIN_11),
                    12 => gpio_pin!(p.PIN_12),
                    13 => gpio_pin!(p.PIN_13),
                    14 => gpio_pin!(p.PIN_14),
                    15 => gpio_pin!(p.PIN_15),
                    16 => gpio_pin!(p.PIN_16),
                    17 => gpio_pin!(p.PIN_17),
                    18 => gpio_pin!(p.PIN_18),
                    19 => gpio_pin!(p.PIN_19),
                    20 => gpio_pin!(p.PIN_20),
                    21 => gpio_pin!(p.PIN_21),
                    22 => gpio_pin!(p.PIN_22),
                    23 => gpio_pin!(p.PIN_23),
                    24 => gpio_pin!(p.PIN_24),
                    25 => gpio_pin!(p.PIN_25),
                    26 => gpio_pin!(p.PIN_26),
                    27 => gpio_pin!(p.PIN_27),
                    28 => gpio_pin!(p.PIN_28),
                    _ => gpio_pin!(p.PIN_29),
                };
                hp.spawn(led::gpio_task(led).unwrap());
            }
            2 => {
                // `pimoroni`: a 3-pin PWM RGB on fixed pins (Pimoroni Tiny 2350) —
                // R=GPIO18 (slice1·A), G=GPIO19 (slice1·B), B=GPIO20 (slice2·A);
                // common-anode polarity is in `led::pimoroni_cfg`. led_gpio is N/A.
                let rg = Pwm::new_output_ab(p.PWM_SLICE1, p.PIN_18, p.PIN_19, led::pimoroni_cfg());
                let b = Pwm::new_output_a(p.PWM_SLICE2, p.PIN_20, led::pimoroni_cfg());
                hp.spawn(led::pimoroni_task(rg, b).unwrap());
            }
            _ => {
                // `ws2812` (driver 3, and the safe fallback): the single addressable
                // RGB LED on `led_gpio`. Wire order is a software r/g swap in the
                // task (`led::set_rg_swap`), so embassy's color order stays `Rgb`.
                let Pio {
                    mut common, sm0, ..
                } = Pio::new(p.PIO0, Irqs);
                let program = PioWs2812Program::new(&mut common);
                macro_rules! ws2812_pin {
                    ($pin:expr) => {
                        PioWs2812::with_color_order(
                            &mut common,
                            sm0,
                            p.DMA_CH0,
                            Irqs,
                            $pin,
                            &program,
                        )
                    };
                }
                let ws2812 = match led_gpio {
                    0 => ws2812_pin!(p.PIN_0),
                    1 => ws2812_pin!(p.PIN_1),
                    2 => ws2812_pin!(p.PIN_2),
                    3 => ws2812_pin!(p.PIN_3),
                    4 => ws2812_pin!(p.PIN_4),
                    5 => ws2812_pin!(p.PIN_5),
                    6 => ws2812_pin!(p.PIN_6),
                    7 => ws2812_pin!(p.PIN_7),
                    8 => ws2812_pin!(p.PIN_8),
                    9 => ws2812_pin!(p.PIN_9),
                    10 => ws2812_pin!(p.PIN_10),
                    11 => ws2812_pin!(p.PIN_11),
                    12 => ws2812_pin!(p.PIN_12),
                    13 => ws2812_pin!(p.PIN_13),
                    14 => ws2812_pin!(p.PIN_14),
                    15 => ws2812_pin!(p.PIN_15),
                    16 => ws2812_pin!(p.PIN_16),
                    17 => ws2812_pin!(p.PIN_17),
                    18 => ws2812_pin!(p.PIN_18),
                    19 => ws2812_pin!(p.PIN_19),
                    20 => ws2812_pin!(p.PIN_20),
                    21 => ws2812_pin!(p.PIN_21),
                    22 => ws2812_pin!(p.PIN_22),
                    23 => ws2812_pin!(p.PIN_23),
                    24 => ws2812_pin!(p.PIN_24),
                    25 => ws2812_pin!(p.PIN_25),
                    26 => ws2812_pin!(p.PIN_26),
                    27 => ws2812_pin!(p.PIN_27),
                    28 => ws2812_pin!(p.PIN_28),
                    _ => ws2812_pin!(p.PIN_29),
                };
                hp.spawn(led::ws2812_task(ws2812).unwrap());
            }
        }
    }

    core1::spawn(p.CORE1);

    let presence_ref = PRESENCE.init(RefCell::new(BootselPresence::new(p.BOOTSEL)));
    let platform_ref = RESCUE_PLATFORM.init(RefCell::new(rescue_platform::RescuePlatform));
    let (kvm, kvc) = (kvmain_range(), kvcnt_range());
    let kv_total = (kvm.end - kvm.start) + (kvc.end - kvc.start);
    let mut worker = Worker::new(
        fs_ref,
        rng_ref,
        presence_ref,
        platform_ref,
        serial_id,
        serial_hash,
        otp_mkek,
        otp_devk,
        kv_total,
    );
    worker.run().await;
}
