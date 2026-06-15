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
use embassy_rp::pio::{InterruptHandler as PioIrq, Pio};
use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
use embassy_rp::trng::{
    Config as TrngConfig, InterruptHandler as TrngIrq, InverterChainLength, Trng,
};
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
    if let Some(phy) = rsk_rescue::phy::load(&mut fs) {
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
        usb_itf = rsk_rescue::phy::effective_usb_itf(&phy);
    }

    let driver = UsbDriver::new(p.USB, Irqs);
    Timer::after_millis(200).await;

    let mut config = UsbConfig::new(usb_vid, usb_pid);
    config.manufacturer = Some(USB_MANUFACTURER);
    config.product = Some(usb_product);
    config.serial_number = Some("rs-key-0001");
    config.max_power = 100;
    config.max_packet_size_0 = 64;
    config.device_release = 0x0760; // bcdDevice: our build counter

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

    let usb = builder.build();
    let ctap = hid.map(|h| {
        let (reader, writer) = h.split();
        CtapHid::new(reader, writer, ClientCtap, presence::up_pending)
    });

    let mut trng_cfg = TrngConfig::default();
    trng_cfg.inverter_chain_length = InverterChainLength::None;
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
    let _ = rsk_fido::seed::ensure_seed(&dev, &mut fs, &mut rng);
    let _ = rsk_openpgp::scan_files(&dev, &mut fs, &mut rng);
    vendor::load_led_config(&mut fs);
    rsk_otp::power_up_bump(&mut fs);

    let fs_ref = FS.init(RefCell::new(fs));
    let rng_ref = RNG_CELL.init(RefCell::new(rng));

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

    let Pio {
        mut common, sm0, ..
    } = Pio::new(p.PIO0, Irqs);
    let program = PioWs2812Program::new(&mut common);
    macro_rules! led_pin {
        ($($n:literal => $pin:expr),* $(,)?) => {{
            $( #[cfg(led_pin = $n)] { $pin } )*
        }};
    }
    let led_data = led_pin!(
        "0" => p.PIN_0, "1" => p.PIN_1, "2" => p.PIN_2, "3" => p.PIN_3, "4" => p.PIN_4,
        "5" => p.PIN_5, "6" => p.PIN_6, "7" => p.PIN_7, "8" => p.PIN_8, "9" => p.PIN_9,
        "10" => p.PIN_10, "11" => p.PIN_11, "12" => p.PIN_12, "13" => p.PIN_13, "14" => p.PIN_14,
        "15" => p.PIN_15, "16" => p.PIN_16, "17" => p.PIN_17, "18" => p.PIN_18, "19" => p.PIN_19,
        "20" => p.PIN_20, "21" => p.PIN_21, "22" => p.PIN_22, "23" => p.PIN_23, "24" => p.PIN_24,
        "25" => p.PIN_25, "26" => p.PIN_26, "27" => p.PIN_27, "28" => p.PIN_28, "29" => p.PIN_29,
    );
    let ws2812 = PioWs2812::with_color_order(&mut common, sm0, p.DMA_CH0, Irqs, led_data, &program);
    hp.spawn(led::led_task(ws2812).unwrap());

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
