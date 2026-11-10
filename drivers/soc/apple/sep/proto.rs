// SPDX-License-Identifier: GPL-2.0-only
//
// The SEP's mailbox words as macOS 14.8.3's and 27.2's AppleSEPManager send and read them (rda AppleSEPManager,
// AppleSEPManager_272; work/scratch/trace14/sep-1.log), the lab's step tables in macOS's order, and the one list of
// what the lab may send (allowed).

use kernel::prelude::*;
use kernel::soc::apple::mailbox::Message;

// The endpoints: the control endpoint 0, the apps by the numbers the discovery advertised on this Mac (sep-1.log
// 1462-1500, and 27.2's at step 8), and the ROM's three (Asahi's sep.rs).
pub(crate) const EP_CONTROL: u8 = 0x00;
pub(crate) const EP_SBIO: u8 = 0x08;
pub(crate) const EP_SCRD: u8 = 0x0a;
pub(crate) const EP_HDCP: u8 = 0x0e;
pub(crate) const EP_SKS: u8 = 0x12;
pub(crate) const EP_XARM: u8 = 0x13;
pub(crate) const EP_STAC: u8 = 0x18;
pub(crate) const EP_DISCOVER: u8 = 0xFD;
pub(crate) const EP_SHMEM: u8 = 0xFE;
pub(crate) const EP_BOOT: u8 = 0xFF;

/// Discovery op 0: the app's 4CC in the data; op 1: its out-of-line sizes in SEP pages (AppleSEPDiscovery::_msgReceived
/// 0xfffffe0009d16580).
pub(crate) const DISCOVER_NAME: u8 = 0x00;
pub(crate) const DISCOVER_SIZES: u8 = 0x01;

/// One mailbox word (msg0; msg1 is 0 both ways): byte 0 the endpoint, byte 1 a tag the reply echoes, byte 2 the
/// operation, byte 3 a parameter, bytes 4-7 a 32-bit datum. The xART service and the key store reuse bytes 2-7 in
/// their own ways (xarm.rs, sks.rs).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Word {
    pub(crate) ep: u8,
    pub(crate) tag: u8,
    pub(crate) op: u8,
    pub(crate) param: u8,
    pub(crate) data: u32,
}

impl Word {
    pub(crate) const fn new(ep: u8, tag: u8, op: u8, param: u8, data: u32) -> Word {
        Word { ep, tag, op, param, data }
    }

    pub(crate) const fn of(m: &Message) -> Word {
        let b = m.msg0.to_le_bytes();
        Word {
            ep: b[0],
            tag: b[1],
            op: b[2],
            param: b[3],
            data: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    pub(crate) const fn raw(&self) -> u64 {
        u64::from_le_bytes([
            self.ep,
            self.tag,
            self.op,
            self.param,
            self.data as u8,
            (self.data >> 8) as u8,
            (self.data >> 16) as u8,
            (self.data >> 24) as u8,
        ])
    }

    pub(crate) const fn msg(&self) -> Message {
        Message { msg0: self.raw(), msg1: 0 }
    }
}

/// The SEP addresses and sizes buffers in 4 KiB units, though its own pages are 16 KiB.
pub(crate) const UNIT_SHIFT: u32 = 12;

/// The warm registration of the shared memory, as AppleSEPBooter::bootSEP (rda AppleSEPManager 0xfffffe0009d231dc)
/// sends it to a SEP iBoot already booted: endpoint 0xFE, the size in units in bits 16-31 and the address in units in
/// bits 32-63, nothing else (macOS's byte 1 is 0xAA, the kext's stack fill under its message). None for a size or
/// address that is not whole units or does not fit its field.
pub(crate) const fn shm_register(iova: u64, size: usize) -> Option<Message> {
    let unit = 1u64 << UNIT_SHIFT;
    let size = size as u64;
    if size == 0 || size % unit != 0 || iova % unit != 0 || size >> UNIT_SHIFT > 0xffff || iova >> UNIT_SHIFT > 0xffff_ffff {
        return None;
    }
    let w = (EP_SHMEM as u64) | ((size >> UNIT_SHIFT) << 16) | ((iova >> UNIT_SHIFT) << 32);
    Some(Message { msg0: w, msg1: 0 })
}

// macOS's registration on this Mac (sep-1.log 1458), but for its byte 1
static_assert!(match shm_register(0x1_0000_5b4_000, 0x1_c000) {
    Some(m) => m.msg0 == 0x1000_05b4_001c_00fe,
    None => false,
});
static_assert!(shm_register(0x1_0000_5b4_800, 0x1_c000).is_none());

/// The control endpoint's ack: op 0x01 with the request's tag, its data echoed (sep-1.log 1531-1785).
pub(crate) const CONTROL_ACK: u8 = 0x01;
/// How long a control request waits for its ack.
pub(crate) const CONTROL_TIMEOUT_MS: u32 = 2000;

// The control endpoint's ops for an app's buffers (AppleSEPEndpoint::enable 0xfffffe0009d2fabc) and the security mode
pub(crate) const OP_OOL_IN_ADDR: u8 = 0x02;
pub(crate) const OP_OOL_OUT_ADDR: u8 = 0x03;
pub(crate) const OP_OOL_IN_SIZE: u8 = 0x04;
pub(crate) const OP_OOL_OUT_SIZE: u8 = 0x05;
pub(crate) const OP_SECMODE: u8 = 0x14;
/// 32 random bits in the reply's data, its param the status (2: not supported): macOS's
/// AppleSEPControl::cmsgGET_ENTROPY_FOR_XNU_PRNG (rda AppleSEPManager_272 0xfffffe0009dc9b90).
pub(crate) const OP_ENTROPY: u8 = 0x36;
/// The tag of the driver's own control requests after the bring-up (macOS's is its command's pool index plus 1).
pub(crate) const TAG_OWN: u8 = 0x01;

pub(crate) const fn control(tag: u8, op: u8, param: u8, data: u32) -> Message {
    Word::new(EP_CONTROL, tag, op, param, data).msg()
}

// The trace's first enable, bit for bit (sep-1.log 1531)
static_assert!(control(0x08, OP_OOL_IN_SIZE, EP_HDCP, 0x4000).msg0 == 0x0000_4000_0e04_0800);

/// The app whose out-of-line pair a step names, or none (op 0x14).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum App {
    None,
    Hdcp,
    Xarm,
    Stac,
    Sks,
    Scrd,
    Sbio,
}

impl App {
    pub(crate) const fn ep(self) -> u8 {
        match self {
            App::None => 0,
            App::Hdcp => EP_HDCP,
            App::Xarm => EP_XARM,
            App::Stac => EP_STAC,
            App::Sks => EP_SKS,
            App::Scrd => EP_SCRD,
            App::Sbio => EP_SBIO,
        }
    }

    /// The 4CC the discovery endpoint names it by, as the message's data (big-endian characters).
    pub(crate) const fn fourcc(self) -> u32 {
        match self {
            App::None => 0,
            App::Hdcp => u32::from_be_bytes(*b"hdcp"),
            App::Xarm => u32::from_be_bytes(*b"xarm"),
            App::Stac => u32::from_be_bytes(*b"stac"),
            App::Sks => u32::from_be_bytes(*b"sks "),
            App::Scrd => u32::from_be_bytes(*b"scrd"),
            App::Sbio => u32::from_be_bytes(*b"sbio"),
        }
    }

    /// Its discovery op 1 data on 14.8.3 (sep-1.log 1491, 1515, 1475, 2129): in and out sizes in 0x4000-byte pages
    /// (sks: one to two each way, inferred; macOS registered two).
    pub(crate) const fn sizes_word(self) -> u32 {
        match self {
            App::None => 0,
            App::Hdcp | App::Scrd | App::Sbio => 0x0101_0101,
            App::Xarm | App::Stac => 0x0202_0202,
            App::Sks => 0x0201_0201,
        }
    }

    /// Each buffer's size, as macOS registered it (op 0x04 and 0x05's data).
    pub(crate) const fn ool_size(self) -> usize {
        match self {
            App::None => 0,
            App::Hdcp | App::Scrd | App::Sbio => 0x4000,
            App::Xarm | App::Stac | App::Sks => 0x8000,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            App::None => "cntl",
            App::Hdcp => "hdcp",
            App::Xarm => "xarm",
            App::Stac => "stac",
            App::Sks => "sks",
            App::Scrd => "scrd",
            App::Sbio => "sbio",
        }
    }
}

/// What a step's data is: a constant, or one of the app's buffers' address >> 12.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Data {
    Const(u32),
    InAddr,
    OutAddr,
}

/// One control message of the sequence and the ack it waits for.
#[derive(Clone, Copy)]
pub(crate) struct Step {
    /// macOS's tag for it (the SEP echoes it)
    pub(crate) tag: u8,
    pub(crate) op: u8,
    pub(crate) app: App,
    pub(crate) data: Data,
    /// the trace's line, for the log
    pub(crate) line: u32,
}

const fn step(tag: u8, op: u8, app: App, data: Data, line: u32) -> Step {
    Step {
        tag,
        op,
        app,
        data,
        line,
    }
}

/// macOS 14.8.3's first enables after the warm registration (sep-1.log 1531-1608), in its order and with its
/// tags: hdcp's and xarm's in sizes, the security mode, the in addresses, the out sizes, the out addresses.
pub(crate) const STAGE1: [Step; 9] = [
    step(0x08, OP_OOL_IN_SIZE, App::Hdcp, Data::Const(0x4000), 1531),
    step(0x07, OP_OOL_IN_SIZE, App::Xarm, Data::Const(0x8000), 1540),
    step(0x06, OP_SECMODE, App::None, Data::Const(0), 1549),
    step(0x06, OP_OOL_IN_ADDR, App::Xarm, Data::InAddr, 1558),
    step(0x06, OP_OOL_IN_ADDR, App::Hdcp, Data::InAddr, 1567),
    step(0x08, OP_OOL_OUT_SIZE, App::Xarm, Data::Const(0x8000), 1576),
    step(0x08, OP_OOL_OUT_SIZE, App::Hdcp, Data::Const(0x4000), 1585),
    step(0x06, OP_OOL_OUT_ADDR, App::Xarm, Data::OutAddr, 1595),
    step(0x08, OP_OOL_OUT_ADDR, App::Hdcp, Data::OutAddr, 1604),
];

/// stac's enable (sep-1.log 1750-1781). macOS sends it after hdcp's own ops 0x27 and 0x28 on endpoint 0x0e,
/// which step 2 does not send.
pub(crate) const STAGE2: [Step; 4] = [
    step(0x08, OP_OOL_IN_SIZE, App::Stac, Data::Const(0x8000), 1750),
    step(0x08, OP_OOL_IN_ADDR, App::Stac, Data::InAddr, 1759),
    step(0x08, OP_OOL_OUT_SIZE, App::Stac, Data::Const(0x8000), 1768),
    step(0x08, OP_OOL_OUT_ADDR, App::Stac, Data::OutAddr, 1781),
];

/// sks's enable (sep-1.log 2143-2175), once the discovery names it (2125, 2129): the in size and address, then
/// the out size and address, as stac's and unlike hdcp's and xarm's interleaved pair, each with macOS's tag 0x08.
pub(crate) const STAGE6: [Step; 4] = [
    step(0x08, OP_OOL_IN_SIZE, App::Sks, Data::Const(0x8000), 2143),
    step(0x08, OP_OOL_IN_ADDR, App::Sks, Data::InAddr, 2157),
    step(0x08, OP_OOL_OUT_SIZE, App::Sks, Data::Const(0x8000), 2166),
    step(0x08, OP_OOL_OUT_ADDR, App::Sks, Data::OutAddr, 2175),
];

/// scrd's and sbio's enables (sep-1.log 1897-1924 and 1952-1979, 0x4000 each way, macOS's tag 0x08), stage 8.
/// macOS sends scrd's INITIALIZE and one more command between the two (1934, 1943); stage 8 leaves scrd's
/// INITIALIZE for last.
pub(crate) const STAGE8: [Step; 8] = [
    step(0x08, OP_OOL_IN_SIZE, App::Scrd, Data::Const(0x4000), 1897),
    step(0x08, OP_OOL_IN_ADDR, App::Scrd, Data::InAddr, 1906),
    step(0x08, OP_OOL_OUT_SIZE, App::Scrd, Data::Const(0x4000), 1915),
    step(0x08, OP_OOL_OUT_ADDR, App::Scrd, Data::OutAddr, 1924),
    step(0x08, OP_OOL_IN_SIZE, App::Sbio, Data::Const(0x4000), 1952),
    step(0x08, OP_OOL_IN_ADDR, App::Sbio, Data::InAddr, 1961),
    step(0x08, OP_OOL_OUT_SIZE, App::Sbio, Data::Const(0x4000), 1970),
    step(0x08, OP_OOL_OUT_ADDR, App::Sbio, Data::OutAddr, 1979),
];

// sbio's and scrd's first enables (sep-1.log 1952, 1897) and sks's (2143), bit for bit
static_assert!(control(0x08, OP_OOL_IN_SIZE, EP_SBIO, 0x4000).msg0 == 0x0000_4000_0804_0800);
static_assert!(control(0x08, OP_OOL_IN_SIZE, EP_SCRD, 0x4000).msg0 == 0x0000_4000_0a04_0800);
static_assert!(control(0x08, OP_OOL_IN_SIZE, EP_SKS, 0x8000).msg0 == 0x0000_8000_1204_0800);

/// hdcp's own requests, the op in byte 1 and an interface's index in byte 3 (AppleHDCPManager::launchInterfaces
/// 0xfffffe0009ccfe78): op 0x27 asks the interface count (the reply's data; 0x0e on 14.8.3, sep-1.log 1613), op
/// 0x28 launches one (each reply: byte 1 the result, 0, byte 2 the size, 8, of what hdcp's out buffer holds).
pub(crate) const HDCP_OP_COUNT: u8 = 0x27;
pub(crate) const HDCP_OP_LAUNCH: u8 = 0x28;
/// More interfaces than this is not 14.8.3's SEP: nothing is launched.
pub(crate) const HDCP_MAX_INTERFACES: u32 = 0x20;

pub(crate) const fn encode_hdcp(op: u8, index: u8) -> Message {
    Word::new(EP_HDCP, op, 0, index, 0).msg()
}

static_assert!(encode_hdcp(HDCP_OP_COUNT, 0).msg0 == 0x270e);
static_assert!(encode_hdcp(HDCP_OP_LAUNCH, 1).msg0 == 0x0100_280e);

/// stac's generic-transfer transactions (AppleSEPGenericTransfer::transact 0xfffffe0009ccdbcc): a 28-byte packet
/// header and the data in stac's in buffer (_gt_write_next_packet 0xfffffe0009ccb3b8), then the word
/// `sequence << 48 | command << 16 | 0xfc << 8 | endpoint` (_gt_send_transact_message 0xfffffe0009ccb190; the
/// sequence was 0 on 14.8.3). The power-on (AppleTrustedAccessoryManager::setPowerStateGated 0xfffffe000a03e158)
/// is command 0x0f with the u32 1 and flags 0, and the SEP echoes the word (sep-1.log 1790, 1794).
pub(crate) const GT_FIRST: u8 = 0xfc;
pub(crate) const GT_POWER: u8 = 0x0f;
pub(crate) const GT_HEADER: usize = 0x1c;

pub(crate) const fn encode_gt(command: u8) -> Message {
    encode_gt_ep(EP_STAC, command)
}

/// A first packet's word on any generic-transfer endpoint (stac, sbio), sequence 0.
pub(crate) const fn encode_gt_ep(ep: u8, command: u8) -> Message {
    Word::new(ep, GT_FIRST, command, 0, 0).msg()
}

/// A generic-transfer error packet's marker (_gt_read_error 0xfffffe0009d58318 on 27.2: the status at +0x10).
pub(crate) const GT_ERROR: u8 = 0xff;
/// A packet's flags macOS's host refuses (bits 1, 2 and 5: no anti-replay, a static or a command-specific buffer;
/// _gt_get_*_buffer, 0xE00002C7).
pub(crate) const GT_FLAGS_REFUSED: u32 = 0x26;
/// 0x73's value on 27.2 (14.8.3 sent 3): likely the host's protocol generation (inferred).
pub(crate) const SBIO_GENERATION: u32 = 8;

/// Stage 8's SBIO ops, by 27.2's names (enumSBIOCommandToString 0xfffffe0009acfe48), for the log.
pub(crate) const fn sbio_name(op: u8) -> &'static str {
    match op {
        0x73 => "sbio 0x73, the communication init",
        0x7c => "sbio 0x7c, GetBioDeviceList",
        0x40 => "sbio 0x40, IsXARTAvailable",
        0x6b => "sbio 0x6b, GetCatacombState",
        0x6c => "sbio 0x6c, PrepareSaveCatacomb",
        0x37 => "sbio 0x37, ConfirmSaveCatacomb",
        0x70 => "sbio 0x70, SaveLockoutState",
        0x57 => "sbio 0x57, RemoveTemplate",
        0x6d => "sbio 0x6d, LoadCatacomb",
        0x71 => "sbio 0x71, LoadLockoutState",
        0x09 => "sbio 0x09, MatchResult",
        0x79 => "sbio 0x79, GetCatacombGroupState",
        0x7a => "sbio 0x7a, GetIdentityRecords",
        0x6e => "sbio 0x6e, GetIdentitiesList",
        0x38 => "sbio 0x38, the free identity count (v2)",
        0x39 => "sbio 0x39, the system protected config",
        0x33 => "sbio 0x33, a catacomb's ID",
        0x2b => "sbio 0x2b, the protected config",
        0x2e => "sbio 0x2e, the templates' validity",
        0x36 => "sbio 0x36, a catacomb's hash",
        0x5b => "sbio 0x5b, LoadCalibrationData",
        0x19 => "sbio 0x19, the sensor's reset",
        0x63 => "sbio 0x63, GetCalibrationDataInfo",
        0x1f => "sbio 0x1f, the match policy",
        0x0b => "sbio 0x0b, the match's end",
        0x80 => "sbio 0x80, the sensor's ID",
        0x17 => "sbio 0x17, the sensor's serial number",
        0x15 => "sbio 0x15, the key exchange (UID session)",
        0x16 => "sbio 0x16, the sensor's share",
        0x42 => "sbio 0x42, the sequence counter's challenge",
        0x18 => "sbio 0x18, the sensor's answer",
        0x5f => "sbio 0x5f, the patch",
        0x5d => "sbio 0x5d, the first parameters",
        0x5c => "sbio 0x5c, the second parameters",
        0x6a => "sbio 0x6a, a sensor-specific command",
        0x31 => "sbio 0x31, the module serial number's challenge",
        0x32 => "sbio 0x32, the sensor's module serial number",
        0x01 => "sbio 0x01, COMPLETE_INIT",
        0x2d => "sbio 0x2d, the context with no catacomb",
        0x03 => "sbio 0x03, BEGIN_ENROL",
        0x23 => "sbio 0x23, the image processing's preparation",
        0x06 => "sbio 0x06, the image processing's init",
        0x65 => "sbio 0x65, the capture",
        0x07 => "sbio 0x07, the image's assessment",
        0x08 => "sbio 0x08, the enrolment's info",
        0x22 => "sbio 0x22, EnableBgOpsUpdate",
        0x05 => "sbio 0x05, the cancel",
        _ => "sbio, an op stages 8 to 14 do not send",
    }
}

/// Stage 8's SBIO queries, none of which needs the sensor (work/scratch/agents/sep-step8.md, sec. 3 and 6), and the
/// communication init 0x73 27.2 sends first (AppleMesaSEPDriver::initSbioCommunication 0xfffffe0009acec28, data 8).
pub(crate) const SBIO_STAGE8: [u8; 14] = [0x73, 0x7c, 0x40, 0x6b, 0x79, 0x7a, 0x38, 0x39, 0x33, 0x2b, 0x2e, 0x36, 0x63, 0x1f];

/// Stage 9's SBIO ops, the sensor's bring-up in 27.2's order (M272 resetSensorAndLoadPatch 0xfffffe0009abcb18,
/// work/scratch/agents/sep-step9-relay.md sec. 1), after stage 8's: never 0x19 (a first run), 0x6F (only after a
/// calibration upload) or any provisioning, key or factory op (0x1B, 0x24, 0x30, 0x67, 0x84, 0x86).
pub(crate) const SBIO_STAGE9: [u8; 13] = [0x80, 0x17, 0x15, 0x16, 0x42, 0x18, 0x5f, 0x5d, 0x5c, 0x6a, 0x31, 0x32, 0x01];
/// The host's request for a reply's next packet, and the SEP's next packet (_gt_read_next_packet 0xfffffe0009d5807c).
pub(crate) const GT_MORE: u8 = 0xfe;
pub(crate) const GT_NEXT: u8 = 0xfd;
/// The only op whose reply comes in more than one packet in the bring-up, and the packets it may take: 0x500000
/// bytes (27.2's largest transaction) at 0x3FE4 a packet.
pub(crate) const SBIO_MULTI_OP: u8 = 0x5f;
pub(crate) const GT_MORE_MAX: u64 = 0x142;

/// The host's request for packet `seq + 1` of `command`'s reply: `seq << 48 | command << 16 | 0xfe << 8 | ep`,
/// nothing in its buffer (_gt_send_transact_message 0xfffffe0009d57914; seq from 0).
pub(crate) const fn encode_gt_more(ep: u8, command: u8, seq: u16) -> Message {
    Word::new(ep, GT_MORE, command, 0, (seq as u32) << 16).msg()
}

static_assert!(encode_gt_more(EP_SBIO, 0x5f, 0).msg0 == 0x5f_fe08);

/// The host's next packet of a request longer than one packet, after the SEP's 0xFE asked for it: `seq << 48 |
/// command << 16 | 0xfd << 8 | ep`, the packet in the in buffer at its offset (gt_handle_generic_transaction
/// 0xfffffe0009d583d8: 0xFE runs _gt_write_next_packet, then 0xFD goes out). The host's sequence counts every word
/// of the transaction from the first packet's 0 (_gt_send_transact_message), so the first next packet is 1.
pub(crate) const fn encode_gt_next(ep: u8, command: u8, seq: u16) -> Message {
    Word::new(ep, GT_NEXT, command, 0, (seq as u32) << 16).msg()
}

static_assert!(encode_gt_next(EP_SBIO, 0x65, 1).msg0 == 0x0001_0000_0065_fd08);

/// One packet of a request into `out` (_gt_write_next_packet 0xfffffe0009d57b48): the header {u32 version 1, the
/// total length, this packet's offset, the u64 flags, the command, this packet's length} and the chunk. Its length,
/// or None for no room.
pub(crate) fn gt_packet_at(command: u8, flags: u32, total: usize, offset: usize, chunk: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = GT_HEADER + chunk.len();
    let o = out.get_mut(..n)?;
    let words = [1, u32::try_from(total).ok()?, u32::try_from(offset).ok()?, flags, 0, u32::from(command), u32::try_from(chunk.len()).ok()?];
    for (i, w) in words.iter().enumerate() {
        o[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    o[GT_HEADER..].copy_from_slice(chunk);
    Some(n)
}

/// Stage 12 (Touch ID step 10c), an enrolment cancelled before its save, by 27.2's names (M272
/// enumSBIOCommandToString 0xfffffe0009acfe48 and the callers' assert strings): the context (0x2d
/// `cmd_no_catacomb_in_v1_t` {i32 user}, case 0x31; 0x2b {i32 user}), BEGIN_ENROL 0x03, per image 0x23, 0x06, 0x65,
/// 0x07, 0x08 (an image the SEP took for the enrolment), 0x22 (asyncCaptureHandler 0xfffffe0009aac864,
/// handleEnrollment 0xfffffe0009acaae0), and 0x05 (commandCancel 0xfffffe0009ab7330).
pub(crate) const SBIO_CANCEL: u8 = 0x05;
pub(crate) const SBIO_BEGIN_ENROL: u8 = 0x03;
pub(crate) const SBIO_IMAGE_INIT: u8 = 0x06;
pub(crate) const SBIO_IMAGE_ASSESS: u8 = 0x07;
pub(crate) const SBIO_ENROL_RESULT: u8 = 0x08;
pub(crate) const SBIO_BG_OPS: u8 = 0x22;
pub(crate) const SBIO_IMAGE_PREPARE: u8 = 0x23;
pub(crate) const SBIO_PROTECTED_CONFIG: u8 = 0x2b;
pub(crate) const SBIO_SELECT_CONTEXT: u8 = 0x2d;
pub(crate) const SBIO_CAPTURE: u8 = 0x65;
pub(crate) const SBIO_STAGE12: [u8; 10] = [
    SBIO_SELECT_CONTEXT, SBIO_PROTECTED_CONFIG, SBIO_BEGIN_ENROL, SBIO_IMAGE_PREPARE, SBIO_IMAGE_INIT, SBIO_CAPTURE,
    SBIO_IMAGE_ASSESS, SBIO_ENROL_RESULT, SBIO_BG_OPS, SBIO_CANCEL,
];
/// The packets 0x65's 0x7200 bytes take at 0x3FE4 a packet: the first and one more (next sequence 1); 3 bounds it.
pub(crate) const GT_NEXT_MAX: u64 = 3;

/// Stage 12 on, before the enrolment: the sensor's factory calibration, as biometrickitd hands it to the kext
/// (performSpecificCommandGated case 0x20 → setCalibrationData 0xfffffe0009ab9210): 0x5B {u32 the source, the
/// record}, the source 3 (FDR, the kext's names: 1 SysCfg, 2 EEPROM, 3 FDR, 4 Override, 5 File), then 0x63's info,
/// 0x1c bytes, the version at 0x10. 0x5B's refusals: 0x12e the signature, 0x12f the sensor's serial number.
pub(crate) const SBIO_LOAD_CALIBRATION: u8 = 0x5b;
/// A later reset's word to the SEP (resetSensor 0xfffffe0009ac0674): 0x80, the sensor's ID, goes once per boot
/// (+0x23a); every reset after the bring-up (the sensor's state not 0) sends 0x19, no data, in its place before the
/// identifiers and the key exchange again.
pub(crate) const SBIO_SENSOR_RESET: u8 = 0x19;
pub(crate) const SBIO_CALIBRATION_INFO: u8 = 0x63;
pub(crate) const CALIBRATION_FDR: u32 = 3;
pub(crate) const CALIBRATION_INFO_LEN: usize = 0x1c;
pub(crate) const CALIBRATION_BAD_SIGNATURE: u32 = 0x12e;
pub(crate) const CALIBRATION_BAD_SERIAL: u32 = 0x12f;
/// The record's largest size here (the FDR record `FSCl` is 0xfff8 bytes), and the packets 0x5B takes at 0x3FE4
/// a packet with its source: five, so next sequences 1-4.
pub(crate) const CALIBRATION_MAX: usize = 0x1_0000;
pub(crate) const GT_CAL_NEXT_MAX: u64 = 5;
static_assert!(((4 + CALIBRATION_MAX + 0x3fe3) / 0x3fe4) as u64 <= GT_CAL_NEXT_MAX);

/// Stage 13, the save (performSpecificCommandGated cases 0x3d, 0x3f, 0x4a): a component's sealed catacomb for the
/// host, the confirm once the host holds it durably, and the lockout record for the host.
pub(crate) const SBIO_SAVE_PREPARE: u8 = 0x6c;
pub(crate) const SBIO_SAVE_CONFIRM: u8 = 0x37;
pub(crate) const SBIO_LOCKOUT_SAVE: u8 = 0x70;
/// Stage 17, a delete (RemoveTemplate, the kext's performSpecificCommandGated case 0xD, rda `AppleMesaSEPDriver_272`
/// 0xfffffe0009ab3f94; biometrickitd's removeIdentity): {u32 uid, the identity's UUID}, no reply data, no credential;
/// then the save of the save-pending catacombs without the lockout record (touchid-lift.md §2).
pub(crate) const SBIO_REMOVE_TEMPLATE: u8 = 0x57;
pub(crate) const REMOVE_TEMPLATE_LEN: usize = 0x14;
pub(crate) const SBIO_SAVE: [u8; 4] = [SBIO_SAVE_PREPARE, SBIO_SAVE_CONFIRM, SBIO_LOCKOUT_SAVE, SBIO_REMOVE_TEMPLATE];
/// The largest record 27.2's transport takes (14.8.3's capped a transaction at 0x4b000): GT_MORE_MAX packets.
pub(crate) const SAVE_MAX: usize = 0x50_0000;
/// A component's state bits in 0x6b's reply: 2 active, 4 a save pending (10c and 10d: −1 and 501 at 0x3 after the
/// system context, the enrolling user at 0x7 after its enrolment; bit 0 not named, not checked in the kext).
pub(crate) const COMPONENT_ACTIVE: u32 = 2;
pub(crate) const COMPONENT_SAVE_PENDING: u32 = 4;
/// Bit 0: the SEP knows the component (biometrickitd's checkCatacombForUser: loads it when `state & 3 == 1`, known
/// and not loaded; rda BiometricSupport 27.2 0x238a26fc4, touchid-lift.md §3).
pub(crate) const COMPONENT_KNOWN: u32 = 1;

/// The SEP's own sbio request 1 (AppleMesaSEPDriver::handleSEPMessage case 1, rda `AppleMesaSEPDriver_272`
/// 0xfffffe0009abe2a8): a user's lock state in bytes 2-3, the uid in 4-7. biometrickitd's names: 0x1 DeviceLocked, 0x2
/// PasscodeLockout, 0x4 BioLockout, 0x8 UnlockTokenPresent, 0x10 BeforeFirstUnlock, 0x20 PasscodeValidated, 0x40
/// IdentificationLockout, 0x80 CatacombCorrupted. The kext refuses a match's images with 0x4 or 0x2 (status 0x53,
/// checkAutoMatchLockoutConditions): the SEP reports the lockout, the host enforces it (touchid-lift.md §2b).
pub(crate) const SEP_REQ_LOCK_STATE: u8 = 1;
pub(crate) const LOCK_PASSCODE: u16 = 0x2;
pub(crate) const LOCK_BIO: u16 = 0x4;
/// 0x09's status that ends a match (the kext's only special case; its meaning is not named).
pub(crate) const MATCH_STATUS_END: u32 = 0x56;

/// Stage 14, the load and the match (performSpecificCommandGated cases 0x40 and 0x4b, handleMatch): a saved catacomb
/// back to the SEP verbatim (its 0x20-byte catacomb_header_t names the user at 8), the lockout record verbatim, and
/// an unlock match's result, `match_info_t`.
pub(crate) const SBIO_LOAD_CATACOMB: u8 = 0x6d;
pub(crate) const SBIO_LOAD_LOCKOUT: u8 = 0x71;
pub(crate) const SBIO_MATCH_RESULT: u8 = 0x09;
/// A match's end, no data (AppleMesaSEPDriver_272 commandCancel in match mode, checkMatchStop).
pub(crate) const SBIO_MATCH_END: u8 = 0x0b;
/// The match policy, two bytes (`05 05` here, not named in any binary).
pub(crate) const SBIO_MATCH_POLICY: u8 = 0x1f;
/// A user's identities (case 0x42, its payload passed through: {u32 uid}): 20-byte records {u32 uid, the UUID},
/// what biometrickitd's syncTemplateListForUser: reads after each user's catacomb load and checks against the
/// identities it keeps beside the catacomb (rda `biometrickitd_272` `performGetIdentitiesListCommand:outBuffer:`
/// `0x10002282c`).
pub(crate) const SBIO_IDENTITIES_LIST: u8 = 0x6e;
pub(crate) const IDENTITY_LIST_REC: usize = 20;
/// With a match's end (0x0b) and its policy read again after each 0x09 (0x1f), as macOS's match sends them.
pub(crate) const SBIO_LOAD: [u8; 6] =
    [SBIO_LOAD_CATACOMB, SBIO_LOAD_LOCKOUT, SBIO_MATCH_RESULT, SBIO_IDENTITIES_LIST, SBIO_MATCH_END, SBIO_MATCH_POLICY];
pub(crate) const CATACOMB_HEADER: usize = 0x20;
/// 0x6d's answer 0x101, after which the component's state is read again: a second load of a component active after
/// a refusal answers it (build 46; Aurora's driver names it already active).
pub(crate) const LOAD_RECHECK: [u32; 1] = [0x101];

/// 0x6d's refusals: biometrickitd's performLoadCatacombCommand:inData: turns a status whose bits 1-15 are 0x4001
/// (0x8002, 0x8003) or 0x192 into its error 0x10D, which loadCatacombForComponent: reports as a corrupted catacomb
/// (rda `biometrickitd_272` `0x1000253c8`, `0x10002246c`, `catacombCorrupted:`) before it drops the file. The
/// component then shows active (0x3) and empty: 10e's builds 30-38 got 0x8002 for 501's and 1000's catacombs after
/// a reboot, the master's taking (0), and the SEP listed no identity after (0x7a, 0x6e).
pub(crate) fn load_refused(status: u32) -> bool {
    status >> 1 == 0x4001 || status == 0x192
}
pub(crate) const MATCH_RESULT_LEN: usize = 0xca2;
/// commandStartMatch's flags for a plain unlock match.
pub(crate) const MATCH_UNLOCK: u32 = 1;

/// 0x09's `match_info_t` (handleMatch): the matched identity at 0 (u32 the user, 0xffffffff for none, then its
/// 16-byte UUID), the retry-after-a-button-press flag at 0x14.
pub(crate) struct MatchResult {
    pub(crate) user: u32,
    pub(crate) uuid: [u8; 16],
    pub(crate) retry: u32,
}

pub(crate) fn parse_match(b: &[u8]) -> Option<MatchResult> {
    if b.len() != MATCH_RESULT_LEN {
        return None;
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&b[4..20]);
    Some(MatchResult { user: le32(b, 0), uuid, retry: le32(b, 0x14) })
}

/// 0x6c's and 0x37's input: userspace's cmd_prepare_save_catacomb_in_v2_t, the form the kext widens a v1 input
/// (the user alone) to: {u32 user, u32 0, 16 zero bytes}.
pub(crate) const fn save_selector(user: i32) -> [u8; 0x18] {
    let mut b = [0u8; 0x18];
    let u = user.to_le_bytes();
    b[0] = u[0];
    b[1] = u[1];
    b[2] = u[2];
    b[3] = u[3];
    b
}

/// 0x2d's user for the system context: the master catacomb's (case 0x31 then also selects the owner, 501).
pub(crate) const USER_SYSTEM: i32 = -1;
/// The owner the system context also selects, whose component 0x6b lists beside the master's.
pub(crate) const USER_OWNER: i32 = 501;

/// BEGIN_ENROL's data, `enroll_indata_v2_t` (0x44 bytes; userspace's `cmd_enroll_mode_in_v2_t` copied as it is,
/// performSpecificCommandGated case 3): u32 flags (commandStartEnroll keeps bit 0), u32 the user, u32 the
/// credential's kind (0, an ACM context), u32 its length, the 16-byte ACM handle; zeros after. The fields after
/// the flags are not read by the kext, which passes them through; the SEP took this layout (0x03 answered 0 in 10c
/// and 10d, build 28).
pub(crate) const BEGIN_ENROL_LEN: usize = 0x44;
pub(crate) fn begin_enrol(user: u32, acm: &[u8; ACM_HANDLE_LEN]) -> [u8; BEGIN_ENROL_LEN] {
    let mut b = [0u8; BEGIN_ENROL_LEN];
    b[4..8].copy_from_slice(&user.to_le_bytes());
    b[0xc..0x10].copy_from_slice(&(ACM_HANDLE_LEN as u32).to_le_bytes());
    b[0x10..0x10 + ACM_HANDLE_LEN].copy_from_slice(acm);
    b
}

/// 0x06's image-processing init as asyncCaptureHandler builds it for an enrolment image (0x97 bytes, nothing
/// appended: no match flag asks for the ACM or the identities' extension): u32 the match flags at 0 (0, the match
/// context cleared), u8 postpone at 4 and charger at 5 (0), u8 the touch's first image at 7 (+0x1bc4, the images
/// processed since the last finger detect, is 0), u8 the enrolment's last image at 8 (from the touch's fifth image
/// on) and the match's at 9, u8 1 at 0x13 (the command mode 3, an enrolment), u64 the capture's time in 24 MHz ticks
/// at 0x40, u32 the capture's counter in the touch at 0x48 (IOMesaCaptureDataLocal::getCaptureCounter, +0x1bbc),
/// u8 the wake-on-menu pin and the button at 0x4c and 0x4d (0), `biodevice_v1_t` at 0x4f {u32 1, the built-in
/// sensor; 16 zero bytes} (bioDeviceFromCaptureData 0xfffffe0009aca8b0), and u32 the match context's user at 0x67
/// (+0x1d00; 0xffffffff once cleared, clearMatchingContext 0xfffffe0009ace874).
pub(crate) const IMAGE_INIT_LEN: usize = 0x97;
/// BKOptionMatchForCredentialSet: the match puts its credential (type 3) into the ACM context given with it; the
/// kext refuses it together with flags 2 and 0x10 (commandStartMatch 0xfffffe0009ab7920).
pub(crate) const MATCH_CREDENTIAL_SET: u32 = 8;
/// 0x09's flag at 0x14 once that credential is in the context (CredentialAdded).
pub(crate) const MATCH_CREDENTIAL_ADDED: u32 = 0x40;
pub(crate) const IMAGE_INIT_CRED_LEN: usize = IMAGE_INIT_LEN + ACM_HANDLE_LEN;
/// As image_init_match for a match with MATCH_CREDENTIAL_SET: the ACM context's length at 0x93 and its bytes after
/// the struct, on every image of the match (asyncCaptureHandler 0xfffffe0009aac864).
pub(crate) fn image_init_match_cred(in_touch: u32, ticks: u64, user: u32, acm: &[u8; ACM_HANDLE_LEN]) -> [u8; IMAGE_INIT_CRED_LEN] {
    let mut b = [0u8; IMAGE_INIT_CRED_LEN];
    b[..IMAGE_INIT_LEN].copy_from_slice(&image_init_for(in_touch, ticks, Some((MATCH_CREDENTIAL_SET, user))));
    b[0x93..0x97].copy_from_slice(&(ACM_HANDLE_LEN as u32).to_le_bytes());
    b[IMAGE_INIT_LEN..].copy_from_slice(acm);
    b
}
pub(crate) fn image_init(in_touch: u32, ticks: u64) -> [u8; IMAGE_INIT_LEN] {
    image_init_for(in_touch, ticks, None)
}

/// As image_init, for a match (asyncCaptureHandler with commandStartMatch's match_init_v1_t): the match's flags at 0,
/// its user at 0x67, u8 1 at 0x12 (the command mode 2, a match) in place of the enrolment's at 0x13.
pub(crate) fn image_init_match(in_touch: u32, ticks: u64, flags: u32, user: u32) -> [u8; IMAGE_INIT_LEN] {
    image_init_for(in_touch, ticks, Some((flags, user)))
}

fn image_init_for(in_touch: u32, ticks: u64, matching: Option<(u32, u32)>) -> [u8; IMAGE_INIT_LEN] {
    let mut b = [0u8; IMAGE_INIT_LEN];
    b[7] = (in_touch == 0) as u8;
    b[8] = (in_touch >= 4) as u8;
    b[9] = (in_touch + 1 >= 5) as u8;
    b[0x12] = matching.is_some() as u8;
    b[0x13] = matching.is_none() as u8;
    b[0x40..0x48].copy_from_slice(&ticks.to_le_bytes());
    b[0x48..0x4c].copy_from_slice(&in_touch.to_le_bytes());
    b[0x4f..0x53].copy_from_slice(&1u32.to_le_bytes());
    let (flags, user) = matching.unwrap_or((0, u32::MAX));
    b[0..4].copy_from_slice(&flags.to_le_bytes());
    b[0x67..0x6b].copy_from_slice(&user.to_le_bytes());
    b
}

/// 0x07's `image_processing_result_v2` (asyncCaptureHandler's log line and checks): at least 0x89 bytes, and the
/// u32 at 0x85 more; u16 the error at 0, u32 the assessment at 2, u8 usable for a match at 6 and for the
/// enrolment at 7, u32 the feedback at 0xe and the purpose at 0x12, f32 the contrast, brightness and feature
/// strength at 0x18, 0x1c, 0x20, u32 the outlier pixels at 0x24, u8 dirt on the sensor at 0x40.
pub(crate) const ASSESS_MIN: usize = 0x89;
pub(crate) struct Assessment {
    pub(crate) err: u16,
    pub(crate) assessment: u32,
    pub(crate) for_match: u8,
    pub(crate) for_enrol: u8,
    pub(crate) feedback: u32,
    pub(crate) purpose: u32,
    pub(crate) outliers: u32,
    pub(crate) dirt: u8,
}

const fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

const fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

pub(crate) fn parse_assessment(b: &[u8]) -> Option<Assessment> {
    if b.len() < ASSESS_MIN || b.len() < ASSESS_MIN + le32(b, 0x85) as usize {
        return None;
    }
    Some(Assessment {
        err: le16(b, 0),
        assessment: le32(b, 2),
        for_match: b[6],
        for_enrol: b[7],
        feedback: le32(b, 0xe),
        purpose: le32(b, 0x12),
        outliers: le32(b, 0x24),
        dirt: b[0x40],
    })
}

/// 0x08's enrolment info, exactly 0xc98 bytes (handleEnrollment): u16 done at 0, u16 the error at 2 (0x56 also ends
/// it), u8 the progress at 4, u32 a valid node placement at 6 (the placement from 0xa), u32 a valid identity at
/// 0xbfe, the identity {u32 user, 16-byte UUID} at 0xc02.
pub(crate) const ENROL_RESULT_LEN: usize = 0xc98;
pub(crate) const ENROL_ERR_END: u16 = 0x56;
pub(crate) struct EnrolResult {
    pub(crate) done: u16,
    pub(crate) err: u16,
    pub(crate) progress: u8,
    pub(crate) placement: u32,
    pub(crate) identity: u32,
    pub(crate) user: u32,
}

pub(crate) fn parse_enrol_result(b: &[u8]) -> Option<EnrolResult> {
    if b.len() != ENROL_RESULT_LEN {
        return None;
    }
    Some(EnrolResult {
        done: le16(b, 0),
        err: le16(b, 2),
        progress: b[4],
        placement: le32(b, 6),
        identity: le32(b, 0xbfe),
        user: le32(b, 0xc02),
    })
}

/// Set at probe for stage 12: only then may stage 12's SBIO ops and 0x65's next packets go out (allowed).
pub(crate) static ENROL_ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Set at probe for stage 13: only then may the save's ops and 0x6c's and 0x70's next-packet requests go out.
pub(crate) static SAVE_ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Set at probe for stage 14: only then may the load's and the match's ops and 0x6d's and 0x71's next packets go out.
pub(crate) static LOAD_ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Set at probe for stage 9: stage 9's ops and the patch's next-packet requests may go out too (allowed).
pub(crate) static SBIO9_ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// scrd's request word: the endpoint, the request in byte 1, the host-written length in bytes 2-3.
pub(crate) const fn encode_scrd(request: u8, len: u16) -> Message {
    Word::new(EP_SCRD, request, len as u8, (len >> 8) as u8, 0).msg()
}

// scrd's INITIALIZE as 14.8.3 sent it (sep-1.log 1934), bit for bit
static_assert!(encode_scrd(1, 8).msg0 == 0x0008_010a);

/// 27.2's scrd INITIALIZE (AppleCredentialManager performSCRDInitialization 0xfffffe000933ff00, sendSEPCommand
/// 0xfffffe00093400e0, writeToSEPBuffer 0xfffffe00093420cc; not verified on the wire): request 4, an
/// SCRDRequestPayload_v1 {u8 1, u8 0, u16 0x1c, u32 the request ID, 20 zero bytes}, then the 8-byte command
/// {'DRCS', 0x0a, the log level 0x28, 0, 0}.
pub(crate) const SCRD_REQ_V1: u8 = 4;
pub(crate) const SCRD_INIT_LEN: u16 = 0x24;

/// The INITIALIZE request above: the payload header, then the command {'DRCS', INITIALIZE 0x0a, a log level, 0,
/// version 0}, as performSCRDInitialization stores it (the u64 0xA53435244, byte 5 the kext's own log level; 0x28 here,
/// taken at step 8).
pub(crate) const fn scrd_init_v1() -> [u8; SCRD_INIT_LEN as usize] {
    let mut b = [0u8; SCRD_INIT_LEN as usize];
    b[0] = 1;
    b[2] = 0x1c;
    b[4] = 1;
    b[0x1c] = b'D';
    b[0x1d] = b'R';
    b[0x1e] = b'C';
    b[0x1f] = b'S';
    b[0x20] = 0x0a;
    b[0x21] = 0x28;
    b
}

/// Stage 10, the enrolment's credential: ACM's commands as 27.2's kernel library builds them (rda
/// AppleCredentialManager_272 `LibCall_BuildCommand` 0xfffffe0009349f68: {'DRCS', the command, 0, 0, version 2}, then
/// the data) and `_performCommand` (0xfffffe000933f8cc) frames them: request 4, the 0x1c-byte SCRDRequestPayload_v1
/// {u8 1, u8 0, u16 0x1c, u32 the request ID, u32 0, u32 the caller, 12 zero bytes}. The caller is 0, as stage 8's
/// INITIALIZE (the kernel's own ACMKernelTransport passes 0xfffffffe, which the kext maps to a permission bit
/// 0x24's, 0x13's and 0x02's masks lack; how the sepOS maps it is not known). The data, as the engine's
/// ProcessRawCommand (0xfffffe00092e4d08) parses it: 0x24 a u32 uid (CreateCredentialSet 0xfffffe00092e638c); 0x13
/// and 0x02 the 16-byte handle (externalizeContextSerialized 0xfffffe00092e807c); 0x03 the handle, the policy's name
/// and its NUL, the preflight byte, a u32 maximum credential age and a u32 parameter count
/// (DeserializeVerifyPolicy 0xfffffe0009325c08, deserializeParameters 0xfffffe0009326074).
pub(crate) const SCRD_CMD_CONTEXT_DELETE: u8 = 0x02;
pub(crate) const SCRD_CMD_VERIFY_POLICY: u8 = 0x03;
pub(crate) const SCRD_CMD_EXTERNALIZE: u8 = 0x13;
pub(crate) const SCRD_CMD_CONTEXT_CREATE_TRACKED: u8 = 0x24;
pub(crate) const SCRD_CMD_VERSION: u8 = 2;
pub(crate) const SCRD_HEADER_V1: usize = 0x1c;
pub(crate) const ACM_HANDLE_LEN: usize = 16;
pub(crate) const POLICY_TOUCHID_ENROLLMENT: &[u8] = b"TouchIdEnrollment";
/// The reply's SCRDResponsePayloadHead (sendSEPCommand 0xfffffe00093400e0): u8 version (> 0), u8 an ack, u16 its own
/// length (0x20 on 27.2, stage 8), u32 the request ID; at least 0xc bytes. The command's output follows it.
pub(crate) const SCRD_REPLY_HEAD_MIN: usize = 0xc;

/// The data's length for each stage-10 command, as the engine requires it.
pub(crate) const fn scrd_cred_data_len(cmd: u8) -> Option<usize> {
    match cmd {
        SCRD_CMD_CONTEXT_CREATE_TRACKED => Some(4),
        SCRD_CMD_EXTERNALIZE | SCRD_CMD_CONTEXT_DELETE => Some(ACM_HANDLE_LEN),
        SCRD_CMD_VERIFY_POLICY => Some(ACM_HANDLE_LEN + POLICY_TOUCHID_ENROLLMENT.len() + 1 + 1 + 4 + 4),
        _ => None,
    }
}

/// One stage-10 request into `out`: the payload header, the command, the data. Its length, or None for a command
/// outside stage 10, data of another length or no room.
pub(crate) fn scrd_cred_request(id: u32, cmd: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
    if scrd_cred_data_len(cmd)? != data.len() {
        return None;
    }
    let n = SCRD_HEADER_V1 + 8 + data.len();
    let o = out.get_mut(..n)?;
    o.fill(0);
    o[0] = 1;
    o[2] = SCRD_HEADER_V1 as u8;
    o[4..8].copy_from_slice(&id.to_le_bytes());
    o[0x1c..0x20].copy_from_slice(b"DRCS");
    o[0x20] = cmd;
    o[0x23] = SCRD_CMD_VERSION;
    o[0x24..].copy_from_slice(data);
    Some(n)
}

/// The policy check's data: the handle, "TouchIdEnrollment" and its NUL, preflight 0, no maximum age, no parameters.
pub(crate) fn scrd_policy_data(handle: &[u8; ACM_HANDLE_LEN]) -> [u8; ACM_HANDLE_LEN + 18 + 9] {
    let mut d = [0u8; ACM_HANDLE_LEN + 18 + 9];
    d[..ACM_HANDLE_LEN].copy_from_slice(handle);
    d[ACM_HANDLE_LEN..ACM_HANDLE_LEN + POLICY_TOUCHID_ENROLLMENT.len()].copy_from_slice(POLICY_TOUCHID_ENROLLMENT);
    d
}

static_assert!(scrd_cred_data_len(SCRD_CMD_VERIFY_POLICY).unwrap() == ACM_HANDLE_LEN + 18 + 9);

/// Set at probe for stage 10: only then may the credential's four scrd commands and the key store's verify-secret
/// go out (allowed, sks::request_allowed).
pub(crate) static CRED_ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

static_assert!(encode_gt(GT_POWER).msg0 == 0x0f_fc18);

/// A single-packet transaction: the header (u32s: version 1, the total length, the offset 0, the flags, 0, the
/// command, this packet's length) and the data.
pub(crate) fn gt_packet(command: u8, flags: u32, data: &[u8], out: &mut [u8]) -> Option<usize> {
    gt_packet_at(command, flags, data.len(), 0, data, out)
}

/// Set at probe for stage 8: only then may scrd's and sbio's enables, stage 8's SBIO queries and scrd's
/// INITIALIZE go out (allowed).
pub(crate) static SBIO_ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The only messages steps 2 and 3 may send: the registration (from probe, once), and the control endpoint's
/// out-of-line size and address ops for hdcp, xarm and stac and the security-mode request. Nothing else
/// reaches the mailbox (`SepData::send`): no boot or reset message (endpoint 0xFF), no reply to the SEP's
/// requests (xarm, nap), no message to an app's own endpoint. Step 3 adds hdcp's ops 0x27 and 0x28, stac's power-on,
/// and replies on xarm's endpoint with the three statuses it answers with (`SepData::serve_xarm` sends them, each
/// to a request the SEP made). Step 6 adds sks's size and address ops and the key store's three start-up requests
/// (sks::request_allowed); nothing answers the key store's own messages.
pub(crate) fn allowed(msg: &Message) -> bool {
    let f = Word::of(msg);
    if msg.msg1 != 0 {
        return false;
    }
    match f.ep {
        EP_SHMEM => f.tag == 0 && f.param == 0 && f.op != 0,
        EP_CONTROL => match f.op {
            OP_OOL_IN_ADDR | OP_OOL_OUT_ADDR | OP_OOL_IN_SIZE | OP_OOL_OUT_SIZE => {
                matches!(f.param, EP_HDCP | EP_XARM | EP_STAC | EP_SKS)
                    || (SBIO_ARMED.load(core::sync::atomic::Ordering::Relaxed) && matches!(f.param, EP_SBIO | EP_SCRD))
            }
            OP_SECMODE => f.param == 0 && f.data == 0,
            OP_ENTROPY => f.param == 0 && f.data == 0,
            _ => false,
        },
        EP_HDCP => {
            f.op == 0
                && f.data == 0
                && match f.tag {
                    HDCP_OP_COUNT => f.param == 0,
                    HDCP_OP_LAUNCH => u32::from(f.param) < HDCP_MAX_INTERFACES,
                    _ => false,
                }
        }
        EP_STAC => msg.msg0 == encode_gt(GT_POWER).msg0,
        EP_SBIO => {
            let nine = SBIO9_ARMED.load(core::sync::atomic::Ordering::Relaxed);
            (SBIO_ARMED.load(core::sync::atomic::Ordering::Relaxed)
                && SBIO_STAGE8.iter().any(|&op| msg.msg0 == encode_gt_ep(EP_SBIO, op).msg0))
                || (nine && SBIO_STAGE9.iter().any(|&op| msg.msg0 == encode_gt_ep(EP_SBIO, op).msg0))
                || (nine
                    && (msg.msg0 & 0xffff_ffff) == encode_gt_more(EP_SBIO, SBIO_MULTI_OP, 0).msg0
                    && (msg.msg0 >> 32) & 0xffff == 0
                    && (msg.msg0 >> 48) < GT_MORE_MAX)
                || (ENROL_ARMED.load(core::sync::atomic::Ordering::Relaxed)
                    && (SBIO_STAGE12.iter().any(|&op| msg.msg0 == encode_gt_ep(EP_SBIO, op).msg0)
                        || msg.msg0 == encode_gt_ep(EP_SBIO, SBIO_LOAD_CALIBRATION).msg0
                        || msg.msg0 == encode_gt_ep(EP_SBIO, SBIO_SENSOR_RESET).msg0
                        || ((msg.msg0 & 0xffff_ffff) == encode_gt_next(EP_SBIO, SBIO_CAPTURE, 0).msg0
                            && (msg.msg0 >> 32) & 0xffff == 0
                            && (1..GT_NEXT_MAX).contains(&(msg.msg0 >> 48)))
                        || ((msg.msg0 & 0xffff_ffff) == encode_gt_next(EP_SBIO, SBIO_LOAD_CALIBRATION, 0).msg0
                            && (msg.msg0 >> 32) & 0xffff == 0
                            && (1..GT_CAL_NEXT_MAX).contains(&(msg.msg0 >> 48)))))
                || (SAVE_ARMED.load(core::sync::atomic::Ordering::Relaxed)
                    && (SBIO_SAVE.iter().any(|&op| msg.msg0 == encode_gt_ep(EP_SBIO, op).msg0)
                        || ([SBIO_SAVE_PREPARE, SBIO_LOCKOUT_SAVE]
                            .iter()
                            .any(|&op| (msg.msg0 & 0xffff_ffff) == encode_gt_more(EP_SBIO, op, 0).msg0)
                            && (msg.msg0 >> 32) & 0xffff == 0
                            && (msg.msg0 >> 48) < GT_MORE_MAX)))
                || (LOAD_ARMED.load(core::sync::atomic::Ordering::Relaxed)
                    && (SBIO_LOAD.iter().any(|&op| msg.msg0 == encode_gt_ep(EP_SBIO, op).msg0)
                        || ([SBIO_LOAD_CATACOMB, SBIO_LOAD_LOCKOUT]
                            .iter()
                            .any(|&op| (msg.msg0 & 0xffff_ffff) == encode_gt_next(EP_SBIO, op, 0).msg0)
                            && (msg.msg0 >> 32) & 0xffff == 0
                            && (1..GT_MORE_MAX).contains(&(msg.msg0 >> 48)))))
        }
        EP_SCRD => {
            let cred = CRED_ARMED.load(core::sync::atomic::Ordering::Relaxed)
                && [SCRD_CMD_CONTEXT_CREATE_TRACKED, SCRD_CMD_EXTERNALIZE, SCRD_CMD_VERIFY_POLICY, SCRD_CMD_CONTEXT_DELETE]
                    .iter()
                    .filter_map(|&c| scrd_cred_data_len(c))
                    .any(|n| msg.msg0 == encode_scrd(SCRD_REQ_V1, (SCRD_HEADER_V1 + 8 + n) as u16).msg0);
            (SBIO_ARMED.load(core::sync::atomic::Ordering::Relaxed)
                && msg.msg0 == encode_scrd(SCRD_REQ_V1, SCRD_INIT_LEN).msg0)
                || cred
        }
        EP_SKS => crate::sks::request_allowed(msg),
        EP_XARM => matches!(
            f.op,
            crate::xarm::STATUS_OK | crate::xarm::STATUS_NO_UUID | crate::xarm::STATUS_UNKNOWN_OP
        ),
        _ => false,
    }
}
