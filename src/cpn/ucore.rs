//! Depict MicroCore
//! I.e. kind of embedded processor that Handle IOp/DOp translation

use ra2m::prelude::{
    protocol::{addr::Addr, dma::DmaBus, membus::MemBus},
    *,
};
use tfhe::tfhe_hpu_backend::{asm::ToHex, prelude::*};

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use super::DOpPayload;

/// UCore parameters
#[derive(Debug, Clone)]
pub struct UCoreParams {
    pub node_id: u8,
    pub fw_pc: MemKind,

    /// Ciphertext memory
    /// Expressed the number of ciphertext slot to allocate
    pub ct_mem: usize,

    pub axis_depth: usize,
    pub polling_rate: unit::Time,

    pub iopq: QueueConfig,
    pub ackq: QueueConfig,
}

/// Store internal state of UCore module
struct UCoreInner {
    iop_stream: VecDeque<hpu_asm::iop::IOpWordRepr>,
    // TODO
}

impl UCoreInner {
    pub fn new() -> Self {
        Self {
            iop_stream: VecDeque::new(),
        }
    }
}

#[derive(Module)]
pub struct UCore {
    params: UCoreParams,
    props: Arc<module::Properties>,

    /// Membus to access associated on-board memory
    #[port]
    mem: port::ReqRespPort<MemBus>,
    /// Half-duplex port to issue request to Hpu
    #[port]
    hpu_req: port::MasterPort<DOpPayload>,
    /// Half-duplex port to received ack from Hpu
    #[port]
    hpu_ack: port::SlavePort<DOpPayload>,
    /// dma: Issue Dma request for interboard communication
    #[port]
    dma: port::ReqRespPort<DmaBus<(u8, Addr)>>,

    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    inner: Mutex<UCoreInner>,
}

#[default_teardown]
impl UCore {
    pub fn new(params: UCoreParams, props: module::Properties) -> Self {
        let props = Arc::new(props);

        Self {
            mem: port::ReqRespPort::new("mem", props.clone(), Some(1), None),
            hpu_req: port::MasterPort::new("hpu_req", props.clone(), Some(params.axis_depth), None),
            hpu_ack: port::SlavePort::new("hpu_ack", props.clone(), Some(params.axis_depth), None),
            dma: port::ReqRespPort::new("dma", props.clone(), Some(1), None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(UCoreInner::new()),
            params,
            props,
        }
    }

    #[init]
    fn _init(self: Arc<Self>) {
        let mut prc = self.prc.lock().unwrap();
        let asc = self.clone();
        prc.push(spawn_prc!(Self::iopq_flush(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::hpu_feed(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::ackq_flush(asc)));
    }
}

/// Implement a set of runtime task executed by Ucore
impl UCore {
    /// This function poll iopq in memory and buffered value in iop_stream
    async fn iopq_flush(self: Arc<Self>) {
        let QueueConfig {
            head_ofst,
            tail_ofst,
            data_ofst,
            size_w,
            mem,
        } = &self.params.iopq;
        let base_addr = match mem {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { .. } => {
                panic!("Queue must be in DDR, it's currently the only way to have predictive addr")
            }
        };

        loop {
            delay::Delay::wait_for(self.params.polling_rate.into()).await;

            let iop_head = {
                let mut iop_head = 0_u32;
                self.mem
                    .read(self.properties(), base_addr + *head_ofst, &mut iop_head)
                    .await
                    .expect("Error while reading Iopq head");
                iop_head
            };

            let iop_tail = {
                let mut iop_tail = 0_u32;
                self.mem
                    .read(self.properties(), base_addr + *tail_ofst, &mut iop_tail)
                    .await
                    .expect("Error while reading Iopq head");
                iop_tail
            };

            let word_avail = (iop_head - iop_tail) % *size_w as u32;
            let bytes_avail = word_avail as usize * std::mem::size_of::<u32>();
            let chunk_start = base_addr
                + *data_ofst
                + ((iop_tail as usize % *size_w) * std::mem::size_of::<u32>() as usize);
            if word_avail != 0 {
                // Read body
                let data_u8 = self
                    .mem
                    .read_bytes(self.properties(), chunk_start, bytes_avail)
                    .await
                    .expect("Error while reading Iopq body");
                let data_u32 = bytemuck::cast_slice::<u8, u32>(&data_u8);

                // append to inner deque buffer
                self.inner
                    .lock()
                    .unwrap()
                    .iop_stream
                    .extend(data_u32.iter());

                // Ack for value consumption
                self.mem
                    .write(self.properties(), base_addr + *tail_ofst, &iop_head)
                    .await
                    .expect("Error while writing Iopq tail");
            }
        }
    }

    async fn ackq_flush(self: Arc<Self>) {
        let QueueConfig {
            head_ofst,
            tail_ofst,
            data_ofst,
            size_w,
            mem,
        } = &self.params.ackq;
        let base_addr = match mem {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { pc } => {
                panic!("Queue must be in DDR, it's currently the only way to have predictive addr")
            }
        };

        loop {
            // Check for room in the ack queue

            let iop_head = {
                let mut iop_head = 0_u32;
                self.mem
                    .read(self.properties(), base_addr + *head_ofst, &mut iop_head)
                    .await
                    .expect("Error while reading Ackq head");
                iop_head
            };

            let iop_tail = {
                let mut iop_tail = 0_u32;
                self.mem
                    .read(self.properties(), base_addr + *tail_ofst, &mut iop_tail)
                    .await
                    .expect("Error while reading Ackq head");
                iop_tail
            };

            let word_free = *size_w as u32 - ((iop_head - iop_tail) % *size_w as u32);
            let chunk_start = base_addr
                + *data_ofst
                + ((iop_head as usize % *size_w) * std::mem::size_of::<u32>() as usize);
            if word_free != 0 {
                let dop = self
                    .hpu_ack
                    .wait_pkt_ep(None)
                    .await
                    .expect("Issue with DOpPayload xfer")
                    .unwrap_payload();
                let dop_hex = dop.inner.to_hex();

                // write body
                self.mem
                    .write(self.properties(), chunk_start, &dop_hex)
                    .await
                    .expect("Error while reading Ackq body");

                // Ack for value insertion
                self.mem
                    .write(self.properties(), base_addr + *head_ofst, &(iop_head + 1))
                    .await
                    .expect("Error while writing Iopq tail");
            } else {
                log!(|self| log::Category::Own, log::Verbosity::Info => => "Ackq is full");
            }
        }
    }

    async fn hpu_feed(self: Arc<Self>) {
        loop {
            // Extract one Iop from stream
            let iop_pdg = {
                let iop_stream = &mut self.inner.lock().unwrap().iop_stream;
                match hpu_asm::IOp::from_words(iop_stream) {
                    Err(_) => {
                        // not enough data to match
                        None
                    }
                    Ok(iop) => Some(iop),
                }
            };

            if let Some(iop) = iop_pdg {
                log!(|self| log::Category::Own, log::Verbosity::Debug => iop => "Will process following iop");

                // Retrived DOp stream from memory
                let dops = self.load_fw(self.params.node_id, &iop).await;
                // Patch DOps
                let dops_patched = self.patch_fw(self.params.node_id, &iop, &dops);

                // Wrapped DOp in packet and send them to HpuCore
                let dop_pkt = dops_patched
                    .into_iter()
                    .map(|dop| Packet::wrap_payload(DOpPayload::new(dop), Default::default()))
                    .collect::<Vec<_>>();
                self.hpu_req.fwd_pkt_burst(dop_pkt).await;
            } else {
                delay::Delay::wait_for(self.params.polling_rate.into()).await;
            }
        }
    }
}

/// Implement a set of utility functions
/// Mainly extracted from the mockup
impl UCore {
    /// Convert words offset/addr/size in bytes
    fn words_to_bytes<W>(words: usize) -> usize {
        words * std::mem::size_of::<W>()
    }

    /// Convert bytes offset/addr/size in words
    fn bytes_to_words<W>(words: usize) -> usize {
        words / std::mem::size_of::<W>()
    }

    /// Read DOp stream from Firmware memory
    async fn load_fw(&self, hpu_id: u8, iop: &hpu_asm::IOp) -> Vec<hpu_asm::DOp> {
        let fw_base_addr = match self.params.fw_pc {
            // TODO swap with global addr space (i.e. all cpn behind same xbar to prevent such gym)
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { .. } => {
                panic!("Ucore can't access HBM. Fw translation table must be stored in DDR");
            }
        };

        let dop_ofst = {
            let mut val = 0_u32;
            self.mem
                .read(
                    self.properties(),
                    fw_base_addr + Self::words_to_bytes::<u32>(iop.fw_entry(hpu_id)),
                    &mut val,
                )
                .await
                .expect("Error while reading Iopq body");
            val as usize
        };
        let dop_len = {
            let mut val = 0_u32;
            self.mem
                .read(
                    self.properties(),
                    fw_base_addr + dop_ofst as usize,
                    &mut val,
                )
                .await
                .expect("Error while reading fw");
            Self::words_to_bytes::<u32>(val as usize)
        };
        let dop_stream_u8 = self
            .mem
            .read_bytes(
                self.properties(),
                fw_base_addr + dop_ofst + std::mem::size_of::<u32>(),
                dop_len,
            )
            .await
            .expect("Error while reading fw");
        let dop_stream_u32 = bytemuck::cast_slice::<u8, u32>(&dop_stream_u8);

        // Parse DOp stream
        dop_stream_u32
            .iter()
            .map(|bin| hpu_asm::DOp::from_hex(*bin).expect("Invalid DOp"))
            .collect::<Vec<hpu_asm::DOp>>()
    }

    /// Rtl ucore emulation
    /// Map a Raw DOp stream to the given IOp operands
    /// I.e. it replace Templated MemId with concrete one
    fn patch_fw(&self, hpu_id: u8, iop: &hpu_asm::IOp, dops: &[hpu_asm::DOp]) -> Vec<hpu_asm::DOp> {
        let mut dops_patch = dops
            .iter()
            .map(|dop| {
                let mut dop_patch = dop.clone();
                match &mut dop_patch {
                    // LD/ST patching
                    // Do MemId template resolution
                    hpu_asm::DOp::LD(hpu_asm::dop::DOpLd(inner))
                    | hpu_asm::DOp::ST(hpu_asm::dop::DOpSt(inner)) => {
                        let slot = match inner.slot {
                            hpu_asm::MemId::Heap { bid } => hpu_asm::MemId::Addr(hpu_asm::CtId(
                                (self.params.ct_mem - 1) as u16 - bid,
                            )),
                            hpu_asm::MemId::Src { tid, bid } => {
                                let operand = iop.src()[tid as usize];
                                hpu_asm::MemId::Addr(hpu_asm::CtId(
                                    operand.addr.base_cid.0 + bid as u16,
                                ))
                            }
                            hpu_asm::MemId::Dst { tid, bid } => {
                                let operand = iop.dst()[tid as usize];
                                hpu_asm::MemId::Addr(hpu_asm::CtId(
                                    operand.addr.base_cid.0 + bid as u16,
                                ))
                            }
                            hpu_asm::MemId::Addr(ct_id) => hpu_asm::MemId::Addr(ct_id),
                        };
                        dop_patch
                    }
                    // Immediat patching
                    hpu_asm::DOp::ADDS(hpu_asm::dop::DOpAdds(inner))
                    | hpu_asm::DOp::SUBS(hpu_asm::dop::DOpSubs(inner))
                    | hpu_asm::DOp::SSUB(hpu_asm::dop::DOpSsub(inner))
                    | hpu_asm::DOp::MULS(hpu_asm::dop::DOpMuls(inner)) => {
                        patch_imm(iop, &mut inner.msg_cst);
                        dop_patch
                    }

                    // Patch Ucore
                    // Do Virtual/Physical Id translation
                    // Do MemId template resolution
                    // NB: Since Ucore complex DOp are handle by ucore directly, they are patched on the flight
                    hpu_asm::DOp::SYNC(hpu_asm::dop::DOpSync(inner))
                    | hpu_asm::DOp::WAIT(hpu_asm::dop::DOpWait(inner))
                    | hpu_asm::DOp::LD_B2B(hpu_asm::dop::DOpLdB2B(inner)) => {
                        //1.  Do virtual to physical Id mapping
                        inner.hid = iop.phys_id(inner.hid).expect(
                            "Invalid IOp mapping. DOp stream contains an unavailable Hpu TargetId",
                        ).into();

                        todo!("Implement LD_B2B");
                        // //2.  Do template patching
                        // inner.slot = match inner.slot {
                        //     hpu_asm::MemId::Heap { bid } =>
                        //     panic!("Error: B2B couldn't use Heap template. Local Hpu hasn't access to distant Heap managament"),
                        //     hpu_asm::MemId::Src { tid, bid } => {
                        //         let operand = iop.src()[tid as usize];
                        //         let tid = hpu_asm::TargetId(operand.pos.0);
                        //         let slot = hpu_asm::MemId::Addr(hpu_asm::CtId(
                        //             operand.base_cid.0 + bid as u16,
                        //         ));
                        //         (tid, slot)
                        //     }
                        //     hpu_asm::MemId::Dst { tid, bid } => {
                        //         let operand = iop.dst()[tid as usize];
                        //         let tid = hpu_asm::TargetId(operand.pos.0);
                        //         let slot = hpu_asm::MemId::Addr(hpu_asm::CtId(
                        //             operand.base_cid.0 + bid as u16,
                        //         ));
                        //         (tid, slot)
                        //     }
                        //     hpu_asm::MemId::Addr(ct_id) => (inner.tid, hpu_asm::MemId::Addr(ct_id)),
                        // };
                        //
                        dop_patch
                    }
                    _ => dop_patch,
                }
            })
            .collect::<Vec<_>>();

        // Ucore is in charge of Sync insertion
        // TODO check format of inserted DOp
        // TODO rework Ctor (split usual host sync from B2B sync ?)
        dops_patch.push(
            hpu_asm::dop::DOpSync::new(
                hpu_asm::TargetId(0),
                hpu_asm::dop::TagId(0),
                hpu_asm::dop::IOpMode::from(0),
            )
            .into(),
        );
        log!(|self| log::Category::Own, log::Verbosity::Trace => dops_patch => "Patch DOp stream");
        dops_patch
    }
}

/// Utility function to patch immediat argument
fn patch_imm(iop: &hpu_asm::IOp, imm: &mut hpu_asm::ImmId) {
    *imm = match imm {
        hpu_asm::ImmId::Cst(val) => hpu_asm::ImmId::Cst(*val),
        hpu_asm::ImmId::Var { tid, bid } => {
            hpu_asm::ImmId::Cst(iop.imm()[*tid as usize].msg_block(*bid))
        }
    }
}
