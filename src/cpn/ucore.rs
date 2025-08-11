//! Depict MicroCore
//! I.e. kind of embedded processor that Handle IOp/DOp translation

use ra2m::prelude::{
    protocol::{dma::DmaBus, membus::MemBus},
    *,
};
use tfhe::tfhe_hpu_backend::{asm::ToHex, prelude::*};

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// Queue properties
/// Describe queue in memory. Position of head/tail and data.
/// Word size and number of them
#[derive(Debug, Clone)]
pub struct QueueProperties {
    pub head: usize,
    pub tail: usize,
    pub data: usize,
    pub size: usize,
}

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

    pub iopq: QueueProperties,
    pub ackq: QueueProperties,
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
    hpu_req: port::MasterPort<hpu_asm::DOp>,
    /// Half-duplex port to received ack from Hpu
    #[port]
    hpu_ack: port::SlavePort<hpu_asm::DOp>,
    /// dma: Issue Dma request for interboard communication
    #[port]
    dma: port::ReqRespPort<DmaBus>,

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
        // First of all drop the addr_range request
        self.mem.discard_addr_range().await;

        let QueueProperties {
            head,
            tail,
            data,
            size,
        } = &self.params.iopq;

        loop {
            delay::Delay::wait_for(self.params.polling_rate.into()).await;

            let iop_head = {
                let mut iop_head = 0_u32;
                self.mem
                    .read(self.properties(), *head, &mut iop_head)
                    .await
                    .expect("Error while reading Iopq head");
                iop_head
            };

            let iop_tail = {
                let mut iop_tail = 0_u32;
                self.mem
                    .read(self.properties(), *tail, &mut iop_tail)
                    .await
                    .expect("Error while reading Iopq head");
                iop_tail
            };

            let word_avail = (iop_head - iop_tail) % *size as u32;
            let bytes_avail = word_avail as usize * std::mem::size_of::<u32>();
            let chunk_start =
                *data + ((iop_tail as usize % *size) * std::mem::size_of::<u32>() as usize);
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
                    .write(self.properties(), *tail, &iop_head)
                    .await
                    .expect("Error while writing Iopq tail");
            }
        }
    }

    async fn ackq_flush(self: Arc<Self>) {
        let QueueProperties {
            head,
            tail,
            data,
            size,
        } = &self.params.ackq;

        loop {
            // Check for room in the ack queue

            let iop_head = {
                let mut iop_head = 0_u32;
                self.mem
                    .read(self.properties(), *head, &mut iop_head)
                    .await
                    .expect("Error while reading Ackq head");
                iop_head
            };

            let iop_tail = {
                let mut iop_tail = 0_u32;
                self.mem
                    .read(self.properties(), *tail, &mut iop_tail)
                    .await
                    .expect("Error while reading Ackq head");
                iop_tail
            };

            let word_free = *size as u32 - ((iop_head - iop_tail) % *size as u32);
            let chunk_start =
                *data + ((iop_head as usize % *size) * std::mem::size_of::<u32>() as usize);
            if word_free != 0 {
                // NB: Should use the wait_pkt_ep version but DOp don't implement the RxStatus
                let dop = self.hpu_ack.wait_pkt().await.unwrap_payload();
                let dop_hex = dop.to_hex();

                // write body
                self.mem
                    .write(self.properties(), chunk_start, &dop_hex)
                    .await
                    .expect("Error while reading Ackq body");

                // Ack for value insertion
                self.mem
                    .write(self.properties(), *head, &(iop_head + 1))
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
                let mut dop_pkt = dops_patched
                    .into_iter()
                    .map(|dop| Packet::wrap_payload(dop, Default::default()))
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
    /// Read DOp stream from Firmware memory
    async fn load_fw(&self, hpu_id: u8, iop: &hpu_asm::IOp) -> Vec<hpu_asm::DOp> {
        let fw_base_addr = match self.params.fw_pc {
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
                    fw_base_addr + iop.fw_entry(hpu_id),
                    &mut val,
                )
                .await;
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
                .await;
            val as usize
        };
        let dop_stream_u8 = self
            .mem
            .read_bytes(self.properties(), dop_ofst + 1, dop_len)
            .await
            .expect("Error while reading Iopq body");
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
        // Sync on host(i.e. pos 0) -> trgt 1
        todo!("Handle Sync insertion");
        // dops_patch.push(hpu_asm::dop::DOpSync::new(hpu_asm::dop::HpuId(1), None).into());
        // tracing::trace!("Patch DOp stream => {dops_patch:?}");
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
