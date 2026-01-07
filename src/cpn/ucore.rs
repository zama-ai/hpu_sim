//! Depict MicroCore
//! I.e. kind of embedded processor that Handle IOp/DOp translation

use ra2m::prelude::{
    protocol::{
        addr::{Addr, Pattern},
        dma::DmaBus,
        membus::MemBus,
        network::Network,
    },
    *,
};
use tfhe::tfhe_hpu_backend::prelude::*;

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use super::{DOpPayload, IOpPayload};

/// UCore parameters
#[derive(Debug, Clone)]
pub struct UCoreParams {
    pub cluster_nodes: Vec<u8>,
    pub fw_pc: MemKind,

    /// Ciphertext memory
    /// Expressed the number of ciphertext slot to allocate
    pub ct_pc: Vec<MemKind>,
    pub ct_user: usize,
    pub ct_b2b: usize,
    pub ct_heap: usize,

    pub axis_depth: usize,
    pub polling_rate: unit::Time,

    pub iopq: QueueConfig,
    pub ackq: QueueConfig,

    /// rtl_params for Dma xfer size computation
    // TODO Replace this by read in regmap ?!
    pub rtl_params: HpuParameters,

    // Hbm global offset for Dma xfer addr computation
    pub hbm_global_ofst: usize,
    // Hbm pc offset for Dma xfer addr computation
    pub hbm_pc_ofst: usize,
}

/// Store internal state of UCore module
struct UCoreInner {
    config: UcoreConfig,
    iop_stream: VecDeque<hpu_asm::iop::IOpWordRepr>,
    iop_pdg: VecDeque<hpu_asm::IOp>,
    event_list: HashMap<UcoreHash, Event>,
    b2b_pool: B2bPool,
    dst_ldq: Vec<DstLdOrder>,
    // Use to detect restart on the user side (i.e. start of a new application)
    cur_iid: hpu_asm::IOpId,
}

impl UCoreInner {
    pub fn new() -> Self {
        Self {
            config: UcoreConfig::new(Default::default()),
            iop_stream: VecDeque::new(),
            iop_pdg: VecDeque::new(),
            event_list: HashMap::new(),
            b2b_pool: B2bPool::new(),
            dst_ldq: Vec::new(),
            cur_iid: hpu_asm::SW_IOP_ID,
        }
    }
}

/// UcoreHash
/// Use for unique Ucore event identification
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Hash)]
pub enum UcoreHash {
    Ucore {
        iid: hpu_asm::IOpId,
        flag: hpu_asm::UcoreFlag,
    },
    User {
        iid: hpu_asm::IOpId,
        flag: hpu_asm::UserFlag,
    },
}

#[derive(Debug)]
enum LdAction {
    Notify(hpu_asm::CtId),
    Read,
}

/// Keep track of Destination slot action
/// Indeed, owner of the destination is responsible of retrieving value at the end of exection
/// Nb: We use deferred read instead of deferred write to ease Rtl buffer manager in DMA
#[derive(Debug)]
struct DstLdOrder {
    iid: hpu_asm::IOpId,
    operand: hpu_asm::Operand,
    cid: hpu_asm::CtId,
    action: LdAction,
}

struct B2bPool {
    free: Vec<hpu_asm::CtId>,
    used_lifetime: HashMap<hpu_asm::IOpId, Vec<hpu_asm::CtId>>,
}

impl B2bPool {
    fn new() -> Self {
        Self {
            free: Vec::new(),
            used_lifetime: HashMap::new(),
        }
    }
    fn add_slot(&mut self, slots: &[hpu_asm::CtId]) {
        self.free.extend_from_slice(slots);
    }

    fn get_tagged(&mut self, iid: hpu_asm::IOpId) -> hpu_asm::CtId {
        let cid = self
            .free
            .pop()
            .expect("B2bPool is empty, check you local variable usage");
        if let Some(vec) = self.used_lifetime.get_mut(&iid) {
            vec.push(cid);
        } else {
            self.used_lifetime.insert(iid, vec![cid]);
        }
        cid
    }

    fn release_tagged(&mut self, iid: hpu_asm::IOpId) {
        if let Some(used) = self.used_lifetime.remove(&iid) {
            self.free.extend_from_slice(&used);
        }
    }

    fn release_all(&mut self) {
        for (_, slot) in self.used_lifetime.iter_mut() {
            self.free.append(slot)
        }
    }
}

/// Event states and associated data
#[derive(Debug, Clone)]
enum Event {
    Received(hpu_asm::UcorePayload),
    Resolved(hpu_asm::MemId),
}

#[derive(Module)]
pub struct UCore {
    params: UCoreParams,
    props: Arc<module::Properties>,

    /// Membus to access associated on-board memory
    #[port]
    mem: port::ReqRespPort<MemBus>,

    // Interface with HpuCore
    // Slighly different from RTL, indeed iop_ctx is furnished for better context in logging
    /// Half-duplex port to issue request to HpuCore
    #[port]
    hpu_ctx: port::MasterPort<IOpPayload>,
    #[port]
    hpu_req: port::MasterPort<DOpPayload>,
    /// Half-duplex port to received ack from HpuCore
    #[port]
    hpu_ack: port::SlavePort<IOpPayload>,

    /// Ctrl: Issue/Received control token for interboard synchronisation
    #[port]
    ctrl: port::ReqRespPort<Network<u8, hpu_asm::UcorePayload>>,

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

        let mut inner = UCoreInner::new();
        // Populate b2b_pool
        // Memory layout is as follow:
        // * user [used downward]
        // * b2b  [used downward]
        // * heap [used upward]
        let b2b_slot = (0..params.ct_b2b)
            .map(|i| hpu_asm::CtId((params.ct_user + i) as u16))
            .collect::<Vec<_>>();
        inner.b2b_pool.add_slot(&b2b_slot);

        Self {
            mem: port::ReqRespPort::new("mem", props.clone(), Some(1), None),
            hpu_ctx: port::MasterPort::new("hpu_ctx", props.clone(), Some(params.axis_depth), None),
            hpu_req: port::MasterPort::new("hpu_req", props.clone(), Some(params.axis_depth), None),
            hpu_ack: port::SlavePort::new("hpu_ack", props.clone(), Some(params.axis_depth), None),
            ctrl: port::ReqRespPort::new("ctrl", props.clone(), None, None),
            dma: port::ReqRespPort::new("dma", props.clone(), Some(1), None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(inner),
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

        // Handle sync payload
        let asc = self.clone();
        prc.push(spawn_prc!(Self::ctrl_flush(asc)));
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
                + ((iop_tail as usize % *size_w) * std::mem::size_of::<u32>());
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
            MemKind::Hbm { .. } => {
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
                + ((iop_head as usize % *size_w) * std::mem::size_of::<u32>());
            if word_free != 0 {
                let iop_pld = self
                    .hpu_ack
                    .wait_pkt_ep(None)
                    .await
                    .expect("Issue with DOpPayload xfer")
                    .unwrap_payload();

                // Generate execution report
                self.dump_iop_report(&iop_pld);

                let (hid, iop) = {
                    let mut inner = self.inner.lock().unwrap();
                    let hid = inner.config.node_id;
                    let iop = inner
                        .iop_pdg
                        .pop_front()
                        .expect("Received IOp Ack without IOp pending");
                    assert_eq!(
                        iop.to_words(),
                        iop_pld.inner.to_words(),
                        "Mismatch between IOpPayload content and local store"
                    );
                    (hid, iop)
                };
                let iop_header_hex = iop.to_words()[0];
                self.clone()
                    .flush_dst_ldq(iop.get_iid())
                    .await
                    .expect("Error while flush Dst Store queue");

                // Notify Other HpuNode of dst availability
                let notify_order = iop
                    .dst()
                    .iter()
                    .filter(|op| op.props.pos.0 == hid)
                    .flat_map(|op| {
                        let vec_len = op.props.vec_size.len();
                        let blk_len = op.props.block.len();
                        itertools::iproduct!(0..vec_len, 0..blk_len)
                            .map(|(v, b)| v * blk_len + b)
                            .flat_map(|bid| {
                                let ucore_pld = hpu_asm::UcorePayload {
                                    mode: hpu_asm::UcorePayloadMode::Ucore(hpu_asm::UcoreFlag {
                                        pos: op.props.pos,
                                        slot: hpu_asm::CtId(op.addr.base_cid.0 + bid as u16),
                                    }),
                                    slot: None,
                                    from_hid: hpu_asm::NodeId(hid),
                                    iid: op.props.iid,
                                };

                                self.params
                                    .cluster_nodes
                                    .iter()
                                    .filter(|n| **n != hid)
                                    .map(|n| Network::new_wrapped(hid, *n, ucore_pld, None))
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                self.ctrl
                    .tx()
                    .send_pkt_burst(notify_order)
                    .await
                    .expect("Error while notifying cluster");

                // Release b2b_pool slot that belong to current iop
                self.inner
                    .lock()
                    .unwrap()
                    .b2b_pool
                    .release_tagged(iop.get_iid());

                // write body
                self.mem
                    .write(self.properties(), chunk_start, &iop_header_hex)
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
                hpu_asm::IOp::from_words(iop_stream).ok()
            };

            if let Some(iop) = iop_pdg {
                log!(|self| log::Category::Own, log::Verbosity::Debug => iop => "Will process following iop");

                {
                    // Mutex scope
                    let mut inner = self.inner.lock().unwrap();

                    // Check for user side restart
                    // I.e. start of a new application that reset the allocator state
                    if inner.cur_iid >= iop.get_iid() {
                        // Flush internal state
                        inner.b2b_pool.release_all();
                        inner.event_list.clear();
                    }
                    // Populate DstLdQueue
                    // Add entry for each sub-slot owned by local node
                    // DstLdQueue will be flush between:
                    //  * Sync received from hpu_core
                    //  *  Forward to host
                    for operand in iop.dst().iter() {
                        if operand.props.pos.0 == inner.config.node_id {
                            let vec_len = operand.props.vec_size.len();
                            let blk_len = operand.props.block.len();

                            for bid in itertools::iproduct!(0..vec_len, 0..blk_len)
                                .map(|(v, b)| v * blk_len + b)
                            {
                                let order = DstLdOrder {
                                    iid: iop.get_iid(),
                                    operand: *operand,
                                    cid: hpu_asm::CtId(operand.addr.base_cid.0 + bid as u16),
                                    action: LdAction::Read,
                                };
                                inner.dst_ldq.push(order);
                            }
                        }
                    }

                    inner.cur_iid = iop.get_iid();
                    inner.iop_pdg.push_back(iop.clone());
                    event::Event::triggered(&forge_event_name!(|self| "NoIOpPending"), None);
                }

                // Update context in HpuCore
                let iop_pkt = {
                    let mut pld = IOpPayload::new(iop.clone());
                    // Insert creator uuid and timestamp
                    pld.wrap_up(*self.props.uid());
                    Packet::wrap_payload(pld, Default::default())
                };
                self.hpu_ctx
                    .send_pkt(iop_pkt)
                    .await
                    .expect("Issue with ucore iop context update");

                // Retrived DOp stream from memory
                let dops = self.load_fw(&iop).await;
                // handle Dops
                self.clone()
                    .exec_or_deferred(&iop, &dops)
                    .await
                    .expect("Issue with ucore exec_or_deferred");
            } else {
                delay::Delay::wait_for(self.params.polling_rate.into()).await;
            }
        }
    }

    /// This function handle ctrl message and update internal table accordingly
    async fn ctrl_flush(self: Arc<Self>) {
        loop {
            let ucore_pld = self
                .ctrl
                .rx()
                .wait_pkt_ep(None)
                .await
                .expect("Issue with Ctrl xfer")
                .inner_unwrap()
                .unwrap_payload();

            // Stall event handling while there is no iop_pending
            // Aims is to correctly detect user reset (i.e. start of new application)
            // and prevent clash with event_list
            let iop_empty = self.inner.lock().unwrap().iop_pdg.is_empty();
            if iop_empty {
                event::Event::wait(&forge_event_name!(|self| "NoIOpPending")).await;
            }

            self.insert_event(ucore_pld);
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
    #[allow(unused)]
    fn bytes_to_words<W>(words: usize) -> usize {
        words / std::mem::size_of::<W>()
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

    /// Utility function to convert CtId in real Addr
    fn cid_to_addr(&self, cid: hpu_asm::CtId) -> Vec<Addr> {
        let ct_chunk_size_b = page_align(
            hpu_big_lwe_ciphertext_size(&self.params.rtl_params)
                .div_ceil(self.params.rtl_params.pc_params.pem_pc)
                * std::mem::size_of::<u64>(),
        );
        // Ct_ofst is equal over PC
        let ct_ofst = cid.0 as usize * ct_chunk_size_b;

        self.params
            .ct_pc
            .iter()
            .map(|mem_kind| {
                // WARN: this only work if ct_mem is allocated at begin of each channel
                // TODO read offset from regmap register

                Addr::Phys(match mem_kind {
                    MemKind::Ddr { offset } => offset + ct_ofst,
                    MemKind::Hbm { pc } => {
                        self.params.hbm_global_ofst + pc * self.params.hbm_pc_ofst + ct_ofst
                    }
                })
            })
            .collect::<Vec<_>>()
    }

    /// Utility function to get hpu ciphertext pattern for one Pc
    fn ct_pc_pattern(&self) -> Pattern {
        let ct_chunk_size_b = page_align(
            hpu_big_lwe_ciphertext_size(&self.params.rtl_params)
                .div_ceil(self.params.rtl_params.pc_params.pem_pc)
                * std::mem::size_of::<u64>(),
        );

        Pattern::Simple(ct_chunk_size_b.Byte())
    }

    /// Read DOp stream from Firmware memory
    async fn load_fw(&self, iop: &hpu_asm::IOp) -> Vec<hpu_asm::DOp> {
        let fw_base_addr = match self.params.fw_pc {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { .. } => {
                panic!("Ucore can't access HBM. Fw translation table must be stored in DDR");
            }
        };
        let fw_lut_addr = fw_base_addr + FW_RUNTIME_MAX_WORD * std::mem::size_of::<u32>();

        // Read config from runtime config area
        // Update inner config and extract hid
        let hid = {
            let fw_cfg_raw = self
                .mem
                .read_bytes(
                    self.properties(),
                    fw_base_addr,
                    std::mem::size_of::<UcoreConfig>(),
                )
                .await
                .expect("Error while reading fw config");

            let fw_cfg = *bytemuck::from_bytes(fw_cfg_raw.as_slice());

            let mut inner = self.inner.lock().unwrap();
            inner.config = fw_cfg;

            inner.config.node_id
        };

        let dop_ofst = {
            let mut val = 0_u32;
            self.mem
                .read(
                    self.properties(),
                    fw_lut_addr + Self::words_to_bytes::<u32>(iop.fw_entry(hid)),
                    &mut val,
                )
                .await
                .expect("Error while reading Iopq body");
            val as usize
        };
        let dop_len = {
            let mut val = 0_u32;
            self.mem
                .read(self.properties(), fw_lut_addr + dop_ofst as usize, &mut val)
                .await
                .expect("Error while reading fw");
            Self::words_to_bytes::<u32>(val as usize)
        };
        let dop_stream_u8 = self
            .mem
            .read_bytes(
                self.properties(),
                fw_lut_addr + dop_ofst + std::mem::size_of::<u32>(),
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
    /// Some Dop are directly executed by the ucore other one are deferred to HPU
    async fn exec_or_deferred(
        self: Arc<Self>,
        iop: &hpu_asm::IOp,
        dops: &[hpu_asm::DOp],
    ) -> Result<(), anyhow::Error> {
        for dop in dops {
            // Execute DOp directly or [patch] & deferred to Hpu
            let deferred_dop = match dop {
                // Direct execution by Ucore
                hpu_asm::DOp::NOTIFY(hpu_asm::dop::DOpNotify(inner)) => {
                    // Build Ucore payload based on context and current DOp
                    let raw_cid = match inner.slot {
                        hpu_asm::MemId::Addr(ct_id) => ct_id,
                        hpu_asm::MemId::Heap { bid } => hpu_asm::CtId(
                            (self.params.ct_user + self.params.ct_b2b + self.params.ct_heap - 1)
                                as u16
                                - bid,
                        ),

                        _ => panic!("Unsupported Ucore memory mode"),
                    };
                    let from_hid = hpu_asm::NodeId(self.inner.lock().unwrap().config.node_id);
                    let to_hid = inner.hid;

                    let ucore_pld = hpu_asm::UcorePayload {
                        mode: hpu_asm::UcorePayloadMode::User(inner.flag),
                        slot: Some(raw_cid),
                        from_hid,
                        iid: iop.get_iid(),
                    };

                    log!(|self| log::Category::Own, log::Verbosity::Trace => ucore_pld => "Issue B2b Notify");
                    self.ctrl
                        .tx()
                        .send_pkt(Network::new_wrapped(from_hid.0, to_hid.0, ucore_pld, None))
                        .await?;

                    None
                }
                hpu_asm::DOp::WAIT(hpu_asm::dop::DOpWait(inner)) => {
                    let hash = UcoreHash::User {
                        iid: iop.get_iid(),
                        flag: inner.flag,
                    };
                    self.wait(&hash).await;
                    None
                }
                hpu_asm::DOp::LD_B2B(hpu_asm::dop::DOpLdB2B(inner)) => {
                    //1. Construct hash
                    let raw_cid = match inner.slot {
                        hpu_asm::MemId::Addr(ct_id) => ct_id,
                        hpu_asm::MemId::Heap { bid } => hpu_asm::CtId(
                            (self.params.ct_user + self.params.ct_b2b + self.params.ct_heap - 1)
                                as u16
                                - bid,
                        ),

                        _ => panic!("Unsupported Ucore memory mode"),
                    };
                    let hash = UcoreHash::User {
                        iid: iop.get_iid(),
                        flag: inner.flag,
                    };

                    //2. Register background worker
                    // This worker will wait on associated event and triggered the dma acess
                    let asc = self.clone();
                    let iid = iop.get_iid();
                    spawn_prc!(Self::ld_b2b_bg(asc, iid, hash, Some(raw_cid)));
                    None
                }

                _ => {
                    let mut dop_patch = dop.clone();
                    match &mut dop_patch {
                        // Patching and deferred execution
                        // LD/ST patching
                        // Do MemId template resolution
                        // Warn: With Multi-Hpu support Src/Dst could be located on another Hpu
                        hpu_asm::DOp::LD(hpu_asm::dop::DOpLd(inner))
                        | hpu_asm::DOp::ST(hpu_asm::dop::DOpSt(inner)) => {
                            inner.slot = match inner.slot {
                                hpu_asm::MemId::Heap { bid } => {
                                    hpu_asm::MemId::Addr(hpu_asm::CtId(
                                        (self.params.ct_user
                                            + self.params.ct_b2b
                                            + self.params.ct_heap
                                            - 1) as u16
                                            - bid,
                                    ))
                                }
                                hpu_asm::MemId::Src { tid, bid } => {
                                    let operand = iop.src()[tid as usize];
                                    let op_cid =
                                        hpu_asm::CtId(operand.addr.base_cid.0 + bid as u16);
                                    if operand.props.pos.0
                                        == self.inner.lock().unwrap().config.node_id
                                    {
                                        // Local access -> Usual patching
                                        hpu_asm::MemId::Addr(op_cid)
                                    } else {
                                        // Remote access
                                        let hash = UcoreHash::Ucore {
                                            iid: operand.props.iid,
                                            flag: hpu_asm::UcoreFlag {
                                                pos: operand.props.pos,
                                                slot: op_cid,
                                            },
                                        };
                                        self.clone()
                                            .ld_b2b_bg(iop.get_iid(), hash, None)
                                            .await
                                            .expect("Issue with ld_b2b background task")
                                    }
                                }
                                hpu_asm::MemId::Dst { tid, bid } => {
                                    let mut inner = self.inner.lock().unwrap();
                                    let operand = iop.dst()[tid as usize];
                                    let cid = hpu_asm::CtId(operand.addr.base_cid.0 + bid as u16);

                                    let op_cid = if operand.props.pos.0 == inner.config.node_id {
                                        // Local access -> Usual patching
                                        // Also removed associated DstLdOrder in the queue
                                        if let Some(i) = inner
                                            .dst_ldq
                                            .iter()
                                            .enumerate()
                                            .filter(|(_i, x)| {
                                                x.iid == inner.cur_iid
                                                    && x.operand == operand
                                                    && x.cid == cid
                                            })
                                            .map(|(i, _x)| i)
                                            .next()
                                        {
                                            let _ = inner.dst_ldq.remove(i);
                                        };
                                        cid
                                    } else {
                                        // Remote access
                                        // Allocate temporary value in the B2B_pool
                                        let tmp_cid = inner.b2b_pool.get_tagged(iop.get_iid());

                                        // Create associated DstLdOrder in the queue if it doesn't exist
                                        match inner.dst_ldq.iter().enumerate().find(|(_i, x)| {
                                            x.iid == inner.cur_iid
                                                && x.operand == operand
                                                && x.cid == cid
                                        }) {
                                            Some(_) => {}
                                            None => {
                                                // Create associated entry.
                                                // NB: only occured for remote access case (i.e. no direct deletion afterward)
                                                let order = DstLdOrder {
                                                    iid: inner.cur_iid,
                                                    operand,
                                                    cid,
                                                    action: LdAction::Notify(tmp_cid),
                                                };
                                                inner.dst_ldq.push(order)
                                            }
                                        };
                                        tmp_cid
                                    };

                                    hpu_asm::MemId::Addr(op_cid)
                                }
                                hpu_asm::MemId::Addr(ct_id) => hpu_asm::MemId::Addr(ct_id),
                            };
                            Some(dop_patch)
                        }
                        // Immediat patching
                        hpu_asm::DOp::ADDS(hpu_asm::dop::DOpAdds(inner))
                        | hpu_asm::DOp::SUBS(hpu_asm::dop::DOpSubs(inner))
                        | hpu_asm::DOp::SSUB(hpu_asm::dop::DOpSsub(inner))
                        | hpu_asm::DOp::MULS(hpu_asm::dop::DOpMuls(inner)) => {
                            Self::patch_imm(iop, &mut inner.msg_cst);
                            Some(dop_patch)
                        }
                        // Deferred execution
                        _ => Some(dop_patch),
                    }
                }
            };

            if let Some(dop) = deferred_dop {
                // Wrapped DOp in packet and send them to HpuCore
                let dop_pkt = Packet::wrap_payload(DOpPayload::new(dop), Default::default());
                self.hpu_req.send_pkt(dop_pkt).await?;
                // TODO refine this maybe use a more accurate timing model inside the ucore
                delay::Delay::wait_for(
                    (unit::Time::from(self.props.clock_domain().frequency()) * 2.0).into(),
                )
                .await;
            }
        }

        // Ucore is in charge of Sync insertion
        let sync_dop = hpu_asm::dop::DOpSync::new(iop.get_iid()).into();
        let sync_dop_pkt = Packet::wrap_payload(DOpPayload::new(sync_dop), Default::default());
        self.hpu_req.send_pkt(sync_dop_pkt).await?;
        log!(|self| log::Category::Own, log::Verbosity::Trace => iop => "IOp translate and deferred to Hpu");
        Ok(())
    }

    /// Wait an event to be received
    async fn wait(&self, key: &UcoreHash) {
        log!(|self| log::Category::Own, log::Verbosity::Trace => key);

        // Hang DOp translation until associated event is founded
        loop {
            let wait_ready = {
                let inner_data = self.inner.lock().unwrap();
                inner_data.event_list.contains_key(key)
            };

            if wait_ready {
                break;
            } else {
                event::Event::wait(&forge_event_name!(|self| "sync_evt")).await;
            }
        }
    }

    /// Background task to wait for Notify event and start matching DMA request
    async fn ld_b2b_bg(
        self: Arc<Self>,
        iid: hpu_asm::IOpId,
        hash: UcoreHash,
        dst: Option<hpu_asm::CtId>,
    ) -> Result<hpu_asm::MemId, anyhow::Error> {
        loop {
            let (hid, event) = {
                let inner = self.inner.lock().unwrap();
                (inner.config.node_id, inner.event_list.get(&hash).cloned())
            };

            log!(|self| log::Category::Own, log::Verbosity::Debug => hash, event);
            match event {
                Some(Event::Resolved(mid)) => {
                    // Nothing to do, value already fetch on board
                    return Ok(mid);
                }
                Some(Event::Received(payload)) => {
                    // Value ready but not retrieved yet
                    // Allocate temporary value in the B2B_pool if required
                    let dst_cid = match dst {
                        Some(cid) => cid,
                        None => self.inner.lock().unwrap().b2b_pool.get_tagged(iid),
                    };
                    let src_addr =
                        self.cid_to_addr(payload.slot.expect("LD_B2B required slot information"));
                    let dst_addr = self.cid_to_addr(dst_cid);

                    let dma_req = std::iter::zip(src_addr.into_iter(), dst_addr.into_iter())
                        .map(|(src, dst)| {
                            DmaBus::new_wrapped(
                                (payload.from_hid.0, src),
                                (hid, dst),
                                self.ct_pc_pattern(),
                                None,
                            )
                        })
                        .collect::<Vec<_>>();
                    log!(|self| log::Category::Own, log::Verbosity::Debug => dma_req => "Build Dma requests");

                    // Only check for error
                    // FIXME: check behavior of b_req_resp_burst cf Ra2m doc
                    // self.dma.b_req_resp_burst(dma_req).await.into_iter().map(|(_resp, res)| res).collect::<Result<(),_>>()?;
                    for r in dma_req {
                        self.dma.b_req_resp(r).await?;
                    }

                    // Update event state
                    let mut inner = self.inner.lock().unwrap();
                    let event = inner.event_list.get_mut(&hash).unwrap();
                    *event = Event::Resolved(hpu_asm::MemId::Addr(dst_cid));
                }
                None => {
                    if let UcoreHash::Ucore { iid, flag } = hash
                        && iid == hpu_asm::SW_IOP_ID
                    {
                        // Value generated by Sw and already uploaded in memory
                        // Automatically register its associated event
                        let ucore_pld = hpu_asm::UcorePayload {
                            mode: hpu_asm::UcorePayloadMode::Ucore(flag),
                            slot: Some(flag.slot),
                            from_hid: flag.pos,
                            iid,
                        };
                        self.insert_event(ucore_pld);
                    }

                    self.wait(&hash).await
                }
            }
        }
    }

    /// Issue all dst load order belonging to `for_iid`.
    /// Kept other one in the queue
    async fn flush_dst_ldq(self: Arc<Self>, for_iid: hpu_asm::IOpId) -> Result<(), anyhow::Error> {
        //1. Filter out all read request that belong to current iop
        // Store back unmatch DstRdOrder in queue
        let (hid, mut cur_ord) = {
            let mut inner = self.inner.lock().unwrap();
            let remains_elem = inner
                .dst_ldq
                .iter_mut()
                .partition_in_place(|e| e.iid != for_iid);
            (inner.config.node_id, inner.dst_ldq.split_off(remains_elem))
        };

        // 2. Execute DstLdOrder
        let (notify_ord, read_ord) = {
            let rd_elem = cur_ord.iter_mut().partition_in_place(|e| match e.action {
                LdAction::Notify(_) => false,
                LdAction::Read => true,
            });
            (cur_ord.split_off(rd_elem), cur_ord)
        };

        // 2.a Execute Notify
        let notify_order = notify_ord
            .iter()
            .map(|order| {
                let slot = match order.action {
                    LdAction::Notify(ct_id) => ct_id,
                    LdAction::Read => panic!("Check cur_ord filtering"),
                };
                let ucore_pld = hpu_asm::UcorePayload {
                    mode: hpu_asm::UcorePayloadMode::Ucore(hpu_asm::UcoreFlag {
                        pos: order.operand.props.pos,
                        slot: order.cid,
                    }),
                    slot: Some(slot),
                    from_hid: hpu_asm::NodeId(hid),
                    iid: order.iid,
                };

                // Notify owner HpuNode
                Network::new_wrapped(hid, order.operand.props.pos.0, ucore_pld, None)
            })
            .collect::<Vec<_>>();

        self.ctrl.tx().send_pkt_burst(notify_order).await?;

        // 2.b Execute Remote load
        // Also notify other Node of data availability
        for order in read_ord.iter() {
            let hash = UcoreHash::Ucore {
                iid: order.iid,
                flag: hpu_asm::UcoreFlag {
                    pos: order.operand.props.pos,
                    slot: order.cid,
                },
            };
            self.clone()
                .ld_b2b_bg(order.iid, hash, Some(order.cid))
                .await
                .expect("Issue with ld_b2b background task");
        }
        Ok(())
    }

    /// Check around event insertion in event_list
    fn insert_event(&self, ucore_pld: hpu_asm::UcorePayload) {
        // Compute hash
        let hash = match &ucore_pld.mode {
            hpu_asm::UcorePayloadMode::Ucore(ucore_flag) => UcoreHash::Ucore {
                iid: ucore_pld.iid,
                flag: *ucore_flag,
            },
            hpu_asm::UcorePayloadMode::User(user_flag) => UcoreHash::User {
                iid: ucore_pld.iid,
                flag: *user_flag,
            },
        };
        // Update inner state table
        let mut inner = self.inner.lock().unwrap();
        let present = inner.event_list.insert(hash, Event::Received(ucore_pld));
        if let Some(event) = present {
            panic!(
                "Ucore {}: Received duplicated event @{hash:?} => {event:?}",
                inner.config.node_id
            );
        }
        // Notify to wake up pending task
        event::Event::triggered(&forge_event_name!(|self| "sync_evt"), None);
    }
}

impl UCore {
    fn dump_iop_report(&self, pld: &IOpPayload) {
        // Display in console for user real-time inspection
        println!(
            "Executed IOp: {} in {} [{} timeout]",
            pld.inner.asm_opcode(),
            pld.get_history().duration(),
            pld.batch_timeout.len()
        );
        println!("{pld}");

        // Append in execution log for later analyses
        {
            let trace_folder = Output::get_trace_folder();
            let trace_path = trace_folder.join(std::path::Path::new(self.props.path()));
            let rpt_f = format!("{}/executed_iop.rpt", trace_path.to_str().unwrap());

            let rpt_p = std::path::Path::new(&rpt_f);
            if let Some(dir_p) = rpt_p.parent() {
                std::fs::create_dir_all(dir_p).unwrap();
            }

            // Open file
            let mut wr_f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(rpt_p)
                .expect("Error: Unable to open rpt file in append mode");
            writeln!(
                wr_f,
                "{}::{} [{} timeout]",
                pld.inner.asm_opcode(),
                pld.get_history().duration(),
                pld.batch_timeout.len()
            )
            .expect("Error: Unable to append to rpt file");
        }

        // Dump dop execution order for debug
        let trace_folder = Output::get_trace_folder();
        let trace_path = trace_folder.join(std::path::Path::new(self.props.path()));

        // Generate executed DOp order
        let iopcode = pld.inner.opcode().0;

        let asm_p = format!(
            "{}/dop/dop_executed_{iopcode:0>2x}.asm",
            trace_path.to_str().unwrap()
        );
        let hex_p = format!(
            "{}/dop/dop_executed_{iopcode:0>2x}.hex",
            trace_path.to_str().unwrap()
        );
        let dop_prog = hpu_asm::Program::new(
            pld.exec_order
                .iter()
                .map(|op| hpu_asm::AsmOp::Stmt(op.clone()))
                .collect::<Vec<_>>(),
        );
        dop_prog.write_asm(&asm_p).unwrap();
        dop_prog.write_hex(&hex_p).unwrap();

        // TODO add other report
    }
}
