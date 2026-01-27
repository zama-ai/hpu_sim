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

// Handle notify state in a global structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyState {
    None,                            // Event not received yet
    ReadPending(hpu_asm::CtId),      // Event not received but read is already pending
    Received(hpu_asm::UcorePayload), // Event received but not handled yet
    DmaPending(usize),               // Event received and associated dma request already issued
    Resolved(hpu_asm::CtId),         // Event received and locally resolved in associated mem_id
}

const MAX_IID: usize = 1 << 8; // IOpId expressed on 8b
const MAX_USER_EVENTS: usize = 1 << 6; // User events expressed on 6b
const MAX_UCORE_EVENTS: usize = 1 << 8; // TODO refine the max value here

/// Struture able to store global Notify state
/// Could be indexed by (hpu_id, flag_id) for ease of access
struct NotifyStore {
    user_store: [NotifyState; MAX_IID * MAX_USER_EVENTS],
    ucore_store: [NotifyState; MAX_IID * MAX_UCORE_EVENTS],
}

impl NotifyStore {
    fn index_of(hash: &UcoreHash) -> usize {
        match hash {
            UcoreHash::User { iid, flag } => {
                assert!(
                    iid.0 as usize <= MAX_IID,
                    "Error: looking for event that belong to invalid IOpId"
                );
                assert!(
                    flag.0 as usize <= MAX_USER_EVENTS,
                    "Error: looking for event with invalid user flag"
                );
                iid.0 as usize * MAX_USER_EVENTS + flag.0 as usize
            }
            UcoreHash::Ucore { iid, flag } => {
                assert!(
                    iid.0 as usize <= MAX_IID,
                    "Error: looking for event that belong to invalid IOpId"
                );
                // let flag_hash = flag.pos.0 as usize; // TODO correctly build uuid based on UcoreHash
                let flag_hash = flag.slot.0 as usize; // TODO correctly build uuid based on UcoreHash
                assert!(
                    flag_hash <= MAX_UCORE_EVENTS,
                    "Error: looking for event with invalid user flag"
                );
                iid.0 as usize * MAX_USER_EVENTS + flag_hash
            }
        }
    }
}

impl std::ops::Index<&UcoreHash> for NotifyStore {
    type Output = NotifyState;

    fn index(&self, index: &UcoreHash) -> &Self::Output {
        let idx = Self::index_of(index);
        match index {
            UcoreHash::Ucore { .. } => &self.ucore_store[idx],
            UcoreHash::User { .. } => &self.user_store[idx],
        }
    }
}

impl std::ops::IndexMut<&UcoreHash> for NotifyStore {
    fn index_mut(&mut self, index: &UcoreHash) -> &mut Self::Output {
        let idx = Self::index_of(index);
        match index {
            UcoreHash::Ucore { .. } => &mut self.ucore_store[idx],
            UcoreHash::User { .. } => &mut self.user_store[idx],
        }
    }
}

impl Default for NotifyStore {
    fn default() -> Self {
        Self {
            user_store: [NotifyState::None; MAX_IID * MAX_USER_EVENTS],
            ucore_store: [NotifyState::None; MAX_IID * MAX_UCORE_EVENTS],
        }
    }
}

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
/// This structure held common value that could be edited by multiple tasks
struct UCoreInner {
    config: UcoreConfig,
    iop_stream: VecDeque<hpu_asm::iop::IOpWordRepr>,
    iop_pdg: VecDeque<hpu_asm::IOp>,
    event_list: HashMap<UcoreHash, Event>,
    b2b_pool: B2bPool,
    dst_ldq: Vec<DstLdOrder>,
    // Use to detect restart on the user side (i.e. start of a new application)
    cur_iid: hpu_asm::IOpId,

    // Global state for notify state
    notify_store: NotifyStore,
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
            notify_store: Default::default(),
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
    Resolved(hpu_asm::CtId),
}

/// Internal structure used only by IrqAck task
#[derive(Debug, Default)]
struct IrqAck {
    pdg_notify: VecDeque<(hpu_asm::NodeId, hpu_asm::UcorePayload)>,
}

/// Internal structure used only by IrqNotify task
#[derive(Debug, Default)]
struct IrqNotify {}

/// Internal structure used only by IrqNotify task
#[derive(Debug, Default)]
struct IrqDma {
    pdg_req: VecDeque<(UcoreHash, hpu_asm::CtId)>,
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
    #[port]
    hpu_ctx: port::ReqRespPort<IOpPayload>,
    #[port]
    hpu_dop: port::ReqRespPort<DOpPayload>,

    /// Ctrl: Issue/Received control token for interboard synchronisation
    #[port]
    ctrl: port::ReqRespPort<Network<u8, hpu_asm::UcorePayload>>,

    /// dma: Issue Dma request for interboard communication
    #[port]
    dma: port::ReqRespPort<DmaBus<(u8, Addr)>>,

    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    // Ucore internal state
    // Some part are only used by sub-task and thus extracted from the main mutex
    inner: Mutex<UCoreInner>,
    irq_ack_ctx: Mutex<IrqAck>,
    irq_dma_ctx: Mutex<IrqDma>,
    irq_notify_ctx: Mutex<IrqNotify>,
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
            hpu_ctx: port::ReqRespPort::new(
                "hpu_ctx",
                props.clone(),
                Some(params.axis_depth),
                None,
            ),
            hpu_dop: port::ReqRespPort::new(
                "hpu_dop",
                props.clone(),
                Some(params.axis_depth),
                None,
            ),
            ctrl: port::ReqRespPort::new("ctrl", props.clone(), None, None),
            dma: port::ReqRespPort::new("dma", props.clone(), Some(1), None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(inner),
            irq_ack_ctx: Mutex::new(Default::default()),
            irq_dma_ctx: Mutex::new(Default::default()),
            irq_notify_ctx: Mutex::new(Default::default()),
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

        // Mimic Irq sub-routines
        let asc = self.clone();
        prc.push(spawn_prc!(Self::irq_ack(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::irq_dma(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::irq_notify(asc)));
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

    async fn hpu_feed(self: Arc<Self>) {
        loop {
            // Extract one Iop from stream
            let iop_pdg = {
                let iop_stream = &mut self.inner.lock().unwrap().iop_stream;
                hpu_asm::IOp::from_words(iop_stream).ok()
            };

            if let Some(iop) = iop_pdg {
                self.load_config().await;
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
                    println!(
                        "@{} -> Start of IOp: {:?}",
                        inner.config.node_id, inner.dst_ldq
                    );
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
                    .tx()
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

    /// This function modelize handler of hpu_core Ackq interrupt
    async fn irq_ack(self: Arc<Self>) -> Result<(), anyhow::Error> {
        loop {
            // Wait for hpu dop ack event
            let dop_sync = self
                .hpu_dop
                .rx()
                .wait_pkt_ep(None)
                .await
                .expect("Issue with DOpPayload xfer")
                .unwrap_payload();
            log!(|self| log::Category::Own, log::Verbosity::Debug => dop_sync => "Sync received");

            let dop_sync = match dop_sync.inner {
                hpu_asm::DOp::SYNC(dop_sync) => dop_sync,
                _ => panic!("Invalid Dop received as ack. Only DOpSync must be returned"),
            };

            if dop_sync.0.is_inner_sync {
                // Inner sync, retrived associated notify and issue it
                let (to_hid, ucore_pld) = {
                    let mut irq_ack_ctx = self.irq_ack_ctx.lock().unwrap();
                    irq_ack_ctx
                        .pdg_notify
                        .pop_front()
                        .expect("Received inner_sync ack without pending notify")
                };
                log!(|self| log::Category::Own, log::Verbosity::Trace => ucore_pld => "Issue B2b Notify");
                self.ctrl
                    .tx()
                    .send_pkt(Network::new_wrapped(
                        ucore_pld.from_hid.0,
                        to_hid.0,
                        ucore_pld,
                        None,
                    ))
                    .await?;
            } else {
                // Probe associated iop properties
                // Do not pop it to prevent irq_notify to be suspended (and prevent iop_teardown resolution)
                let (hid, iid) = {
                    let inner = self.inner.lock().unwrap();
                    let hid = inner.config.node_id;
                    let iid = inner
                        .iop_pdg
                        .front()
                        .expect("Received IOp Ack without IOp pending")
                        .get_iid();

                    (hid, iid)
                };

                // Start iop teardown
                self.iop_teardown(hpu_asm::NodeId(hid), iid)
                    .await
                    .expect("Issue with iop teardown");

                // IOp is now completly resolved and could be pop from local queue
                let iop = self
                    .inner
                    .lock()
                    .unwrap()
                    .iop_pdg
                    .pop_front()
                    .expect("Received IOp Ack without IOp pending");

                // Retrieved associated iop context
                // Only handle payload lifetime for logging (Ra2m only)
                let iop_pld = self
                    .hpu_ctx
                    .rx()
                    .wait_pkt_ep(None)
                    .await
                    .expect("Issue with IOpPayload xfer")
                    .unwrap_payload();
                // TODO check that iid in iop_ctx match with local storage
                assert_eq!(
                    iop.to_words(),
                    iop_pld.inner.to_words(),
                    "Mismatch between IOpPayload content and local store"
                );
                // Generate execution report
                self.dump_iop_report(&iop_pld);

                // Notify host
                let iop_header_hex = iop.to_words()[0];
                self.ackq_push(iop_header_hex).await;
            }
        }
    }

    /// This function modelize handler of dma end_of_work signal
    async fn irq_dma(self: Arc<Self>) {
        loop {
            // Wait for dma event
            let dma_resp = self
                .dma
                .rx()
                .wait_pkt_ep(None)
                .await
                .expect("Issue with Dma xfer")
                .unwrap_payload();

            log!(|self| log::Category::Own, log::Verbosity::Debug => dma_resp => "Dma ack received");

            // View hash of current request
            let mut irq_dma_ctx = self.irq_dma_ctx.lock().unwrap();
            let (hash, _cid) = irq_dma_ctx
                .pdg_req
                .front()
                .expect("Received dma_resp without pending request");

            // Update global state accordingly
            let mut inner = self.inner.lock().unwrap();
            let node_id = inner.config.node_id;
            let state = &mut inner.notify_store[&hash];
            match state {
                NotifyState::DmaPending(pdg_cnt) => {
                    println!("@{node_id}[{hash:?}] => Current pending_cnt {pdg_cnt}");
                    if *pdg_cnt == 1 {
                        // All pem_pc slice where retrieved remove from pending request
                        // and update state
                        let (hash, cid) = irq_dma_ctx
                            .pdg_req
                            .pop_front()
                            .expect("Received dma_resp without pending request");
                        *state = NotifyState::Resolved(cid);

                        // Notify to wake up pending task
                        event::Event::triggered(&forge_event_name!(|self| "resolved_evt"), None);
                        println!("@{node_id}[{hash:?}] event triggered");
                    } else {
                        *pdg_cnt -= 1;
                    }
                }
                _ => panic!("Received dma_resp for entry in invalid state {state:?}"),
            }
        }
    }

    /// This function handle notify message send by other nodes
    async fn irq_notify(self: Arc<Self>) {
        loop {
            // Stall event handling while there is no iop_pending
            // Aims is to correctly detect user reset (i.e. start of new application)
            // and prevent clash with event_list
            // TODO: Robustify user-reset detection
            let iop_empty = self.inner.lock().unwrap().iop_pdg.is_empty();
            if iop_empty {
                event::Event::wait(&forge_event_name!(|self| "NoIOpPending")).await;
            }

            let ucore_pld = self
                .ctrl
                .rx()
                .wait_pkt_ep(None)
                .await
                .expect("Issue with Ctrl xfer")
                .inner_unwrap()
                .unwrap_payload();

            log!(|self| log::Category::Own, log::Verbosity::Debug => ucore_pld => "Notify received");

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
            // Update glabal notify_store table
            // NB: deffered dma_req to prevent issue with inner lock and async context
            let dma_req = {
                let mut inner = self.inner.lock().unwrap();
                let state = &mut inner.notify_store[&hash];
                match state {
                    NotifyState::None => {
                        // Simply update state
                        *state = NotifyState::Received(ucore_pld);
                        None
                    }
                    NotifyState::ReadPending(cid) => {
                        let cid = *cid;
                        // Update state
                        // NB: A dedicated request is made for each Ct slice
                        *state = NotifyState::DmaPending(self.params.rtl_params.pc_params.pem_pc);

                        // Must trigger dma request
                        Some((inner.config.node_id, hash, ucore_pld, cid))
                    }
                    _ => {
                        panic!(
                            "Ucore {}: Received duplicated event @{hash:?} => {ucore_pld:?}",
                            inner.config.node_id
                        );
                    }
                }
            };

            if let Some((hid, hash, pld, cid)) = dma_req {
                self.start_dma(hid, hash, pld, cid).await;
            }

            // Notify to wake up pending task
            event::Event::triggered(&forge_event_name!(|self| "received_evt"), None);
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

    /// Update node configuration from DDR
    async fn load_config(&self) {
        let fw_base_addr = match self.params.fw_pc {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { .. } => {
                panic!("Ucore can't access HBM. Fw translation table must be stored in DDR");
            }
        };

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

        // Read node if from config
        let hid = {
            let inner = self.inner.lock().unwrap();
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
                // NB: An inner sync is automatically append to the stream to enforce execution of previous Dop before notifying
                // -> Insert a sync and register notify in the queue. When sync returned, issue associated notify
                // NB': Sync couldn't be reorder by hpu_core, thus use a simple Fifo for notify bufering
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

                    log!(|self| log::Category::Own, log::Verbosity::Trace => ucore_pld => "Register B2b Notify for later execution");
                    // Register notify in the queue
                    let mut irq_ack_ctx = self.irq_ack_ctx.lock().unwrap();
                    irq_ack_ctx.pdg_notify.push_back((to_hid, ucore_pld));
                    // Push sync in the stream
                    let inner_sync =
                        hpu_asm::dop::DOpSync::new(iop.get_iid(), Some(inner.flag)).into();
                    Some(inner_sync)
                }
                hpu_asm::DOp::WAIT(hpu_asm::dop::DOpWait(inner)) => {
                    let hash = UcoreHash::User {
                        iid: iop.get_iid(),
                        flag: inner.flag,
                    };
                    self.wait_received(&hash).await;
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

                    //2. Issue request
                    self.ld_b2b(hash, Some(raw_cid)).await;
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

                                        // Issue request
                                        self.ld_b2b(hash.clone(), None).await;

                                        // Wait for resolution (i.e. Dma read finished)
                                        let cid = self.wait_resolved(&hash).await;
                                        hpu_asm::MemId::Addr(cid)
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
                                        // Create associated DstLdOrder in the queue if it doesn't exist
                                        match inner.dst_ldq.iter().enumerate().find(|(_i, x)| {
                                            x.iid == inner.cur_iid
                                                && x.operand == operand
                                                && x.cid == cid
                                        }) {
                                            Some((_pos, order)) => {
                                                assert!(
                                                    matches!(order.action, LdAction::Notify(_)),
                                                    "Clash with alread present order {order:?}[{:?}",
                                                    inner.dst_ldq
                                                );
                                                order.cid
                                            }
                                            None => {
                                                // Allocate temporary value in the B2B_pool
                                                let tmp_cid =
                                                    inner.b2b_pool.get_tagged(iop.get_iid());

                                                // Create associated entry.
                                                // NB: only occured for remote access case (i.e. no direct deletion afterward)
                                                let order = DstLdOrder {
                                                    iid: inner.cur_iid,
                                                    operand,
                                                    cid,
                                                    action: LdAction::Notify(tmp_cid),
                                                };
                                                inner.dst_ldq.push(order);
                                                tmp_cid
                                            }
                                        }
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
                self.hpu_dop.tx().send_pkt(dop_pkt).await?;
                // TODO refine this maybe use a more accurate timing model inside the ucore
                delay::Delay::wait_for(
                    (unit::Time::from(self.props.clock_domain().frequency()) * 2.0).into(),
                )
                .await;
            }
        }

        // Ucore is in charge of Sync insertion
        let sync_dop = hpu_asm::dop::DOpSync::new(iop.get_iid(), None).into();
        let sync_dop_pkt = Packet::wrap_payload(DOpPayload::new(sync_dop), Default::default());
        self.hpu_dop.tx().send_pkt(sync_dop_pkt).await?;
        log!(|self| log::Category::Own, log::Verbosity::Trace => iop => "IOp translated and deferred to Hpu");
        Ok(())
    }

    /// Wait an event to be received
    async fn wait_received(&self, key: &UcoreHash) {
        log!(|self| log::Category::Own, log::Verbosity::Trace => key);

        // Hang DOp translation until associated event is received
        loop {
            let wait_ready = {
                let inner_data = self.inner.lock().unwrap();
                let state = inner_data.notify_store[key];
                matches!(state, NotifyState::Received(_))
            };

            if wait_ready {
                break;
            } else {
                event::Event::wait(&forge_event_name!(|self| "received_evt")).await;
            }
        }
    }

    async fn wait_resolved(&self, key: &UcoreHash) -> hpu_asm::CtId {
        log!(|self| log::Category::Own, log::Verbosity::Trace => key);

        // Hang DOp translation until associated event resolved
        loop {
            let resolved_in = {
                let inner_data = self.inner.lock().unwrap();
                let state = inner_data.notify_store[key];
                match state {
                    NotifyState::Resolved(cid) => Some(cid),
                    _ => None,
                }
            };

            if let Some(cid) = resolved_in {
                break cid;
            } else {
                event::Event::wait(&forge_event_name!(|self| "resolved_evt")).await;
            }
        }
    }

    /// Load data from external board
    /// Look at the current notify state and register required work accordingly
    /// Hook Dma read request in the irq handler infrastructure
    async fn ld_b2b(&self, hash: UcoreHash, dst: Option<hpu_asm::CtId>) {
        // Update associated state
        // NB: deffered dma_req to prevent issue with inner lock and async context
        let dma_req = {
            let mut inner = self.inner.lock().unwrap();
            let cur_iid = inner.cur_iid;
            let state = inner.notify_store[&hash];

            log!(|self| log::Category::Own, log::Verbosity::Debug => hash, dst, state => "Register B2b load");

            match state {
                NotifyState::None => {
                    if let UcoreHash::Ucore { iid, flag } = hash
                        && iid == hpu_asm::SW_IOP_ID
                    {
                        // Value generated by Sw and already uploaded in memory
                        // Directly issue Dma request
                        let ucore_pld = hpu_asm::UcorePayload {
                            mode: hpu_asm::UcorePayloadMode::Ucore(flag),
                            slot: Some(flag.slot),
                            from_hid: flag.pos,
                            iid,
                        };
                        // Allocate temporary value in the B2B_pool if required
                        let dst_cid = match dst {
                            Some(cid) => cid,
                            None => inner.b2b_pool.get_tagged(iid),
                        };

                        *(&mut inner.notify_store[&hash]) =
                            NotifyState::DmaPending(self.params.rtl_params.pc_params.pem_pc);
                        Some((ucore_pld, dst_cid))
                    } else {
                        // Allocate temporary value in the B2B_pool if required
                        let dst_cid = match dst {
                            Some(cid) => cid,
                            None => inner.b2b_pool.get_tagged(cur_iid),
                        };
                        *(&mut inner.notify_store[&hash]) = NotifyState::ReadPending(dst_cid);
                        None
                    }
                }
                NotifyState::ReadPending(_) => {
                    /* Already register nothing to do */
                    None
                }
                NotifyState::Received(payload) => {
                    // Value ready but not retrieved yet
                    // Allocate temporary value in the B2B_pool if required
                    let dst_cid = match dst {
                        Some(cid) => cid,
                        None => inner.b2b_pool.get_tagged(cur_iid),
                    };
                    let pld = payload.clone();

                    *(&mut inner.notify_store[&hash]) =
                        NotifyState::DmaPending(self.params.rtl_params.pc_params.pem_pc);
                    Some((pld, dst_cid))
                }
                NotifyState::DmaPending(_) => {
                    /* Do Nothing */
                    None
                }
                NotifyState::Resolved(_) => {
                    /* Do Nothing */
                    None
                }
            }
        };

        if let Some((pld, cid)) = dma_req {
            let hid = self.inner.lock().unwrap().config.node_id;
            self.start_dma(hid, hash, pld, cid).await;
        }
    }

    async fn start_dma(
        &self,
        from_hid: u8,
        hash: UcoreHash,
        payload: hpu_asm::UcorePayload,
        dst_cid: hpu_asm::CtId,
    ) {
        log!(|self| log::Category::Own, log::Verbosity::Debug => hash, payload, dst_cid => "Dma registered");

        let src_addr = self.cid_to_addr(payload.slot.expect("LD_B2B required slot information"));
        let dst_addr = self.cid_to_addr(dst_cid);

        let dma_req = std::iter::zip(src_addr.into_iter(), dst_addr.into_iter())
            .map(|(src, dst)| {
                DmaBus::new_wrapped(
                    (payload.from_hid.0, src),
                    (from_hid, dst),
                    self.ct_pc_pattern(),
                    None,
                )
            })
            .collect::<Vec<_>>();
        log!(|self| log::Category::Own, log::Verbosity::Debug => dma_req => "Build Dma requests");

        // Start dma
        for r in dma_req {
            self.dma
                .tx()
                .send_pkt(r)
                .await
                .expect("Issue with dma request");
        }

        // Register req for correct resp handling
        let mut irq_dma_ctx = self.irq_dma_ctx.lock().unwrap();
        irq_dma_ctx.pdg_req.push_back((hash, dst_cid));
    }

    /// Issue all dst load order belonging to `for_iid`.
    /// Kept other one in the queue
    async fn flush_dst_ldq(&self, for_iid: hpu_asm::IOpId) -> Result<(), anyhow::Error> {
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
        log!(|self| log::Category::Own, log::Verbosity::Debug => cur_ord => "Load queue for current IOp");

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
        let hash_cid_v = read_ord
            .iter()
            .map(|order| {
                (
                    UcoreHash::Ucore {
                        iid: order.iid,
                        flag: hpu_asm::UcoreFlag {
                            pos: order.operand.props.pos, // TODO this could only be self no ?
                            slot: order.cid,
                        },
                    },
                    order.cid,
                )
            })
            .collect::<Vec<_>>();

        // Issue all requests
        for (hash, cid) in hash_cid_v.iter() {
            self.ld_b2b(hash.clone(), Some(*cid)).await;
        }
        // Wait for all requests
        for (hash, _) in hash_cid_v.iter() {
            self.wait_resolved(hash).await;
        }
        Ok(())
    }

    /// Iop teardown
    /// Flush associated deffered work and update internal state
    /// Also Notify all HpuNode of iop_done
    /// Enable all hpu to know that the IOp is done and view all associated dest operands as valid
    /// Kept other one in the queue
    async fn iop_teardown(
        &self,
        node_id: hpu_asm::NodeId,
        iid: hpu_asm::IOpId,
    ) -> Result<(), anyhow::Error> {
        // Flush deferred load queue
        self.flush_dst_ldq(iid)
            .await
            .expect("Error while flush Dst Store queue");

        // Notify Other HpuNode of dst availability
        // TODO replace with iop done notify to reduce notify bandwidth
        // let notify_order = iop
        //     .dst()
        //     .iter()
        //     .filter(|op| op.props.pos == node_id)
        //     .flat_map(|op| {
        //         log!(|self| log::Category::Own, log::Verbosity::Debug => op => "Dst avail notify");
        //         let vec_len = op.props.vec_size.len();
        //         let blk_len = op.props.block.len();
        //         itertools::iproduct!(0..vec_len, 0..blk_len)
        //             .map(|(v, b)| v * blk_len + b)
        //             .flat_map(|bid| {
        //                 let ucore_pld = hpu_asm::UcorePayload {
        //                     mode: hpu_asm::UcorePayloadMode::Ucore(hpu_asm::UcoreFlag {
        //                         pos: op.props.pos,
        //                         slot: hpu_asm::CtId(op.addr.base_cid.0 + bid as u16),
        //                     }),
        //                     slot: None,
        //                     from_hid: node_id,
        //                     iid: op.props.iid,
        //                 };

        //                 self.params
        //                     .cluster_nodes
        //                     .iter()
        //                     .filter(|n| **n != node_id.0)
        //                     .map(|n| Network::new_wrapped(node_id.0, *n, ucore_pld, None))
        //                     .collect::<Vec<_>>()
        //             })
        //             .collect::<Vec<_>>()
        //     })
        //     .collect::<Vec<_>>();

        // self.ctrl
        //     .tx()
        //     .send_pkt_burst(notify_order)
        //     .await
        //     .expect("Error while notifying cluster");

        // Release b2b_pool slot that belong to current iop
        self.inner.lock().unwrap().b2b_pool.release_tagged(iid);
        Ok(())
    }

    async fn ackq_push(&self, iop_header_hex: hpu_asm::iop::IOpWordRepr) {
        let QueueConfig {
            head_ofst,
            tail_ofst,
            data_ofst,
            size_w,
            mem,
        } = &self.params.ackq;
        log!(|self| log::Category::Own, log::Verbosity::Debug => iop_header_hex => "IOp is done");
        let base_addr = match mem {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { .. } => {
                panic!("Queue must be in DDR, it's currently the only way to have predictive addr");
            }
        };
        let iop_head = loop {
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
            if word_free == 0 {
                log!(|self| log::Category::Own, log::Verbosity::Info => => "Ackq is full");
                delay::Delay::wait_for(self.params.polling_rate.into()).await;
            } else {
                break iop_head;
            }
        };

        let chunk_start =
            base_addr + *data_ofst + ((iop_head as usize % *size_w) * std::mem::size_of::<u32>());

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
    }
}

impl UCore {
    fn dump_iop_report(&self, pld: &IOpPayload) {
        // Display in console for user real-time inspection
        println!(
            "Ucore {}: Executed IOp: {} in {} [{} timeout]",
            self.inner.lock().unwrap().config.node_id,
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
