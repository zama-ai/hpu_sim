//! Depict UCore behavior
//! I.e. kind of embedded processor that Handle IOp/DOp translation
//!
//! Ucore is in charge of IOp to Dop translation and inter-hpu communication
//! For inter-hpu, it has 3 kind of events two handles:
//! * Explicit xfer `User`: There are explicit xfer point inside DOp stream. There are known at compile time
//!    => Event could occured outside of current scope (i.e. received from future IOp only running on other node)
//! * Implicit xfer `Arg`: There only known at runtime based on Src/Dst operand position in the cluster.
//!    Those xfer must be handle differently:
//!     * Src -> Local work based on global IOp status. Position information expressed in IOp code
//!        => There are handle during translation phase (i.e only 1 IOp is translated at a time)
//!     * Dst -> external event carry Ready status and data position (Only local dst position is expressed in IOp)
//!        => Event could occured outside of current scope (i.e. received from future IOp only running on other node)
//!
//! Thus two kind of handling are used:
//!  * Full-table store for User/Arg-Dst events: Those event are not bound to scope and could occured from
//!    the future
//!  * Local context for Arg-Src: Those events are bound to current context. Thus, there lifetime are easy to manage
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

// Define a set of constant
// Use constant instead of parameters to have static allocation of array (and thus mimics real Fw impl)
/// Maximum number of user event inside an IOp
/// Fixed by DOp definition only 6b reserved for it
const MAX_USER_EVENTS: usize = 1 << 6;

/// Maximum number of Src variable inside an IOp
/// Unbound in the IOp structure but fix here to handle buffer size
const MAX_SRC_VARS: usize = 64; // at most 64 source in IOp

/// Maximum number of dst variable inside an IOp
/// Unbound in the IOp structure but fix here to handle buffer size
const MAX_DST_VARS: usize = 64; // at most 64 source in IOp

/// Maximum integer width (expressed in block)
const MAX_VARS_BLK: usize = 64;

/// Maximum IOpId
/// Fixed by IOp definition only 8b reserved for it
const MAX_IID: usize = 1 << 8;

// User synchronisation ===============================================================================================
/// Handle user variable state
/// Use to track lifetime of explicit inter-hpu communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserVarState {
    None,                            // Event not received yet
    ReadPending(hpu_asm::CtId),      // Event not received but read is already pending
    Received(hpu_asm::UcorePayload), // Event received but not handled yet
    DmaPending(usize),               // Event received and associated dma request already issued
    Resolved(hpu_asm::CtId),         // Event received and locally resolved in associated mem_id
}

/// Struture able to store user synchronisation state
struct UserStore(Vec<UserVarState>);

impl Default for UserStore {
    fn default() -> Self {
        Self(vec![UserVarState::None; MAX_IID * MAX_USER_EVENTS])
    }
}

impl UserStore {
    fn index_from_tuple(iid: hpu_asm::IOpId, flag: hpu_asm::UserFlag) -> usize {
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
}

impl std::ops::Index<&(hpu_asm::IOpId, hpu_asm::UserFlag)> for UserStore {
    type Output = UserVarState;

    fn index(&self, index: &(hpu_asm::IOpId, hpu_asm::UserFlag)) -> &Self::Output {
        &self.0[Self::index_from_tuple(index.0, index.1)]
    }
}

impl std::ops::IndexMut<&(hpu_asm::IOpId, hpu_asm::UserFlag)> for UserStore {
    fn index_mut(&mut self, index: &(hpu_asm::IOpId, hpu_asm::UserFlag)) -> &mut Self::Output {
        &mut self.0[Self::index_from_tuple(index.0, index.1)]
    }
}

// Destination synchronisation ========================================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DstVarState {
    None,              // Slot unused with current configured IOp
    WaitNotify,        // Event not received but read is already pending
    DmaPending(usize), // Event received and associated dma request already issued
    Resolved,          // Event received and locally resolved in associated mem_id
}
/// Struture able to store DstArg synchronisation state
struct DstArgStore {
    owner: Vec<hpu_asm::NodeId>,
    store: Vec<DstVarState>,
}

impl Default for DstArgStore {
    fn default() -> Self {
        Self {
            owner: vec![hpu_asm::NodeId(u8::max_value()); MAX_IID * MAX_USER_EVENTS],
            store: vec![DstVarState::WaitNotify; MAX_IID * MAX_DST_VARS * MAX_VARS_BLK],
        }
    }
}

impl DstArgStore {
    fn var_index_from_tuple(iid: hpu_asm::IOpId, var: u8) -> usize {
        assert!(
            iid.0 as usize <= MAX_IID,
            "Error: looking for event that belong to invalid IOpId"
        );
        assert!(
            var as usize <= MAX_DST_VARS,
            "Error: looking for dst variable outside of buffer range"
        );

        (iid.0 as usize * MAX_DST_VARS) + var as usize
    }

    fn blk_index_from_tuple(iid: hpu_asm::IOpId, var: u8, blk: u8) -> usize {
        let var_idx = Self::var_index_from_tuple(iid, var);
        assert!(
            blk as usize <= MAX_VARS_BLK,
            "Error: looking for blk outside of buffer range"
        );

        (var_idx * MAX_VARS_BLK) + blk as usize
    }

    /// Reset iop state
    fn reset_iop(&mut self, iid: hpu_asm::IOpId) {
        for v in 0..MAX_DST_VARS {
            let idx = Self::var_index_from_tuple(iid, v as u8);
            self.owner[idx] = hpu_asm::NodeId(u8::max_value());

            for b in 0..MAX_VARS_BLK {
                let idx = Self::blk_index_from_tuple(iid, v as u8, b as u8);
                self.store[idx] = DstVarState::WaitNotify;
            }
        }
    }

    /// Init iop state
    /// Based on IOp properties discard unused slot
    fn init_iop(&mut self, iop: &hpu_asm::IOp) {
        let iid = iop.get_iid();
        for (idx, var) in iop.dst().iter().enumerate() {
            let var_idx = Self::var_index_from_tuple(iid, idx as u8);
            self.owner[var_idx] = var.props.pos;

            // Discard unused slot
            for b in var.props.block.len()..MAX_VARS_BLK as u8 {
                let blk_idx = Self::blk_index_from_tuple(iid, idx as u8, b);
                self.store[blk_idx] = DstVarState::None;
            }
        }
    }

    /// return position of all blk that belong to current hpu
    fn get_owned(&self, iid: hpu_asm::IOpId, hid: hpu_asm::NodeId) -> Vec<(u8, u8)> {
        let mut owned = Vec::new();
        for v in 0..MAX_DST_VARS {
            let idx = Self::var_index_from_tuple(iid, v as u8);
            if hid == self.owner[idx] {
                for b in 0..MAX_VARS_BLK {
                    let idx = Self::blk_index_from_tuple(iid, v as u8, b as u8);
                    if DstVarState::None != self.store[idx] {
                        owned.push((v as u8, b as u8))
                    } else {
                        // reach end of used blk
                        break;
                    }
                }
            }
        }
        owned
    }
}

impl std::ops::Index<&(hpu_asm::IOpId, u8, u8)> for DstArgStore {
    type Output = DstVarState;

    fn index(&self, index: &(hpu_asm::IOpId, u8, u8)) -> &Self::Output {
        &self.store[Self::blk_index_from_tuple(index.0, index.1, index.2)]
    }
}

impl std::ops::IndexMut<&(hpu_asm::IOpId, u8, u8)> for DstArgStore {
    fn index_mut(&mut self, index: &(hpu_asm::IOpId, u8, u8)) -> &mut Self::Output {
        &mut self.store[Self::blk_index_from_tuple(index.0, index.1, index.2)]
    }
}

/// Keep track of destination slot generated during current IOp context
#[derive(Debug)]
struct DstNotifyOrder {
    // destination info
    var: u8,
    blk: u8,
    trgt_cid: hpu_asm::CtId,
    trgt_hid: hpu_asm::NodeId,
    // local info
    local_cid: hpu_asm::CtId,
}

// Source synchronisation =============================================================================================
/// Handle source variable state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SrcVarState {
    None,                       // Event not received yet
    ReadPending(hpu_asm::CtId), // Event not received but read is already pending
    DmaPending(usize),          // Event received and associated dma request already issued
    Resolved(hpu_asm::CtId),    // Event received and locally resolved in associated mem_id
}

/// Handle Src Iop context
/// NB: Src are required during IOp translation and only 1 IOp is translate at a time
#[derive(Debug, Clone)]
struct SrcArgStore {
    cur_iop: Option<hpu_asm::IOp>,
    store: Vec<SrcVarState>,
}

impl Default for SrcArgStore {
    fn default() -> Self {
        Self {
            cur_iop: Default::default(),
            store: vec![SrcVarState::None; MAX_SRC_VARS * MAX_VARS_BLK],
        }
    }
}

impl SrcArgStore {
    /// Reset internal state
    fn reset(&mut self, iop: hpu_asm::IOp) {
        (*self) = Default::default();
        self.cur_iop = Some(iop);
    }

    /// Get IopId of var/blk
    fn src_iid(&self, var: u8, _blk: u8) -> hpu_asm::IOpId {
        let iop = self
            .cur_iop
            .as_ref()
            .expect("Look for Cid of src while there is no iop registered");
        iop.src()[var as usize].props.iid
    }

    /// Get NodeId of var/blk
    fn src_hid(&self, var: u8, _blk: u8) -> hpu_asm::NodeId {
        let iop = self
            .cur_iop
            .as_ref()
            .expect("Look for Cid of src while there is no iop registered");
        iop.src()[var as usize].props.pos
    }

    /// Get CtId of var/blk
    fn src_cid(&self, var: u8, blk: u8) -> hpu_asm::CtId {
        let iop = self
            .cur_iop
            .as_ref()
            .expect("Look for Cid of src while there is no iop registered");
        hpu_asm::CtId(iop.src()[var as usize].addr.base_cid.0 + blk as u16)
    }

    /// get reference of {blk} state of destination variable at position {var}
    fn src(&self, var: u8, blk: u8) -> &SrcVarState {
        assert!(
            (var as usize) < MAX_SRC_VARS,
            "invalid source variable index"
        );
        assert!((blk as usize) < MAX_VARS_BLK, "invalid block index");
        &self.store[MAX_VARS_BLK * (var as usize) + blk as usize]
    }

    fn src_mut(&mut self, var: u8, blk: u8) -> &mut SrcVarState {
        assert!(
            (var as usize) < MAX_SRC_VARS,
            "invalid source variable index"
        );
        assert!((blk as usize) < MAX_VARS_BLK, "invalid block index");
        &mut self.store[MAX_VARS_BLK * (var as usize) + blk as usize]
    }

    /// Get list of src that belong to given iid
    fn idx_of(&self, iid: &hpu_asm::IOpId) -> Vec<(u8, u8)> {
        if let Some(iop) = &self.cur_iop {
            iop.src()
                .iter()
                .enumerate()
                .filter(|(_, op)| op.props.iid == *iid)
                .flat_map(|(i, op)| {
                    (0..op.props.block.len())
                        .map(|b| (i as u8, b as u8))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    }
}

/// Local external load cache
/// Cache some access to enable reuse across IOps
/// Only store matching between {iid,hid,addr}  and local addr
struct ArgCache {}

/// Number of set in the cache
const CACHE_SET: usize = 64;
/// Number of way in each set
const CACHE_WAY: usize = 4;

impl Default for ArgCache {
    fn default() -> Self {
        Self {}
    }
}

/// Source argument cache
// NB: it seems a good idea before hand but after some tought dunno if the gain
//     is really valubale compared to the added complexity in the Fw.
// *To be discuss*
// Handling lifetime of variable that are in the cache line are pretty hard.
// Currently local b2b_pool is handle by iid and it's hard to swap iid ownership on cache it
impl ArgCache {
    fn try_hit(
        &self,
        _iid: hpu_asm::IOpId,
        _hpid: hpu_asm::NodeId,
        _cid: hpu_asm::CtId,
    ) -> Option<hpu_asm::CtId> {
        None
    }
    fn register_ct(
        &mut self,
        _iid: hpu_asm::IOpId,
        _hpid: hpu_asm::NodeId,
        _cid: hpu_asm::CtId,
        _local_cid: hpu_asm::CtId,
    ) {
        // todo!()
    }
}

// IOp synchronisation =================================================================================================
/// Handle IOp state
/// Keep track of IOpDone notify
/// Use to know state of associated variables
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IOpState([u8; MAX_IID]);

impl IOpState {
    /// Check IOp iid done status
    /// IOp is considered done when all involved nodes have finish
    fn is_done(&self, iid: hpu_asm::IOpId) -> bool {
        self.0[iid.0 as usize] == 0
    }

    /// Register ack from a node
    /// Ack are send with associated involved nodes.
    /// NB: An ack register on a is_done entry rearm the counter and clean var states
    fn node_ack(&mut self, iid: hpu_asm::IOpId, iop_nodes: u8) {
        if self.is_done(iid) {
            // Ack considered as a new registration
            self.0[iid.0 as usize] = iop_nodes - 1;
        } else {
            self.0[iid.0 as usize] -= 1;
        }
    }
}

impl Default for IOpState {
    fn default() -> Self {
        Self([0; MAX_IID])
    }
}

/// Define origin of variable
/// Used to know where to find associated VarState
#[derive(Debug, Clone, Copy)]
enum VarMode {
    User {
        iid: hpu_asm::IOpId,
        flag: hpu_asm::UserFlag,
    },
    ArgSrc {
        var: u8,
        blk: u8,
    },
    ArgDst {
        iid: hpu_asm::IOpId,
        var: u8,
        blk: u8,
    },
}

// Local Ct pool ======================================================================================================
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

// Ucore implementation ================================================================================================
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
    b2b_pool: B2bPool,
    // Use to detect restart on the user side (i.e. start of a new application)
    // TODO replace with proper mechanisms in load_config
    cur_iid: hpu_asm::IOpId,

    /// Use to keep track of Iop state in the cluster
    iop_state: IOpState,

    // Use for inter-iop sync (i.e. inferred by ucore based on vars position)
    /// Local context (handle Src/dstNotify tracking)
    /// Its bound to current IOp context and reset upon each new IOp
    local_store: SrcArgStore,
    /// Use for arg reuse across IOp
    /// This structure is here to enable reuse of local context while keeping
    ///  the required memory space manageable
    arg_cache: ArgCache,

    /// Use to keep track of Dst notify
    /// Couldn't be completly bound to IOp context (flush in irq_ack on in hpu_feed)
    /// I.e. bind to IOp translation but must be flush only after sync return
    dst_notifyq: VecDeque<Vec<DstNotifyOrder>>,

    /// Use to keep track of Dst vars status
    /// NB: Couldn't be bound to local context
    dst_store: DstArgStore,

    /// Use for intra-iop sync (i.e. explicit in the DOp Stream)
    /// Kept across IOp to handle multiple iid inflight in the cluster
    user_store: UserStore,
}

impl UCoreInner {
    pub fn new() -> Self {
        Self {
            config: UcoreConfig::new(Default::default()),
            iop_stream: VecDeque::new(),
            iop_pdg: VecDeque::new(),
            b2b_pool: B2bPool::new(),
            cur_iid: hpu_asm::SW_IOP_ID,
            iop_state: Default::default(),
            local_store: Default::default(),
            arg_cache: Default::default(),
            dst_notifyq: Default::default(),
            dst_store: Default::default(),
            user_store: Default::default(),
        }
    }
}

/// Internal structure used only by IrqAck task
#[derive(Debug, Default)]
struct IrqAck {
    pdg_notify: VecDeque<(hpu_asm::NodeId, hpu_asm::UcorePayload)>,
}

/// Internal structure used only by IrqNotify task
#[derive(Debug, Default)]
struct IrqDma {
    pdg_req: VecDeque<(VarMode, hpu_asm::CtId)>,
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
                    // TODO move this in load_config
                    if inner.cur_iid >= iop.get_iid() {
                        // Flush internal state
                        inner.b2b_pool.release_all();
                        inner.user_store = Default::default();
                        inner.dst_store = Default::default();
                        inner.arg_cache = Default::default();
                    }

                    // Update ArgStore context
                    // And register new entry in DstNotify
                    inner.local_store.reset(iop.clone());
                    inner.dst_notifyq.push_back(Vec::new());
                    inner.dst_store.init_iop(&iop);

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
    async fn irq_ack(self: Arc<Self>) {
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

            let hid = self.inner.lock().unwrap().config.node_id;
            println!("Ucore@{hid} DONE=> {dop_sync:?}");

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
                    .await
                    .expect("Issue with Ctrl xfer")
            } else {
                // Probe associated iop properties
                // Do not pop it to prevent irq_notify to be suspended (and prevent iop_teardown resolution)
                let (hid, iid, involved_nodes) = {
                    let inner = self.inner.lock().unwrap();
                    let hid = inner.config.node_id;
                    let iop = inner
                        .iop_pdg
                        .front()
                        .expect("Received IOp Ack without IOp pending");

                    (hid, iop.get_iid(), iop.mapping().len() as u8)
                };

                // Start iop teardown
                self.iop_teardown(hpu_asm::NodeId(hid), iid, involved_nodes)
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

            // View mode of current request
            let mut irq_dma_ctx = self.irq_dma_ctx.lock().unwrap();
            let (var_mode, _cid) = irq_dma_ctx
                .pdg_req
                .front()
                .expect("Received dma_resp without pending request");

            // Update global state accordingly
            let mut inner = self.inner.lock().unwrap();
            let hid = inner.config.node_id;

            // Extract global state based on request sources
            let notify_evt = match var_mode {
                VarMode::User { iid, flag } => {
                    let state = &mut inner.user_store[&(*iid, *flag)];
                    match state {
                        UserVarState::DmaPending(pdg_cnt) => {
                            // Update irq_dma context
                            if *pdg_cnt == 1 {
                                println!("Ucore{hid} => DMA DONE {var_mode:?}");
                                // All pem_pc slice where retrieved remove from pending request
                                // and update state
                                let (_mode, cid) = irq_dma_ctx
                                    .pdg_req
                                    .pop_front()
                                    .expect("Received dma_resp without pending request");
                                *state = UserVarState::Resolved(cid);

                                true
                            } else {
                                *pdg_cnt -= 1;
                                false
                            }
                        }
                        _ => panic!("Received user dma_resp on invalid state {state:?}"),
                    }
                }
                VarMode::ArgSrc { var, blk } => {
                    let state = inner.local_store.src_mut(*var, *blk);
                    match state {
                        SrcVarState::DmaPending(pdg_cnt) => {
                            // Update irq_dma context
                            if *pdg_cnt == 1 {
                                // All pem_pc slice where retrieved remove from pending request
                                // and update state
                                let (_mode, cid) = irq_dma_ctx
                                    .pdg_req
                                    .pop_front()
                                    .expect("Received dma_resp without pending request");
                                *state = SrcVarState::Resolved(cid);

                                true
                            } else {
                                *pdg_cnt -= 1;
                                false
                            }
                        }
                        _ => panic!("Received src dma_resp on invalid state {state:?}"),
                    }
                }
                VarMode::ArgDst { iid, var, blk } => {
                    let state = &mut inner.dst_store[&(*iid, *var, *blk)];
                    match state {
                        DstVarState::DmaPending(pdg_cnt) => {
                            // Update irq_dma context
                            if *pdg_cnt == 1 {
                                // All pem_pc slice where retrieved remove from pending request
                                // and update state
                                let (_mode, _cid) = irq_dma_ctx
                                    .pdg_req
                                    .pop_front()
                                    .expect("Received dma_resp without pending request");
                                *state = DstVarState::Resolved;

                                true
                            } else {
                                *pdg_cnt -= 1;
                                false
                            }
                        }
                        _ => panic!("Received dst dma_resp on invalid state {state:?}"),
                    }
                }
            };
            if notify_evt {
                event::Event::triggered(&forge_event_name!(|self| "resolved_evt"), None);
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

            // Update internal state
            let hpu_asm::UcorePayload {
                mode,
                slot,
                from_hid,
                iid,
            } = ucore_pld;

            let dma_req = {
                let mut inner = self.inner.lock().unwrap();
                let node_id = inner.config.node_id;
                let mut dma_req = Vec::new();

                match mode {
                    hpu_asm::UcorePayloadMode::Ucore(flag) => {
                        let state = &mut inner.dst_store[&(iid, flag.tid, flag.bid)];
                        match state {
                            DstVarState::WaitNotify => {
                                // Update state and register associated dma req
                                *state = DstVarState::DmaPending(
                                    self.params.rtl_params.pc_params.pem_pc,
                                );

                                let var_mode = VarMode::ArgDst {
                                    iid,
                                    var: flag.tid,
                                    blk: flag.bid,
                                };
                                let from = (
                                    from_hid.clone(),
                                    slot.expect("ReadPending required notify with associated data"),
                                );
                                let to = (hpu_asm::NodeId(inner.config.node_id), flag.trgt_cid);

                                dma_req.push((var_mode, from, to))
                            }
                            _ => {
                                panic!(
                                    "Ucore {}: Received duplicated dst event @{iid}::{flag:?} [{mode:?}, {from_hid:?}, {slot:?}]",
                                    inner.config.node_id
                                );
                            }
                        }
                    }
                    hpu_asm::UcorePayloadMode::User(flag) => {
                        let state = &mut inner.user_store[&(iid, flag)];
                        match state {
                            UserVarState::None => {
                                // Simply update state
                                *state = UserVarState::Received(ucore_pld);
                            }
                            UserVarState::ReadPending(cid) => {
                                // Issue dma request
                                let var_mode = VarMode::User { iid, flag };
                                let from = (
                                    from_hid.clone(),
                                    slot.expect("ReadPending required notify with associated data"),
                                );
                                let to = (hpu_asm::NodeId(node_id), *cid);

                                dma_req.push((var_mode, from, to));

                                // Update state and register associated dma req
                                *state = UserVarState::DmaPending(
                                    self.params.rtl_params.pc_params.pem_pc,
                                );
                            }
                            _ => {
                                panic!(
                                    "Ucore {}: Received duplicated event @{iid}::{flag:?} [{mode:?}, {from_hid:?}, {slot:?}]",
                                    inner.config.node_id
                                );
                            }
                        }
                    }
                    hpu_asm::UcorePayloadMode::IOpDone(iop_nodes) => {
                        // Register ack
                        inner.iop_state.node_ack(iid, iop_nodes);

                        // Check if iop is done and execute associated pending work if any
                        if inner.iop_state.is_done(iid) {
                            let arg_store = &inner.local_store;
                            let pdg_ld_idx = arg_store
                                .idx_of(&iid)
                                .into_iter()
                                .filter(|(var, blk)| {
                                    matches!(arg_store.src(*var, *blk), SrcVarState::ReadPending(_))
                                })
                                .collect::<Vec<_>>();

                            for (var, blk) in pdg_ld_idx {
                                let state = inner.local_store.src_mut(var, blk);
                                match state {
                                    SrcVarState::ReadPending(cid) => {
                                        let cid = *cid;
                                        // Update state
                                        *state = SrcVarState::DmaPending(
                                            self.params.rtl_params.pc_params.pem_pc,
                                        );

                                        let var_mode = VarMode::ArgSrc { var, blk };
                                        let from =
                                            (from_hid.clone(), inner.local_store.src_cid(var, blk));
                                        let to = (hpu_asm::NodeId(inner.config.node_id), cid);

                                        // Must trigger dma request
                                        dma_req.push((var_mode, from, to));
                                    }
                                    _ => {
                                        panic!(
                                            "Ucore {}: Invalid VarState filtering",
                                            inner.config.node_id
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                dma_req
            };
            // Executed pending request if any
            for (mode, from, to) in dma_req {
                self.start_dma(mode, from, to).await;
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

        // TODO add proper mechanisms for user side reset request

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
        let iop_id = iop.get_iid();
        let hid = self.inner.lock().unwrap().config.node_id;

        for dop in dops {
            // Execute DOp directly or [patch] & deferred to Hpu
            let deferred_dop = match dop {
                // Direct execution by Ucore
                // NB: An inner sync is automatically append to the stream to enforce execution of previous Dop before notifying
                // -> Insert a sync and register notify in the queue. When sync returned, issue associated notify
                // NB': Sync couldn't be reorder by hpu_core, thus use a simple Fifo for notify bufering
                hpu_asm::DOp::NOTIFY(hpu_asm::dop::DOpNotify(op_impl)) => {
                    // Build Ucore payload based on context and current DOp
                    let raw_cid = match op_impl.slot {
                        hpu_asm::MemId::Addr(ct_id) => ct_id,
                        hpu_asm::MemId::Heap { bid } => hpu_asm::CtId(
                            (self.params.ct_user + self.params.ct_b2b + self.params.ct_heap - 1)
                                as u16
                                - bid,
                        ),
                        _ => panic!("Unsupported Ucore memory mode"),
                    };
                    let from_hid = hpu_asm::NodeId(self.inner.lock().unwrap().config.node_id);
                    let to_hid = op_impl.hid;

                    let ucore_pld = hpu_asm::UcorePayload {
                        mode: hpu_asm::UcorePayloadMode::User(op_impl.flag),
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
                        hpu_asm::dop::DOpSync::new(iop.get_iid(), Some(op_impl.flag)).into();
                    Some(inner_sync)
                }
                hpu_asm::DOp::WAIT(hpu_asm::dop::DOpWait(op_impl)) => {
                    let var_mode = VarMode::User {
                        iid: iop.get_iid(),
                        flag: op_impl.flag,
                    };
                    // self.wait_received(&var_mode).await;
                    // TODO correctly select flavored based on CtId value
                    self.wait_resolved(&var_mode).await;
                    None
                }
                hpu_asm::DOp::LD_B2B(hpu_asm::dop::DOpLdB2B(op_impl)) => {
                    //1. Construct mode
                    let raw_cid = match op_impl.slot {
                        hpu_asm::MemId::Addr(ct_id) => ct_id,
                        hpu_asm::MemId::Heap { bid } => hpu_asm::CtId(
                            (self.params.ct_user + self.params.ct_b2b + self.params.ct_heap - 1)
                                as u16
                                - bid,
                        ),

                        _ => panic!("Unsupported Ucore memory mode"),
                    };
                    let var_mode = VarMode::User {
                        iid: iop.get_iid(),
                        flag: op_impl.flag,
                    };

                    //2. Issue request
                    self.ld_b2b(var_mode, Some(raw_cid)).await;
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
                                        let var_mode = VarMode::ArgSrc { var: tid, blk: bid };

                                        // Issue request
                                        self.ld_b2b(var_mode.clone(), None).await;

                                        // Wait for resolution (i.e. Dma read finished)
                                        let cid = self.get_resolved(&var_mode).await;
                                        hpu_asm::MemId::Addr(cid)
                                    }
                                }
                                hpu_asm::MemId::Dst { tid, bid } => {
                                    let mut inner = self.inner.lock().unwrap();
                                    let operand = iop.dst()[tid as usize];
                                    let cid = hpu_asm::CtId(operand.addr.base_cid.0 + bid as u16);

                                    let op_cid = if operand.props.pos.0 == inner.config.node_id {
                                        // Local access -> Usual patching
                                        // Update dst_store accordingly (i.e. toggle to receive to store the fact that value is locally generated)
                                        // Also removed associated DstLdOrder in the queue
                                        inner.dst_store[&(iop_id, tid, bid)] =
                                            DstVarState::Resolved;
                                        cid
                                    } else {
                                        // Remote access
                                        // Register in DstNotifyQ for later notify
                                        // TODO Check that not already present or enforce single access by compiler rules ?!
                                        // Allocate temporary value in the B2B_pool
                                        let local_cid = inner.b2b_pool.get_tagged(iop.get_iid());

                                        // Create associated entry.
                                        // NB: only occured for remote access case (i.e. no direct deletion afterward)
                                        let order = DstNotifyOrder {
                                            var: tid,
                                            blk: bid,
                                            trgt_hid: operand.props.pos,
                                            trgt_cid: cid,
                                            local_cid,
                                        };
                                        inner.dst_notifyq.back_mut().expect("notifyq must have been register during context init").push(order);
                                        local_cid
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
                println!("Ucore@{hid} => {dop:?}");
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
    async fn wait_received(&self, key: &VarMode) {
        log!(|self| log::Category::Own, log::Verbosity::Trace => key);

        // Hang DOp translation until associated event is received
        loop {
            let wait_ready = {
                let inner = self.inner.lock().unwrap();
                match key {
                    VarMode::User { iid, flag } => {
                        let state = &inner.user_store[&(*iid, *flag)];
                        matches!(state, UserVarState::Received(_))
                    }
                    _ => panic!("Wait on received is only meaningfull for user sync"),
                }
            };

            if wait_ready {
                break;
            } else {
                event::Event::wait(&forge_event_name!(|self| "received_evt")).await;
            }
        }
    }

    /// Get CtId associated with external load resolution
    async fn get_resolved(&self, key: &VarMode) -> hpu_asm::CtId {
        log!(|self| log::Category::Own, log::Verbosity::Trace => key);

        // Hang DOp translation until associated event resolved
        loop {
            let resolved_in = {
                let inner = self.inner.lock().unwrap();
                match key {
                    VarMode::User { iid, flag } => {
                        let state = &inner.user_store[&(*iid, *flag)];
                        match state {
                            UserVarState::Resolved(cid) => Some(cid.clone()),
                            _ => None,
                        }
                    }
                    VarMode::ArgSrc { var, blk } => {
                        let state = inner.local_store.src(*var, *blk);
                        match state {
                            SrcVarState::Resolved(cid) => Some(cid.clone()),
                            _ => None,
                        }
                    }
                    VarMode::ArgDst { .. } => {
                        panic!("get_resolved unsupported for ArgDst, no CtId attached")
                    }
                }
            };

            if let Some(cid) = resolved_in {
                break cid;
            } else {
                event::Event::wait(&forge_event_name!(|self| "resolved_evt")).await;
            }
        }
    }
    /// Only wain external load resolution
    async fn wait_resolved(&self, key: &VarMode) {
        log!(|self| log::Category::Own, log::Verbosity::Trace => key);

        // Hang DOp translation until associated event resolved
        loop {
            let wait_ready = {
                let inner = self.inner.lock().unwrap();
                match key {
                    VarMode::User { iid, flag } => {
                        let state = &inner.user_store[&(*iid, *flag)];
                        println!("{key:?} => {state:?}");
                        matches!(state, UserVarState::Resolved(_))
                    }
                    VarMode::ArgSrc { var, blk } => {
                        let state = inner.local_store.src(*var, *blk);
                        matches!(state, SrcVarState::Resolved(_))
                    }
                    VarMode::ArgDst { iid, var, blk } => {
                        let state = inner.dst_store[&(*iid, *var, *blk)];
                        matches!(state, DstVarState::Resolved)
                    }
                }
            };

            if wait_ready {
                break;
            } else {
                event::Event::wait(&forge_event_name!(|self| "resolved_evt")).await;
            }
        }
    }

    /// Load data from external board
    /// Look at the current context and register required work accordingly
    /// Hook Dma read request in the irq handler infrastructure
    async fn ld_b2b(&self, var_mode: VarMode, dst: Option<hpu_asm::CtId>) {
        // Update associated state
        // NB: deffered dma_req to prevent issue with inner lock and async context
        let dma_req = {
            let mut inner = self.inner.lock().unwrap();
            let UCoreInner {
                cur_iid,
                config,
                ref mut user_store,
                local_store: ref mut arg_store,
                ref arg_cache,
                ref mut b2b_pool,
                ref iop_state,
                ..
            } = *inner;

            log!(|self| log::Category::Own, log::Verbosity::Debug => var_mode, dst => "Register B2b load");

            match var_mode {
                // Handle explicit DOp transfer inside an IOp
                VarMode::User { iid, flag } => {
                    let state = &mut user_store[&(iid, flag)];

                    match state {
                        UserVarState::None => {
                            // Allocate temporary value in the B2B_pool if required
                            let dst_cid = match dst {
                                Some(cid) => cid,
                                None => b2b_pool.get_tagged(cur_iid),
                            };

                            *state = UserVarState::ReadPending(dst_cid);
                            None
                        }
                        UserVarState::ReadPending(_) => {
                            /* Already register nothing to do */
                            None
                        }
                        UserVarState::Received(payload) => {
                            // Value ready but not retrieved yet
                            // Register associated dma req
                            // Allocate temporary value in the B2B_pool if required
                            let dst_cid = match dst {
                                Some(cid) => cid,
                                None => b2b_pool.get_tagged(cur_iid),
                            };

                            // Construct DmaRequest
                            let from = (
                                payload.from_hid,
                                payload
                                    .slot
                                    .expect("Ld_b2b required notify with associated data"),
                            );
                            let to = (hpu_asm::NodeId(config.node_id), dst_cid);

                            // Update state
                            *state =
                                UserVarState::DmaPending(self.params.rtl_params.pc_params.pem_pc);

                            Some((var_mode.clone(), from, to))
                        }
                        UserVarState::DmaPending(_) => {
                            /* Do Nothing */
                            None
                        }
                        UserVarState::Resolved(_) => {
                            /* Do Nothing */
                            None
                        }
                    }
                }
                // Handle implicit load based on src operands position
                VarMode::ArgSrc { var, blk } => {
                    let var_iid = arg_store.src_iid(var, blk);
                    let var_hid = arg_store.src_hid(var, blk);
                    let var_cid = arg_store.src_cid(var, blk);

                    let state = arg_store.src_mut(var, blk);

                    match state {
                        SrcVarState::None => {
                            if iop_state.is_done(var_iid) {
                                // Check if present in the cache
                                if let Some(hit) = arg_cache.try_hit(var_iid, var_hid, var_cid) {
                                    // Value present in the cache, update internal state only
                                    *state = SrcVarState::Resolved(hit);
                                    None
                                } else {
                                    // Value ready but not retrieved yet
                                    // Update state and register associated dma req
                                    *state = SrcVarState::DmaPending(
                                        self.params.rtl_params.pc_params.pem_pc,
                                    );

                                    // Allocate temporary value in the B2B_pool if required
                                    let dst_cid = match dst {
                                        Some(cid) => cid,
                                        None => b2b_pool.get_tagged(cur_iid),
                                    };
                                    // Construct DmaRequest
                                    let from = (var_hid, var_cid);
                                    let to = (hpu_asm::NodeId(config.node_id), dst_cid);

                                    Some((var_mode.clone(), from, to))
                                }
                            } else {
                                // Value not ready
                                // Allocate temporary value in the B2B_pool if required
                                let dst_cid = match dst {
                                    Some(cid) => cid,
                                    None => b2b_pool.get_tagged(cur_iid),
                                };

                                *state = SrcVarState::ReadPending(dst_cid);
                                None
                            }
                        }
                        SrcVarState::ReadPending(_) => {
                            /* Already register nothing to do */
                            None
                        }
                        SrcVarState::DmaPending(_) => {
                            /* Do Nothing */
                            None
                        }
                        SrcVarState::Resolved(_) => {
                            /* Do Nothing */
                            None
                        }
                    }
                }
                // Handle implicit load based on destination generation
                // I.e. Current node own the slot but distant node generate the value
                VarMode::ArgDst { .. } => {
                    todo!("Handle this properly");
                }
            }
        };

        if let Some((var_mode, from, to)) = dma_req {
            self.start_dma(var_mode, from, to).await;
        }
    }

    async fn start_dma(
        &self,
        mode: VarMode,
        from: (hpu_asm::NodeId, hpu_asm::CtId),
        to: (hpu_asm::NodeId, hpu_asm::CtId),
    ) {
        log!(|self| log::Category::Own, log::Verbosity::Debug => mode, from, to => "Dma registered");
        let (from_hid, from_cid) = from;
        let (to_hid, to_cid) = to;

        let src_addr = self.cid_to_addr(from_cid);
        let dst_addr = self.cid_to_addr(to_cid);

        let dma_req = std::iter::zip(src_addr.into_iter(), dst_addr.into_iter())
            .map(|(src, dst)| {
                DmaBus::new_wrapped(
                    (from_hid.0, src),
                    (to_hid.0, dst),
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
        irq_dma_ctx.pdg_req.push_back((mode, to_cid));
    }

    /// Issue all dst notify order
    async fn flush_dst_notifyq(&self, for_iid: hpu_asm::IOpId) -> Result<(), anyhow::Error> {
        // Retrieved associated notify order
        let (notify_order, hid) = {
            let mut inner = self.inner.lock().unwrap();
            let hid = inner.config.node_id;

            let order = inner
                .dst_notifyq
                .pop_front()
                .expect("notifyq must have been register during context init");
            (order, hid)
        };

        // 2.a Execute Notify
        let notify_pkt = notify_order
            .into_iter()
            .map(
                |DstNotifyOrder {
                     var,
                     blk,
                     trgt_cid,
                     trgt_hid,
                     local_cid,
                 }| {
                    let ucore_pld = hpu_asm::UcorePayload {
                        mode: hpu_asm::UcorePayloadMode::Ucore(hpu_asm::UcoreFlag {
                            tid: var,
                            bid: blk,
                            trgt_cid,
                        }),
                        slot: Some(local_cid),
                        from_hid: hpu_asm::NodeId(hid),
                        iid: for_iid,
                    };

                    // Notify owner HpuNode
                    Network::new_wrapped(hid, trgt_hid.0, ucore_pld, None)
                },
            )
            .collect::<Vec<_>>();

        self.ctrl.tx().send_pkt_burst(notify_pkt).await?;
        Ok(())
    }

    /// Wait for all local dst load to be resolved
    async fn wait_owned_dst(&self, for_iid: hpu_asm::IOpId) -> Result<(), anyhow::Error> {
        // Retrieved list of owned dst blok
        let dst_blk = {
            let inner = self.inner.lock().unwrap();
            let hid = hpu_asm::NodeId(inner.config.node_id);

            inner.dst_store.get_owned(for_iid, hid)
        };

        for (var, blk) in dst_blk {
            let var_mode = VarMode::ArgDst {
                iid: for_iid,
                var,
                blk,
            };
            self.wait_resolved(&var_mode).await;
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
        iop_nodes: u8,
    ) -> Result<(), anyhow::Error> {
        // Flush dst_notify queue
        self.flush_dst_notifyq(iid)
            .await
            .expect("Error while flush Dst Notify queue");

        // wait all external generated dst that we own
        self.wait_owned_dst(iid)
            .await
            .expect("Error while waiting owned dst generated by external node");

        // Notify Other HpuNode of IOpEnd
        // This is usefull to check data availability for future IOp without cluttering
        // the ctrl communication channnel
        // => Notify All node that 1 actor over N has finished it's work
        let notify_order = self
            .params
            .cluster_nodes
            .iter()
            .filter(|n| **n != node_id.0)
            .map(|n| {
                let ucore_pld = hpu_asm::UcorePayload {
                    mode: hpu_asm::UcorePayloadMode::IOpDone(iop_nodes),
                    slot: None,
                    from_hid: node_id,
                    iid,
                };
                Network::new_wrapped(node_id.0, *n, ucore_pld, None)
            })
            .collect::<Vec<_>>();
        self.ctrl
            .tx()
            .send_pkt_burst(notify_order)
            .await
            .expect("Error while notifying cluster");

        // Update internal state
        let mut inner = self.inner.lock().unwrap();
        // register ack in local entry
        inner.iop_state.node_ack(iid, iop_nodes);

        // Release b2b_pool slot that belong to current iop
        inner.b2b_pool.release_tagged(iid);

        // Clean dst store for next iteration
        inner.dst_store.reset_iop(iid);
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
