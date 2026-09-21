//! Depict Hpu computation core

use ra2m::prelude::protocol::addr::{Addr, Pattern};
use ra2m::prelude::types::ClockDomain;
use ra2m::prelude::{protocol::membus, *};
use tfhe::tfhe_hpu_backend::prelude::glwe_lookuptable::HpuGlweLookuptable;
use zhc::sim::hpu as hpu_sim;
pub use zhc::sim::hpu::IscCommand;
use zhc::sim::{Dispatch, Simulatable, Tracer};

use tfhe::tfhe_hpu_backend::interface::io_dump::HexMem;
use tfhe::tfhe_hpu_backend::prelude::*;

use super::{DOpPayload, IOpPayload};
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use zhc::langs::doplang::{CtMem, CtReg, DopInstructionSet, LutRef, PtArg};

/// HpuCore parameters
#[derive(Debug, Clone)]
pub struct HpuCoreParams {
    // Compute parameters for tfhe-rs execution
    pub compute_params: HpuParameters,
    // Performance config for simulation model
    pub sim_config: zhc::config::hpu::HpuConfig,
    // Enable zhc::sim tracing feature
    pub sim_trace: zhc::sim::TracingLevel,

    /// Do trivial computation
    pub trivial: bool,
    /// Disable real tfhe-rs computation
    pub noops: bool,

    /// Dump register
    /// Used to dump execution trace for RTL simulation & debug
    /// Dump register after each update
    pub dump_reg: bool,

    // Used memory pseudo-channel
    pub lut_pc: MemKind,
    pub ct_pc: Vec<MemKind>,
    pub bsk_pc: Vec<MemKind>,
    pub ksk_pc: Vec<MemKind>,
    // Isc trace system
    // Psude-channel used for trace
    pub trace_pc: MemKind,
    // Associated MiB memory allocated for Trace
    pub trace_depth: usize,

    // Hbm position and range
    // Those values are used to compute physical addr from Hbm pc number
    // Hbm global offset for Dma xfer addr computation
    pub hbm_global_ofst: usize,
    // Hbm pc offset for Dma xfer addr computation
    pub hbm_pc_ofst: usize,
}

/// Store internal state of HpuCore module
struct HpuCoreInner {
    /// On-chip regfile
    regfile: Vec<HpuLweCiphertextOwned<u64>>,
    /// Program counter
    refilled_pc: usize,
    issued_pc: usize,
    retired_pc: usize,

    /// IOp context
    iop_ctx: VecDeque<IOpPayload>,

    /// Simulation perf model
    /// Bridge Hpu internal perf model inherited from hpu_compiler
    sim_model: hpu_sim::Hpu,
    sim_event: HpuEventStore<hpu_sim::Events>,
    sim_tracer: Tracer,
    /// Keep track of DOpPayload for later behav execution
    dop_map: HashMap<hpu_sim::DOpId, DOpPayload>,

    /// Keep track of trace offset
    /// Trace memory is written word by word in a wrapping manner
    trace_offset: usize,

    /// Tfhe server keys
    /// Read from memory after bsk_avail/ksk_avail register are set
    /// Conversion from Hpu->Cpu is costly. Thuse store it in the object to prevent extra
    /// computation
    /// Also store buffer for ks-pbs computation
    sks: Option<(
        LweKeyswitchKeyOwned<u32>,
        LweCiphertextOwned<u32>,
        NttLweBootstrapKeyOwned<u64>,
    )>,
}

impl HpuCoreInner {
    pub fn new(params: &HpuCoreParams, ra2m_clk_d: ClockDomain) -> Self {
        let regfile = (0..params.compute_params.regf_params.reg_nb)
            .map(|_| HpuLweCiphertextOwned::new(0, params.compute_params.clone()))
            .collect::<Vec<_>>();

        let iop_ctx = VecDeque::new();
        let sim_model =
            hpu_sim::Hpu::new(&params.sim_config.clone(), zhc::langs::hpulang::HpuId(0));
        let sim_event = HpuEventStore::new(ra2m_clk_d);
        let sim_tracer = Tracer::new();
        let dop_map = HashMap::new();
        let trace_offset = match params.trace_pc {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { pc } => params.hbm_global_ofst + pc * params.hbm_pc_ofst,
        };
        Self {
            regfile,
            refilled_pc: 0,
            issued_pc: 0,
            retired_pc: 0,
            iop_ctx,
            sim_model,
            sim_event,
            sim_tracer,
            dop_map,
            trace_offset,
            sks: None,
        }
    }
}

#[derive(Module)]
pub struct HpuCore {
    params: HpuCoreParams,
    props: Arc<module::Properties>,

    /// mem: Key and ciphertext
    #[port]
    mem: port::ReqRespPort<membus::MemBus>,

    /// iop_ctx: Received IOp context
    /// Use to construct correct report and IOp lifetime
    #[port]
    hpu_ctx: port::ReqRespPort<IOpPayload>,
    /// req: Received DOp request
    #[port]
    hpu_dop: port::ReqRespPort<DOpPayload>,
    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    inner: Mutex<HpuCoreInner>,
}

impl HpuCore {
    pub fn new(params: HpuCoreParams, props: module::Properties) -> Self {
        let props = Arc::new(props);
        Self {
            mem: port::ReqRespPort::new("mem", props.clone(), Some(1), None),
            hpu_ctx: port::ReqRespPort::new("hpu_ctx", props.clone(), None, None),
            hpu_dop: port::ReqRespPort::new("hpu_dop", props.clone(), None, None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(HpuCoreInner::new(&params, *props.clock_domain())),
            params,
            props,
        }
    }

    #[init]
    fn _init(self: Arc<Self>) {
        let mut prc = self.prc.lock().unwrap();
        let asc = self.clone();
        prc.push(spawn_prc!(Self::ctx_feed(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::inner_feed(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::simulate_inner(asc)));
    }
    #[teardown]
    fn _teardown(self: Arc<Self>) {
        if !matches!(self.params.sim_trace, zhc::sim::TracingLevel::None) {
            // Construct Path
            let filename = format!("{}_isc_sim.json", self.props.path());
            let trace_folder = Output::get_trace_folder();
            let trace_path = trace_folder.join(std::path::Path::new(&filename));
            let inner = self.inner.lock().unwrap();
            inner.sim_tracer.dump(
                zhc::utils::units::Cycle(self.props.clock_domain().from_tick(cur_tick()).into()),
                trace_path,
            );
        }
    }
}

impl HpuCore {
    async fn ctx_feed(self: Arc<Self>) {
        loop {
            let iop = self.hpu_ctx.rx().wait_pkt().await.unwrap_payload();

            // Insert IOp in local context
            {
                let mut inner = self.inner.lock().unwrap();
                inner.iop_ctx.push_back(iop);
            }
        }
    }
    async fn inner_feed(self: Arc<Self>) {
        loop {
            let dop = self
                .hpu_dop
                .rx()
                .wait_pkt_ep(None)
                .await
                .expect("Issue with DOpPayload xfer")
                .unwrap_payload();

            // Insert DOp is hpu_sim model
            {
                let mut inner = self.inner.lock().unwrap();
                let compiler_dop = into_compiler_view(inner.refilled_pc, &dop.inner);
                inner.dop_map.insert(compiler_dop.id, dop);
                inner
                    .sim_event
                    .dispatch(hpu_sim::Events::IscPushDOp(compiler_dop), None);
                // Increment program counter
                inner.refilled_pc += 1;
                event::Event::triggered(&forge_event_name!(|self| "SimInnerPushDOp"), None);
            }
        }
    }
    async fn simulate_inner(self: Arc<Self>) {
        {
            let mut inner = self.inner.lock().unwrap();
            let HpuCoreInner {
                ref mut sim_model,
                ref mut sim_event,
                ref mut sim_tracer,
                ..
            } = *inner;
            sim_model.power_up(sim_event);
            sim_model.report(
                zhc::utils::units::Cycle(self.props.clock_domain().from_tick(cur_tick()).into()),
                sim_tracer,
                zhc::sim::TracingLevel::None,
            );
        }

        loop {
            // Pop next batch if any
            let mut batch_trigger = {
                let mut inner = self.inner.lock().unwrap();
                inner.sim_event.pop_batch()
            };

            if !batch_trigger.is_empty() {
                // Wait for real simulation to match sim_model
                // And keep track of time for later delta-cycle resolution
                let delta_cycle = batch_trigger[0].at;
                delay::Delay::wait_until(
                    self.props.clock_domain().into_tick(delta_cycle.0.cycles()),
                )
                .await;

                // Resolve delta-cycle
                // NB: use to deferred queue for async tasks. Ease handling of inner mutex
                let mut deferred_exec = Vec::new();
                let mut deferred_retire = Vec::new();
                let mut deferred_trace = Vec::new();
                let mut deferred_timeout = Vec::new();
                loop {
                    let mut inner = self.inner.lock().unwrap();
                    let HpuCoreInner {
                        ref mut sim_model,
                        ref mut sim_event,
                        ref mut sim_tracer,
                        ref mut dop_map,
                        ..
                    } = *inner;

                    // Apply all trigger to sim_model
                    for trigger in batch_trigger.iter() {
                        // Populate hpu ccompiler simulation trace
                        if !matches!(self.params.sim_trace, zhc::sim::TracingLevel::None) {
                            sim_tracer.add_event(
                                self.params.sim_trace,
                                zhc::utils::units::Cycle(
                                    self.props.clock_domain().from_tick(cur_tick()).into(),
                                ),
                                &trigger.event,
                            );
                        }
                        // Handle event in inner hpuc simulation model
                        sim_model.handle(sim_event, trigger.clone());
                    }

                    // Hook back side effects in main simulation
                    while let Some(trigger) = batch_trigger.pop() {
                        // let mut inner = self.inner.lock().unwrap();
                        // let HpuCoreInner{ref mut sim_model, ref mut dop_map,..}= *inner;
                        match trigger.event {
                            hpu_sim::Events::NotifyIsc(dop_id, cmd) => {
                                // Retrieved HpuDop from id
                                let dop = dop_map.get_mut(&dop_id).unwrap_or_else(|| {
                                    panic!("Event registered on unknown DOpId {}", dop_id)
                                });
                                dop.append_handler(types::Handler::custom(*self.props.uid(), cmd));
                                // TODO move to dedicated trace_log file ?!
                                // println!("@{}[{:?}]::{cmd}: {dop}", cur_tick(), self.props.clock_domain().from_tick(cur_tick()));

                                // Append Hw trace data to deferred list
                                let props = sim_model
                                    .scheduler
                                    .get_slot_properties(dop_id)
                                    .unwrap_or(Default::default());
                                let trace = isc_trace::IscTrace {
                                    pe_reserved: 0,
                                    state: isc_trace::IscPoolState {
                                        pdg: props.pdg,
                                        rd_pdg: props.rd_pdg,
                                        vld: props.vld,
                                        cmd: match cmd {
                                            IscCommand::None => isc_trace::IscCommand::None,
                                            IscCommand::RdUnlock => isc_trace::IscCommand::RdUnlock,
                                            IscCommand::Retire => isc_trace::IscCommand::Retire,
                                            IscCommand::Refill => isc_trace::IscCommand::Refill,
                                            IscCommand::Issue => isc_trace::IscCommand::Issue,
                                        },
                                        wr_lock: props.wr_lock as u8,
                                        rd_lock: props.rd_lock as u8,
                                        issue_lock: props.issue_lock as u8,
                                        sync_id: 0, // TODO add proper sync_id tracking
                                    },
                                    // NB: DOp no longer has a standalone hex encoding (see the
                                    // comment on the dop asm dump in `ucore.rs`), so only the
                                    // asm view is available for tracing here.
                                    insn_hex: 0,
                                    insn_asm: Some(dop.inner.to_string()),
                                    timestamp: usize::from(
                                        self.props.clock_domain().from_tick(cur_tick()),
                                    ) as u32,
                                };
                                deferred_trace.extend(trace.into_bytes());

                                // Register Deferred task if any
                                match cmd {
                                    IscCommand::RdUnlock => {
                                        //NB: Operation behavior is executed at the rd_unlock staage to prevent later operation
                                        // to clutter the source operands. The dst register is then available in
                                        // advance, but not used before it's real availability due to wr_lock.
                                        // -> Another option would have been to buffer the source operands. However, due to the
                                        // operands size, we had preferred to move the behavioral execution at the rd_unlock
                                        // stage
                                        deferred_exec.push(dop_id);
                                    }
                                    IscCommand::Retire => {
                                        let dop = dop_map.remove(&dop_id).unwrap_or_else(|| {
                                            panic!("Tried to retired unknown DOpId {}", dop_id)
                                        });
                                        deferred_retire.push(dop);
                                    }
                                    _ => { /*Nothing to do is other cases */ }
                                }
                            }
                            hpu_sim::Events::NotifyStartOnTimeout { last_in } => {
                                deferred_timeout.push(last_in.id);
                            }
                            _ => { /*Nothing to do with other event*/ }
                        }
                    }

                    // Refill batch_trigger with delta-cycle event (i.e. immediate event that must be resolved in-cycle)
                    // Pop them one by one to prevent issue with inner simulation filtering
                    if let Some(dc_trigger) = sim_event.pop_delta(delta_cycle) {
                        batch_trigger.push(dc_trigger);
                    } else {
                        break;
                    }
                }

                // Deferred execution
                for dop_id in deferred_exec.into_iter() {
                    if !self.params.noops {
                        self.exec(dop_id).await.expect("Error with DOp execution");
                    }
                }

                // Deferred timeout
                // Only here for report purpose
                if !deferred_timeout.is_empty() {
                    self.inner.lock().unwrap().iop_ctx[0]
                        .batch_timeout
                        .append(&mut deferred_timeout);
                }

                // Deferred retired
                for dop in deferred_retire.into_iter() {
                    self.retire(dop).await.expect("Error with DOp retire");
                }
                // Deferred trace generation in trace_memory
                if !deferred_trace.is_empty() {
                    // Update trace_offset for next round
                    let addr = {
                        let mut inner = self.inner.lock().unwrap();
                        let addr = inner.trace_offset;
                        inner.trace_offset += std::mem::size_of::<u8>() * deferred_trace.len();
                        addr
                    };

                    // Use explicit request to disable timed mode
                    let trace_req = membus::MemBus::new_wrapped(
                        self.properties().uid(),
                        membus::Command::Write,
                        Addr::Phys(addr),
                        Pattern::Simple(deferred_trace.len().Byte()),
                        Some(&deferred_trace),
                        Some(PacketOptions {
                            timed: false,
                            ..Default::default()
                        }),
                    );
                    let _resp = self
                        .mem
                        .b_req_resp(trace_req)
                        .await
                        .expect("Error while writing trace memory");
                }
            } else {
                event::Event::wait(&forge_event_name!(|self| "SimInnerPushDOp")).await;
            }
        }
    }
}

use tfhe::core_crypto::algorithms::{
    lwe_ciphertext_add_assign, lwe_ciphertext_cleartext_mul_assign, lwe_ciphertext_opposite_assign,
    lwe_ciphertext_plaintext_add_assign, lwe_ciphertext_plaintext_sub_assign,
    lwe_ciphertext_sub_assign,
};
use tfhe::core_crypto::entities::{
    Cleartext, LweCiphertextOwned, LweCiphertextView, LweKeyswitchKey, NttLweBootstrapKey,
    Plaintext,
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::KeySwitch32PBSParameters;

impl HpuCore {
    fn trivial_decode<T: UnsignedInteger>(&self, body: T) -> T {
        let pbs_p = self.params.compute_params.pbs_params;
        let cleartext_and_padding_width = pbs_p.message_width + pbs_p.carry_width + 1;
        (body >> (T::BITS - cleartext_and_padding_width))
            & ((T::ONE << cleartext_and_padding_width) - T::ONE)
    }
    #[allow(dead_code)]
    fn trivial_encode<T: UnsignedInteger>(&self, clear: T) -> T {
        let pbs_p = self.params.compute_params.pbs_params;
        let cleartext_and_padding_width = pbs_p.message_width + pbs_p.carry_width + 1;
        clear << (T::BITS - cleartext_and_padding_width)
    }

    fn as_trivial<T: UnsignedInteger>(&self, hpu_ct: &HpuLweCiphertextView<T>) -> T {
        let body = hpu_ct[hpu_big_lwe_ciphertext_size(&self.params.compute_params) - 1];
        self.trivial_decode(body)
    }

    fn show_trivial_reg(&self, reg_id: CtReg) {
        let inner = self.inner.lock().unwrap();
        let ct = &inner.regfile[reg_id.addr as usize].as_view();
        let trivial = self.as_trivial::<u64>(ct);
        log!(|self| log::Category::Own, log::Verbosity::Debug => reg_id, trivial);
    }
}

impl HpuCore {
    async fn exec(&self, dop_id: hpu_sim::DOpId) -> Result<(), anyhow::Error> {
        // Perf modeling is handled by hpu_compiler model
        // This function is only in charge of behavioral computation
        // => All request across the architecture is made in untimed mode
        let untimed_options = PacketOptions {
            timed: false,
            ..Default::default()
        };
        let dop_inner = {
            let mut inner = self.inner.lock().unwrap();
            let dop = inner.dop_map.get(&dop_id).expect("Invalid DOpId");
            log!(|self| log::Category::Own, log::Verbosity::Debug => inner.issued_pc, dop);
            let dop_inner = dop.inner.clone();

            // Update IOp execution order
            inner.iop_ctx[0].exec_order.push(dop_inner.clone());
            dop_inner
        };

        // Read operands
        match &dop_inner {
            DopInstructionSet::LD_B2B { .. }
            | DopInstructionSet::WAIT { .. }
            | DopInstructionSet::NOTIFY { .. } => {
                panic!("Error: DOp {dop_inner:?} must have been handled by Ucore")
            }
            DopInstructionSet::_START | DopInstructionSet::_END => {}
            DopInstructionSet::SYNC { .. } => {}
            DopInstructionSet::LD { dst, src } => {
                let cid_ofst = match src {
                    CtMem::Io(io) => hpu_asm::CtId(io.addr),
                    _ => panic!("Template must have been resolved before execution"),
                };

                //1. Issue Mem read requests
                // FIXME: check behavior of b_req_resp_burst cf Ra2m doc
                // -> Use burst instead of two separate requests
                let mut ct_mem = Vec::new();
                let mem_req = self
                    .cid_to_addr(cid_ofst)
                    .into_iter()
                    .map(|addr| {
                        membus::MemBus::new_wrapped(
                            self.props.uid(),
                            membus::Command::Read,
                            addr,
                            self.ct_pc_pattern(),
                            None,
                            Some(untimed_options),
                        )
                    })
                    .collect::<Vec<_>>();

                for req in mem_req.into_iter() {
                    let resp = self.mem.b_req_resp(req).await?;
                    ct_mem.push(resp.unwrap_payload());
                }

                //2. Write data inside regfile
                // NB: Don't do both at same time (i.e mem_req, write in regfile) to prevent having a Mutex lock
                // across await points
                {
                    let mut inner = self.inner.lock().unwrap();
                    let regf_dst = &mut inner.regfile[dst.addr as usize];

                    for (hpu_slice, mem_slice) in
                        std::iter::zip(regf_dst.as_mut_view().into_container(), ct_mem)
                    {
                        // NB: Chunk are extended to enforce page align buffer
                        // -> To prevent error during copy, with shrink the mem buffer to
                        // the real   size before-hand
                        let data = mem_slice.data().as_slice();
                        let size_b = std::mem::size_of_val(hpu_slice);
                        let data_u64 = bytemuck::cast_slice::<u8, u64>(&data[0..size_b]);
                        hpu_slice.clone_from_slice(data_u64);
                    }
                }
                self.show_trivial_reg(*dst);
            }

            DopInstructionSet::ST { dst, src } => {
                //1. Read data inside regfile
                // NB: Don't do both at same time (i.e. read in regfile and write in memory) to prevent having a Mutex lock
                // across await points
                // TODO prevent cloning ?!
                let src_ct = {
                    let inner = self.inner.lock().unwrap();
                    inner.regfile[src.addr as usize].clone()
                };

                let cid_ofst = match dst {
                    CtMem::Io(io) => hpu_asm::CtId(io.addr),
                    _ => panic!("Template must have been resolved before execution"),
                };

                let ct_addrs = self.cid_to_addr(cid_ofst);

                //2. Built request and write data in memory
                // FIXME: check behavior of b_req_resp_burst cf Ra2m doc
                // -> Use burst instead of two separate requests
                for (hpu_slice, addr) in std::iter::zip(src_ct.as_view().into_container(), ct_addrs)
                {
                    let data_u8 = bytemuck::cast_slice::<u64, u8>(hpu_slice);

                    let mem_req = membus::MemBus::new_wrapped(
                        self.props.uid(),
                        membus::Command::Write,
                        addr,
                        Pattern::Simple(data_u8.len().Byte()), // Only write used data, not the memory used for padding
                        Some(data_u8),
                        Some(untimed_options),
                    );

                    self.mem.b_req_resp(mem_req).await?;
                }
                self.show_trivial_reg(*src);
            }

            DopInstructionSet::ADD { dst, src1, src2 } => {
                self.show_trivial_reg(*src1);
                self.show_trivial_reg(*src2);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(*src1);
                let cpu_s1 = self.reg2cpu(*src2);
                lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);
                self.cpu2reg(*dst, cpu_s0.as_view());

                self.show_trivial_reg(*dst);
            }
            DopInstructionSet::SUB { dst, src1, src2 } => {
                self.show_trivial_reg(*src1);
                self.show_trivial_reg(*src2);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(*src1);
                let cpu_s1 = self.reg2cpu(*src2);
                lwe_ciphertext_sub_assign(&mut cpu_s0, &cpu_s1);
                self.cpu2reg(*dst, cpu_s0.as_view());

                self.show_trivial_reg(*dst);
            }
            DopInstructionSet::MAC {
                dst,
                src1,
                src2,
                cst,
            } => {
                self.show_trivial_reg(*src1);
                self.show_trivial_reg(*src2);

                // NB: Srcs are used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(*src1);
                let cpu_s1 = self.reg2cpu(*src2);

                let mul_factor = match cst {
                    PtArg::Const(cst) => cst.val,
                    PtArg::Var(_) => panic!("Template must have been resolved before execution"),
                };
                lwe_ciphertext_cleartext_mul_assign(&mut cpu_s0, Cleartext(mul_factor as u64));
                lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);

                self.cpu2reg(*dst, cpu_s0.as_view());

                self.show_trivial_reg(*dst);
            }
            DopInstructionSet::ADDS { dst, src, cst } => {
                self.show_trivial_reg(*src);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(*src);
                let msg_cst = match cst {
                    PtArg::Const(cst) => cst.val as u64,
                    PtArg::Var(_) => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.compute_params.pbs_params.delta();
                lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(*dst, cpu_s0.as_view());

                self.show_trivial_reg(*dst);
            }
            DopInstructionSet::SUBS { dst, src, cst } => {
                self.show_trivial_reg(*src);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(*src);
                let msg_cst = match cst {
                    PtArg::Const(cst) => cst.val as u64,
                    PtArg::Var(_) => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.compute_params.pbs_params.delta();
                lwe_ciphertext_plaintext_sub_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(*dst, cpu_s0.as_view());

                self.show_trivial_reg(*dst);
            }
            DopInstructionSet::SSUB { dst, src, cst } => {
                self.show_trivial_reg(*src);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(*src);
                lwe_ciphertext_opposite_assign(&mut cpu_s0);
                let msg_cst = match cst {
                    PtArg::Const(cst) => cst.val as u64,
                    PtArg::Var(_) => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.compute_params.pbs_params.delta();
                lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(*dst, cpu_s0.as_view());

                self.show_trivial_reg(*dst);
            }
            DopInstructionSet::MULS { dst, src, cst } => {
                self.show_trivial_reg(*src);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(*src);
                let msg_cst = match cst {
                    PtArg::Const(cst) => cst.val as u64,
                    PtArg::Var(_) => panic!("Template must have been resolved before execution"),
                };
                lwe_ciphertext_cleartext_mul_assign(&mut cpu_s0, Cleartext(msg_cst));
                self.cpu2reg(*dst, cpu_s0.as_view());

                self.show_trivial_reg(*dst);
            }
            DopInstructionSet::PBS { dst, src, lut }
            | DopInstructionSet::PBS_F { dst, src, lut } => {
                self.apply_pbs2reg(1, *dst, *src, *lut).await?;
            }
            DopInstructionSet::PBS_ML2 { dst, src, lut }
            | DopInstructionSet::PBS_ML2_F { dst, src, lut } => {
                self.apply_pbs2reg(2, *dst, *src, *lut).await?;
            }
            DopInstructionSet::PBS_ML4 { dst, src, lut }
            | DopInstructionSet::PBS_ML4_F { dst, src, lut } => {
                self.apply_pbs2reg(4, *dst, *src, *lut).await?;
            }
            DopInstructionSet::PBS_ML8_F { dst, src, lut }
            | DopInstructionSet::PBS_ML8 { dst, src, lut } => {
                self.apply_pbs2reg(8, *dst, *src, *lut).await?;
            }
        }
        // Dump operation src/dst in file if required
        self.dump_op_reg(&dop_inner);

        // Update issued_pc
        self.inner.lock().unwrap().issued_pc += 1;
        Ok(())
    }

    async fn retire(&self, mut dop: DOpPayload) -> Result<(), anyhow::Error> {
        {
            let inner = self.inner.lock().unwrap();
            log!(|self| log::Category::Own, log::Verbosity::Debug => inner.retired_pc, dop);
        }

        // Dump DOpPayload to trace
        trace!(|self| trace::Kind::Pipeline => dop);

        if let DopInstructionSet::SYNC { is_inner, .. } = &dop.inner {
            // Skip report/context update on inner_sync
            if !is_inner {
                if !matches!(self.params.sim_trace, zhc::sim::TracingLevel::None) {
                    let mut inner = self.inner.lock().unwrap();
                    let HpuCoreInner {
                        ref mut sim_model,
                        ref mut sim_tracer,
                        ..
                    } = *inner;
                    sim_model.report(
                        zhc::utils::units::Cycle(
                            self.props.clock_domain().from_tick(cur_tick()).into(),
                        ),
                        sim_tracer,
                        self.params.sim_trace,
                    );
                }

                // Retrieved Current IOp context
                let iop = self
                    .inner
                    .lock()
                    .unwrap()
                    .iop_ctx
                    .pop_front()
                    .expect("Sync received without associated context");

                // Push iop in stream for lifetime tracking
                let iop_pkt = Packet::wrap_payload(
                    iop,
                    PacketOptions {
                        timed: false,
                        ..Default::default()
                    },
                );
                self.hpu_ctx.tx().fwd_pkt(iop_pkt).await;
            }

            // Notify Ucore with sync ack
            let ack_pkt = Packet::wrap_payload(
                dop,
                PacketOptions {
                    timed: false,
                    ..Default::default()
                },
            );
            self.hpu_dop.tx().fwd_pkt(ack_pkt).await;
        }

        // Update retired_pc
        self.inner.lock().unwrap().retired_pc += 1;

        Ok(())
    }

    /// Compute dst_rid <- Pbs(src_rid, lut)
    /// Use a function to prevent code duplication in PBS/PBS_F implementation
    /// NB: Current Pbs lookup function arn't reverted from Hbm memory
    /// TODO: Read PbsLut from Hbm instead of online generation based on Pbs Id
    async fn apply_pbs2reg(
        &self,
        lut_ml_nb: usize,
        dst_rid: CtReg,
        src_rid: CtReg,
        gid: LutRef,
    ) -> Result<(), anyhow::Error> {
        assert_eq!(
            dst_rid.mask,
            u8::MAX << (lut_ml_nb - 1),
            "Pbs destination register {dst_rid:?} must be aligned with lut_ml_nb {lut_ml_nb}"
        );

        let mut cpu_reg = self.reg2cpu(src_rid);

        // Read Lut
        let mut tfhe_lut = self.lut2cpu(gid).await?;

        if self.params.trivial {
            self.show_trivial_reg(src_rid);
        }

        self.with_server_key(|ksk, bfr_after_ks, bsk| {
            keyswitch_lwe_ciphertext_with_scalar_change(ksk, &cpu_reg, bfr_after_ks);

            let modulus_switch_type = self.params.compute_params.pbs_params.modulus_switch_type;

            let log_modulus = bsk.polynomial_size().to_blind_rotation_input_modulus_log();
            let bfr_after_ms = match modulus_switch_type {
                HpuModulusSwitchType::Standard => {
                    lwe_ciphertext_modulus_switch(bfr_after_ks.as_view(), log_modulus)
                }
                HpuModulusSwitchType::CenteredMeanNoiseReduction => {
                    lwe_ciphertext_centered_binary_modulus_switch(
                        bfr_after_ks.as_view(),
                        log_modulus,
                    )
                }
            };
            blind_rotate_ntt64_bnf_assign(&bfr_after_ms, &mut tfhe_lut, bsk);
        })
        .await?;

        // Compute ManyLut function stride
        let fn_stride = {
            let pbs_p = &self.params.compute_params.pbs_params;
            let modulus_sup = 1_usize << (pbs_p.message_width + pbs_p.carry_width);
            let box_size = pbs_p.polynomial_size / modulus_sup;
            // Max valid degree for a ciphertext when using the LUT we generate
            // If MaxDegree == 1, we can have two input values 0 and 1, so we need MaxDegree + 1
            // boxes
            let max_degree = modulus_sup / lut_ml_nb;
            max_degree * box_size
        };

        for fn_idx in 0..lut_ml_nb {
            let monomial_degree = MonomialDegree(fn_idx * fn_stride);
            extract_lwe_sample_from_glwe_ciphertext(&tfhe_lut, &mut cpu_reg, monomial_degree);
            let manylut_rid = CtReg::new(dst_rid.addr + fn_idx as u8);
            self.cpu2reg(manylut_rid, cpu_reg.as_view());
        }
        Ok(())
    }

    // NB: to prevent issues with borrow checker we have to clone the value from
    // the regfile. A clone is also required for conversion
    // Thus, directly cast value in Cpu version to prevent extra clone
    /// Extract a cpu value from register file
    fn reg2cpu(&self, reg_id: CtReg) -> LweCiphertextOwned<u64> {
        let inner = self.inner.lock().unwrap();
        let reg = inner.regfile[reg_id.addr as usize].as_view();
        LweCiphertextOwned::from(reg)
    }

    /// Insert a cpu value into the register file
    fn cpu2reg(&self, reg_id: CtReg, cpu: LweCiphertextView<u64>) {
        let mut inner = self.inner.lock().unwrap();
        let hpu =
            HpuLweCiphertextOwned::<u64>::create_from(cpu, self.params.compute_params.clone());
        std::iter::zip(
            inner.regfile[reg_id.addr as usize]
                .as_mut_view()
                .into_container(),
            hpu.into_container(),
        )
        .for_each(|(reg, hpu)| {
            reg.copy_from_slice(hpu.as_slice());
        });
    }

    /// Read Cpu lut from lut memory
    async fn lut2cpu(&self, gid: LutRef) -> Result<GlweCiphertextOwned<u64>, anyhow::Error> {
        let lut_size_b = page_align(
            hpu_glwe_lookuptable_size(&self.params.compute_params) * std::mem::size_of::<u64>(),
        );
        let lut_ofst = gid.id as usize * lut_size_b;

        // WARN: this only work if lut_mem is allocated at begin channel
        // TODO read offset from regmap register
        let lut_addr = Addr::Phys(match self.params.lut_pc {
            MemKind::Ddr { offset } => offset + lut_ofst,
            MemKind::Hbm { pc } => {
                self.params.hbm_global_ofst + pc * self.params.hbm_pc_ofst + lut_ofst
            }
        });
        let hpu_lut = {
            let mut container = HpuGlweLookuptable::new(0, self.params.compute_params.clone());
            let lut_mem = self
                .mem
                .b_req_resp(membus::MemBus::new_wrapped(
                    self.props.uid(),
                    membus::Command::Read,
                    lut_addr,
                    Pattern::Simple(lut_size_b.Byte()),
                    None,
                    Some(PacketOptions {
                        timed: false,
                        ..Default::default()
                    }),
                ))
                .await?
                .unwrap_payload();

            let lut_view = container.as_mut_view().into_container();
            let raw_data = lut_mem.data().as_slice();
            let size_b = std::mem::size_of_val(lut_view);
            let data_u64 = bytemuck::cast_slice::<u8, u64>(&raw_data[0..size_b]);
            lut_view.clone_from_slice(data_u64);
            container
        };
        Ok(GlweCiphertext::from(hpu_lut.as_view()))
    }

    /// Closure used to work with server_key
    /// Check the register state and extract sks from memory if needed
    async fn with_server_key(
        &self,
        f_on_sks: impl FnOnce(
            &LweKeyswitchKeyOwned<u32>,
            &mut LweCiphertextOwned<u32>,
            &NttLweBootstrapKeyOwned<u64>,
        ),
    ) -> Result<(), anyhow::Error> {
        let refresh = {
            let inner = self.inner.lock().unwrap();
            inner.iop_ctx[0].fresh_start || inner.sks.is_none()
        };

        // Retrieved key from memory in internal cache
        if refresh {
            // Perf modeling is handled by hpu_compiler model
            // This function is only in charge of behavioral computation
            // => All request across the architecture is made in untimed mode
            let untimed_options = PacketOptions {
                timed: false,
                ..Default::default()
            };
            log!(|self| log::Category::Own, log::Verbosity::Debug => => "Reload Bsk/Ksk from memory");
            // TODO check state of Bsk/Ksk in register
            // assert!(
            //     self.regmap.bsk_state().is_avail(),
            //     "Bsk avail bit was not set. Hw will hang on Pbs computation, Mockup panic instead"
            // );
            // assert!(
            //     self.regmap.ksk_state().is_avail(),
            //     "Ksk avail bit was not set. Hw will hang on Pbs computation, Mockup panic instead"
            // );

            // Extract HpuBsk /HpuKsk from hbm
            let hpu_bsk = {
                // Create Hpu Bsk container
                let mut bsk = HpuLweBootstrapKeyOwned::new(0, self.params.compute_params.clone());

                // Copy content from Hbm
                let hw_slice = bsk.as_mut_view().into_container();
                for (hpu, mem_kind) in std::iter::zip(hw_slice, self.params.bsk_pc.iter()) {
                    // View cache container as bytes
                    let hpu_u8 = bytemuck::cast_slice_mut::<u64, u8>(hpu);

                    let addr = Addr::Phys(match mem_kind {
                        MemKind::Ddr { offset } => *offset,
                        MemKind::Hbm { pc } => {
                            self.params.hbm_global_ofst + pc * self.params.hbm_pc_ofst
                        }
                    });

                    // TODO read offset from register
                    // let ofst = {
                    //     let [msb, lsb] = self.regmap.addr_offset().bsk[id];
                    //     ((msb as usize) << 32) + lsb as usize
                    // };

                    // Issue read request
                    let mem_req = membus::MemBus::new_wrapped(
                        self.props.uid(),
                        membus::Command::Read,
                        addr,
                        Pattern::Simple(hpu_u8.len().Byte()),
                        None,
                        Some(untimed_options),
                    );

                    let resp = self.mem.b_req_resp(mem_req).await?;
                    let data = resp.payload().data();
                    hpu_u8.clone_from_slice(data.as_slice());
                }
                bsk
            };
            let hpu_ksk = {
                // Create Hpu ksk container
                let mut ksk = HpuLweKeyswitchKeyOwned::new(0, self.params.compute_params.clone());

                // Copy content from Hbm
                let hw_slice = ksk.as_mut_view().into_container();
                for (hpu, mem_kind) in std::iter::zip(hw_slice, self.params.ksk_pc.iter()) {
                    // View cache container as bytes
                    let hpu_u8 = bytemuck::cast_slice_mut::<u64, u8>(hpu);

                    let addr = Addr::Phys(match mem_kind {
                        MemKind::Ddr { offset } => *offset,
                        MemKind::Hbm { pc } => {
                            self.params.hbm_global_ofst + pc * self.params.hbm_pc_ofst
                        }
                    });
                    // TODO read offset from register
                    // let ofst = {
                    //     let [msb, lsb] = self.regmap.addr_offset().ksk[id];
                    //     ((msb as usize) << 32) + lsb as usize
                    // };

                    // Issue read request
                    let mem_req = membus::MemBus::new_wrapped(
                        self.props.uid(),
                        membus::Command::Read,
                        addr,
                        Pattern::Simple(hpu_u8.len().Byte()),
                        None,
                        Some(untimed_options),
                    );

                    let resp = self.mem.b_req_resp(mem_req).await?;
                    let data = resp.payload().data();
                    hpu_u8.clone_from_slice(data.as_slice());
                }
                ksk
            };

            // Allocate Pbs intermediate buffer
            let pbs_p = KeySwitch32PBSParameters::from(self.params.compute_params.clone());
            let bfr_after_ks = LweCiphertext::new(
                0,
                pbs_p.lwe_dimension.to_lwe_size(),
                pbs_p.post_keyswitch_ciphertext_modulus(),
            );

            // Construct Cpu server_key version
            let cpu_bsk = NttLweBootstrapKey::from(hpu_bsk.as_view());
            let cpu_ksk = LweKeyswitchKey::from(hpu_ksk.as_view());
            let mut inner = self.inner.lock().unwrap();
            inner.sks = Some((cpu_ksk, bfr_after_ks, cpu_bsk));
        }

        // Apply function with local cache key
        let mut inner = self.inner.lock().unwrap();
        let (ksk, bfr_after_ks, bsk) = inner.sks.as_mut().unwrap();
        f_on_sks(ksk, bfr_after_ks, bsk);

        Ok(())
    }
}

// Definition of utilities function duplicated from Ucore
// TODO try to fuse theme somewhere ?!
impl HpuCore {
    /// Utility function to convert CtId in real Addr
    fn cid_to_addr(&self, cid: hpu_asm::CtId) -> Vec<Addr> {
        let ct_chunk_size_b = page_align(
            hpu_big_lwe_ciphertext_size(&self.params.compute_params)
                .div_ceil(self.params.compute_params.pc_params.pem_pc)
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
            hpu_big_lwe_ciphertext_size(&self.params.compute_params)
                .div_ceil(self.params.compute_params.pc_params.pem_pc)
                * std::mem::size_of::<u64>(),
        );

        Pattern::Simple(ct_chunk_size_b.Byte())
    }
}

impl HpuCore {
    fn dump_op_reg(&self, op: &DopInstructionSet) {
        if self.params.dump_reg {
            // Create folder-path
            let trace_folder = Output::get_trace_folder();
            let trace_path = trace_folder.join(std::path::Path::new(self.props.path()));

            // Dump register value
            let regid = match op {
                DopInstructionSet::LD { dst, .. } => dst.addr as usize,
                DopInstructionSet::ST { src, .. } => src.addr as usize,
                DopInstructionSet::ADDS { dst, .. } => dst.addr as usize,
                DopInstructionSet::SUBS { dst, .. } => dst.addr as usize,
                DopInstructionSet::SSUB { dst, .. } => dst.addr as usize,
                DopInstructionSet::MULS { dst, .. } => dst.addr as usize,
                DopInstructionSet::ADD { dst, .. } => dst.addr as usize,
                DopInstructionSet::SUB { dst, .. } => dst.addr as usize,
                DopInstructionSet::MAC { dst, .. } => dst.addr as usize,
                DopInstructionSet::PBS { dst, .. } => dst.addr as usize,
                DopInstructionSet::PBS_ML2 { dst, .. } => dst.addr as usize,
                DopInstructionSet::PBS_ML4 { dst, .. } => dst.addr as usize,
                DopInstructionSet::PBS_ML8 { dst, .. } => dst.addr as usize,
                DopInstructionSet::PBS_F { dst, .. } => dst.addr as usize,
                DopInstructionSet::PBS_ML2_F { dst, .. } => dst.addr as usize,
                DopInstructionSet::PBS_ML4_F { dst, .. } => dst.addr as usize,
                DopInstructionSet::PBS_ML8_F { dst, .. } => dst.addr as usize,
                _ => return,
            };
            {
                let inner = self.inner.lock().unwrap();
                let regf = inner.regfile[regid].as_view();

                let base_path = format!(
                    "{}/blwe/run/blwe_isc{}_reg",
                    trace_path.to_str().unwrap(),
                    inner.issued_pc,
                );
                self.dump_regf(regf, &base_path);
            }
        }
    }

    /// Dump associated regf value in a file
    fn dump_regf(&self, regf: HpuLweCiphertextView<u64>, base_path: &str) {
        // Iterate over slice
        regf.into_container()
            .iter()
            .enumerate()
            .for_each(|(i, slice)| {
                // Create file-path
                let file_path = format!("{base_path}_{:0>1x}.hex", i);

                let mut wr_f = open_wr_file(&file_path);

                writeln!(&mut wr_f, "# LweCiphertext slice #{}", i).unwrap();
                // Compact Blwe on 32b if possible
                if self.params.compute_params.ntt_params.ct_width <= u32::BITS {
                    let slice_32b = slice.iter().map(|x| *x as u32).collect::<Vec<u32>>();
                    slice_32b.as_slice().write_hex(
                        &mut wr_f,
                        self.params.compute_params.pc_params.pem_bytes_w,
                        Some("XX"),
                    );
                } else {
                    slice.write_hex(
                        &mut wr_f,
                        self.params.compute_params.pc_params.pem_bytes_w,
                        Some("XX"),
                    );
                }
            });
    }
}

// A set of structure used to bridge zhc::sim simulation model within Ra2m
// simulation kernel
struct HpuEventStore<E: zhc::sim::Event> {
    ra2m_clk_d: ClockDomain,
    triggers: BinaryHeap<std::cmp::Reverse<zhc::sim::Trigger<E>>>,
}

impl<E: zhc::sim::Event> HpuEventStore<E> {
    fn new(ra2m_clk_d: ClockDomain) -> Self {
        Self {
            ra2m_clk_d,
            triggers: BinaryHeap::new(),
        }
    }

    fn pop_batch(&mut self) -> Vec<zhc::sim::Trigger<E>> {
        let mut batch = Vec::new();

        // Extract targeted cycle
        let pop_at =
            if let Some(std::cmp::Reverse(zhc::sim::Trigger { at, .. })) = self.triggers.peek() {
                *at
            } else {
                // early return
                return batch;
            };

        // Pop all subsequent Ord::Equal events
        while let Some(std::cmp::Reverse(next)) = self.triggers.peek() {
            if next.at.cmp(&pop_at) == std::cmp::Ordering::Equal {
                batch.push(self.triggers.pop().unwrap().0);
            } else {
                break;
            }
        }

        batch
    }

    fn pop_delta(&mut self, delta: zhc::utils::units::Cycle) -> Option<zhc::sim::Trigger<E>> {
        // Pop next subsequent Ord::Equal events if any
        if let Some(std::cmp::Reverse(next)) = self.triggers.peek() {
            if next.at.cmp(&delta) == std::cmp::Ordering::Equal {
                Some(self.triggers.pop().unwrap().0)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl<E: zhc::sim::Event> zhc::sim::Dispatch for HpuEventStore<E> {
    type Event = E;

    fn contains_event(
        &self,
        event: &Self::Event,
        filter: Option<zhc::utils::units::Cycle>,
    ) -> bool {
        if let Some(filter_at) = filter.as_ref() {
            self.triggers
                .iter()
                .any(|std::cmp::Reverse(zhc::sim::Trigger { at, event: e })| {
                    (e == event) && (at == filter_at)
                })
        } else {
            self.triggers
                .iter()
                .map(|trigger| &trigger.0.event)
                .any(|e| e == event)
        }
    }

    fn dispatch(&mut self, event: Self::Event, delay: Option<zhc::utils::units::Cycle>) {
        let ra2m_cycle = self.ra2m_clk_d.from_tick(cur_tick());
        let dispatch_cycle = zhc::utils::units::Cycle(ra2m_cycle.into())
            + delay.unwrap_or(zhc::utils::units::Cycle::ZERO);

        // NB: Discard event dispatch in the current cycle if already present
        if !self.contains_event(&event, Some(dispatch_cycle)) {
            self.triggers.push(std::cmp::Reverse(zhc::sim::Trigger {
                at: dispatch_cycle,
                event,
            }));
        }
    }
}

// Convert zhc DOp representation to zhc::sim::DOp (its perf/scheduling model)
// Required current hpu_core context for DOpId extraction
fn into_compiler_view(pc: usize, asm_dop: &DopInstructionSet) -> hpu_sim::DOp {
    debug_assert!(
        !matches!(
            asm_dop,
            DopInstructionSet::LD_B2B { .. }
                | DopInstructionSet::WAIT { .. }
                | DopInstructionSet::NOTIFY { .. }
        ),
        "Error: DOp {asm_dop:?} must have been handled by Ucore"
    );
    hpu_sim::DOp {
        raw: asm_dop.clone(),
        id: hpu_sim::DOpId(pc),
    }
}

// Utilities function to handle filesystem
fn create_dir(file_path: &str) {
    let path = std::path::Path::new(&file_path);
    if let Some(dir_p) = path.parent() {
        std::fs::create_dir_all(dir_p).unwrap();
    }
}

pub fn open_wr_file(file_path: &str) -> std::fs::File {
    create_dir(file_path);
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(file_path)
        .unwrap()
}
