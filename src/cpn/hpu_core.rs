//! Depict Hpu computation core

use hpuc_sim::hpu as hpu_sim;
pub use hpu_sim::IscCommand;
use hpuc_langs;
use hpuc_sim::{Simulatable, Dispatch, Tracer};
use ra2m::prelude::protocol::addr::{Addr, Pattern};
use ra2m::prelude::types::ClockDomain;
use ra2m::prelude::{protocol::membus, *};

use tfhe::tfhe_hpu_backend::asm::PbsLut;
use tfhe::tfhe_hpu_backend::prelude::*;

use super::DOpPayload;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};

use hpu_asm::ToHex;

/// HpuCore parameters
#[derive(Debug, Clone)]
pub struct HpuCoreParams {
    // Rtl parameters for tfhe-rs execution
    pub rtl_params: HpuParameters,
    // Configuration parameters for simulation model
    pub sim_config: hpu_sim::HpuConfig,
    // Enable hpuc_sim tracing feature
    pub sim_trace: bool, 

    /// Do trivial computation
    pub trivial: bool,

    // Used memory pseudo-channel
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
    pc: usize,

    /// Simulation perf model
    /// Bridge Hpu internal perf model inherited from hpu_compiler
    sim_model: hpu_sim::Hpu,
    sim_event: HpuEventStore<hpu_sim::Events>,
    sim_tracer: Tracer<hpu_sim::Events>,
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
        let regfile = (0..params.rtl_params.regf_params.reg_nb)
            .map(|_| HpuLweCiphertextOwned::new(0, params.rtl_params.clone()))
            .collect::<Vec<_>>();
        let sim_model = hpu_sim::Hpu::new(&params.sim_config.clone());
        let sim_event = HpuEventStore::new(ra2m_clk_d);
        let sim_tracer = Tracer::new();
        let dop_map = HashMap::new();
        let trace_offset = match params.trace_pc {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { pc } => {
                params.hbm_global_ofst + pc * params.hbm_pc_ofst
            },
        };
        Self { regfile, pc: 0, sim_model, sim_event, sim_tracer,  dop_map, trace_offset, sks: None}
    }
}

#[derive(Module)]
pub struct HpuCore {
    params: HpuCoreParams,
    props: Arc<module::Properties>,

    /// mem: Key and ciphertext
    #[port]
    mem: port::ReqRespPort<membus::MemBus>,

    /// req: Received DOp request
    #[port]
    req: port::SlavePort<DOpPayload>,
    /// outbound: Send DOp Ack
    #[port]
    ack: port::MasterPort<DOpPayload>,
    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    inner: Mutex<HpuCoreInner>,
}

impl HpuCore {
    pub fn new(params: HpuCoreParams, props: module::Properties) -> Self {
        let props = Arc::new(props);
        Self {
            mem: port::ReqRespPort::new("mem", props.clone(), Some(1), None),
            req: port::SlavePort::new("req", props.clone(), None, None),
            ack: port::MasterPort::new("ack", props.clone(), None, None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(HpuCoreInner::new(&params, props.clock_domain().clone())),
            params,
            props,
        }
    }

    #[init]
    fn _init(self: Arc<Self>) {
        let mut prc = self.prc.lock().unwrap();
        let asc = self.clone();
        prc.push(spawn_prc!(Self::loopback(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::simulate_inner(asc)));
    }
    #[teardown]
    fn _teardown(self: Arc<Self>) {
        if self.params.sim_trace {
            // Construct Path
            let filename = format!("{}_isc_sim.json", self.props.path());
            let trace_folder = Output::get_trace_folder();
            let trace_path = trace_folder.join(std::path::Path::new(&filename));
            let inner = self.inner.lock().unwrap();
            inner.sim_tracer.dump(hpuc_sim::Cycle(self.props.clock_domain().from_tick(cur_tick()).into()),  trace_path);
        }
    }
}

impl HpuCore {
    async fn loopback(self: Arc<Self>) {
        loop {
            let dop = self
                .req
                .wait_pkt_ep(None)
                .await
                .expect("Issue with DOpPayload xfer")
                .unwrap_payload();

            // Insert DOp is hpu_sim model
            {
                let mut inner = self.inner.lock().unwrap();
                let compiler_dop = into_compiler_view(inner.pc, &dop.inner);
                inner.dop_map.insert(compiler_dop.id, dop);
                inner.sim_event.dispatch(hpu_sim::Events::IscPushDOps(vec![compiler_dop]), None);
                // Increment program counter
                inner.pc += 1;
                event::Event::triggered(&forge_event_name!(|self| "SimInnerPushDOp"), None);
            }


        }
    }
    async fn simulate_inner(self: Arc<Self>) {
        {
            let mut inner = self.inner.lock().unwrap();
            let HpuCoreInner{ref mut sim_model, ref mut sim_event,ref mut sim_tracer,..}= *inner;
            sim_model.power_up(sim_event);
            sim_model.report(hpuc_sim::Cycle(self.props.clock_domain().from_tick(cur_tick()).into()), sim_tracer);
        }

        loop {
            // Pop next batch if any
            let mut batch_trigger = {
                let mut inner = self.inner.lock().unwrap();
                inner.sim_event.pop_batch()
            };

            if !batch_trigger.is_empty(){
                // Wait for real simulation to match sim_model
                // And keep track of time for later delta-cycle resolution
                let delta_cycle = batch_trigger[0].at;
                delay::Delay::wait_until(self.props.clock_domain().into_tick(delta_cycle.0.cycles())).await;

                // Resolve delta-cycle
                // NB: use to deffered queue for async tasks. Ease handling of inner mutex
                let mut deferred_exec = Vec::new();
                let mut deferred_retire = Vec::new();
                let mut deferred_trace = Vec::new();
                loop {
                    let mut inner = self.inner.lock().unwrap();
                    let HpuCoreInner{ref mut sim_model, ref mut sim_event,ref mut sim_tracer, ref mut dop_map, ..}= *inner;

                    // Apply all trigger to sim_model
                    for trigger in batch_trigger.iter() {
                        // Populate hpuc simulation trace
                        if self.params.sim_trace {
                            sim_tracer.add_event(hpuc_sim::Cycle(self.props.clock_domain().from_tick(cur_tick()).into()), &trigger.event);
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
                                    let dop = dop_map.get_mut(&dop_id).unwrap_or_else(|| panic!("Event registered on unknown DOpId {}", dop_id));
                                    dop.append_handler(types::Handler::custom(*self.props.uid(), cmd.clone()));
                                    // TODO move to dedicated trace_log file ?!
                                    // println!("@{}[{:?}]::{cmd}: {dop}", cur_tick(), self.props.clock_domain().from_tick(cur_tick()));

                                    // Append Hw trace data to deferred list
                                    let props = sim_model.scheduler.get_slot_properties(dop_id).unwrap_or(Default::default());
                                    let trace = isc_trace::IscTrace{ state: isc_trace::IscPoolState{pdg:props.pdg,rd_pdg: props.rd_pdg,vld:props.vld, cmd:match cmd {
                                        IscCommand::None => isc_trace::IscCommand::None,
                                        IscCommand::RdUnlock => isc_trace::IscCommand::RdUnlock,
                                        IscCommand::Retire => isc_trace::IscCommand::Retire,
                                        IscCommand::Refill => isc_trace::IscCommand::Refill,
                                        IscCommand::Issue => isc_trace::IscCommand::Issue,
                                    }, wr_lock: props.wr_lock, rd_lock: props.rd_lock, issue_lock: props.issue_lock, sync_id: 0 }, insn_hex: dop.inner.to_hex(), insn_asm: None, timestamp: usize::from(self.props.clock_domain().from_tick(cur_tick())) as u32};
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
                                        },
                                        IscCommand::Retire => {
                                            let dop = dop_map.remove(&dop_id).unwrap_or_else(|| panic!("Tried to retired unknown DOpId {}", dop_id));
                                            deferred_retire.push(dop);
                                        },
                                        _ => {/*Nothing to do is other cases */}
                                    }
                                    },
                                    hpu_sim::Events::NotifyStartOnTimeout{last_in} => {
                                        println!("Dop start on timeout {last_in}");
                                        // TODO add counter and report number of timeout per IOp
                                    }
                                    _ => {/*Nothing to do with other event*/},
                            }
                    }

                    // Refill batch_trigger with delta-cycle event (i.e. immediat event that must be resolved in-cycle)
                    // Pop them one by one to prevent issue with inner simulation filtering
                    if let Some(dc_trigger) = sim_event.pop_delta(delta_cycle) {
                        batch_trigger.push(dc_trigger);
                    } else {
                        break;
                    }
                }

                // Deferred execution
                for dop_id in deferred_exec.into_iter() {
                    self.exec(dop_id).await.expect("Error with DOp execution")
                }

                // Deferred retired
                for dop in deferred_retire.into_iter() {
                    self.retire(dop).await.expect("Error with DOp retire");
                }
                // Deferred trace generation in trace_memory
                if 0 != deferred_trace.len() {
                    // Update trace_offset for next round
                    let addr = {
                        let mut inner = self.inner.lock().unwrap();
                        let addr = inner.trace_offset;
                        inner.trace_offset += std::mem::size_of::<u8>()* deferred_trace.len();
                        addr
                        };
                    self.mem
                        .write_bytes(self.properties(), addr, &deferred_trace)
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
use tfhe::core_crypto::hpu::glwe_lookuptable::create_hpu_lookuptable;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::KeySwitch32PBSParameters;


impl HpuCore {
    fn trivial_decode<T: UnsignedInteger>(&self, body: T) -> T {
        let pbs_p = self.params.rtl_params.pbs_params;
        let cleartext_and_padding_width = pbs_p.message_width + pbs_p.carry_width + 1;
        (body >> (T::BITS - cleartext_and_padding_width))
            & ((T::ONE << cleartext_and_padding_width) - T::ONE)
    }
    #[allow(dead_code)]
    fn trivial_encode<T: UnsignedInteger>(&self, clear: T) -> T {
        let pbs_p = self.params.rtl_params.pbs_params;
        let cleartext_and_padding_width = pbs_p.message_width + pbs_p.carry_width + 1;
        clear << (T::BITS - cleartext_and_padding_width)
    }

    fn as_trivial<T: UnsignedInteger>(&self, hpu_ct: &HpuLweCiphertextView<T>) -> T {
        let body = hpu_ct[hpu_big_lwe_ciphertext_size(&self.params.rtl_params) - 1];
        self.trivial_decode(body)
    }

    fn show_trivial_reg(&self, reg_id: hpu_asm::RegId) {
        let inner = self.inner.lock().unwrap();
        let ct = &inner.regfile[reg_id.0 as usize].as_view();
        let trivial = self.as_trivial::<u64>(ct);
        log!(|self| log::Category::Own, log::Verbosity::Debug=> reg_id, trivial);
    }
}

impl HpuCore {
    async fn exec(&self, dop_id: hpu_sim::DOpId) -> Result<(), anyhow::Error> {
        let dop_inner = {
            let inner = self.inner.lock().unwrap();
            let dop = inner.dop_map.get(&dop_id).expect("Invalid DOpId");
            log!(|self| log::Category::Own, log::Verbosity::Debug => inner.pc, dop);
            dop.inner.clone()
        };

        // Read operands
        match &dop_inner {
            hpu_asm::DOp::LD_B2B(_) | hpu_asm::DOp::WAIT(_) | hpu_asm::DOp::NOTIFY(_)=> {
                panic!("Error: DOp {dop_inner:?} must have been handled by Ucore")
            }
            hpu_asm::DOp::SYNC(_) => {}
            hpu_asm::DOp::LD(hpu_asm::dop::DOpLd(insn)) => {
                let cid_ofst = match insn.slot {
                    hpu_asm::MemId::Addr(ct_id) => ct_id,
                    _ => panic!("Template must have been resolved before execution"),
                };


                //1. Issue Mem read requests
                // FIXME: check behavior of b_req_resp_burst cf Ra2m doc
                // -> Use burst instead of two separate requests
                let mut ct_mem = Vec::new();
                let mem_req= self.cid_to_addr(cid_ofst).into_iter().map(|addr| 
                    membus::MemBus::new_wrapped(self.props.uid(), membus::Command::Read, addr, self.ct_pc_pattern(),None, None)
                ).collect::<Vec<_>>();

                for req in mem_req.into_iter() {
                    let resp = self.mem.b_req_resp(req).await?;
                    ct_mem.push(resp.unwrap_payload());
                }

                //2. Write data inside regfile
                // NB: Don't do both at same time (i.e mem_req, write in regfile) to prevent having a Mutex lock
                // across await points
                {
                    let mut inner = self.inner.lock().unwrap();
                    let dst = &mut inner.regfile[insn.rid.0 as usize];

                    for (hpu_slice, mem_slice ) in std::iter::zip(
                        dst.as_mut_view().into_container(),
                        ct_mem,
                    ) {
                        // NB: Chunk are extended to enforce page align buffer
                        // -> To prevent error during copy, with shrink the mem buffer to
                        // the real   size before-hand
                        let data = mem_slice.data().as_slice();
                        let size_b = std::mem::size_of_val(hpu_slice);
                        let data_u64 = bytemuck::cast_slice::<u8, u64>(&data[0..size_b]);
                        hpu_slice.clone_from_slice(data_u64);
                    }
                }
                self.show_trivial_reg(insn.rid);
                
            }

            hpu_asm::DOp::ST(hpu_asm::dop::DOpSt(insn)) => {

                //1. Read data inside regfile
                // NB: Don't do both at same time (i.e. read in regfile and write in memory) to prevent having a Mutex lock
                // across await points
                // TODO prevent cloning ?!
                let src = {
                    let inner = self.inner.lock().unwrap();
                    inner.regfile[insn.rid.0 as usize].clone()
                };

                let cid_ofst = match insn.slot {
                    hpu_asm::MemId::Addr(ct_id) => ct_id,
                    _ => panic!("Template must have been resolved before execution"),
                };

                let ct_addrs = self.cid_to_addr(cid_ofst);

                //2. Built request and write data in memory
                // FIXME: check behavior of b_req_resp_burst cf Ra2m doc
                // -> Use burst instead of two separate requests
                for (hpu_slice, addr) in std::iter::zip(
                    src.as_view().into_container(),
                    ct_addrs,
                ) {
                    let data_u8 = bytemuck::cast_slice::<u64, u8>(hpu_slice);

                    let mem_req = membus::MemBus::new_wrapped(
                        self.props.uid(),
                         membus::Command::Write,
                        addr,
                        Pattern::Simple(data_u8.len().Byte()), // Only write used data, not the memory used for padding
                        Some(data_u8),
                         None);

                     self.mem.b_req_resp(mem_req).await?;
                }
                self.show_trivial_reg(insn.rid);
                
            }

            hpu_asm::DOp::ADD(op_impl) => {
                self.show_trivial_reg(op_impl.0.src0_rid);
                self.show_trivial_reg(op_impl.0.src1_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src0_rid);
                let cpu_s1 = self.reg2cpu(op_impl.0.src1_rid);
                lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
                
            }
            hpu_asm::DOp::SUB(op_impl) => {
                self.show_trivial_reg(op_impl.0.src0_rid);
                self.show_trivial_reg(op_impl.0.src1_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src0_rid);
                let cpu_s1 = self.reg2cpu(op_impl.0.src1_rid);
                lwe_ciphertext_sub_assign(&mut cpu_s0, &cpu_s1);
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
                
            }
            hpu_asm::DOp::MAC(op_impl) => {
                self.show_trivial_reg(op_impl.0.src0_rid);
                self.show_trivial_reg(op_impl.0.src1_rid);

                // NB: Srcs are used as destination to prevent useless allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src0_rid);
                let cpu_s1 = self.reg2cpu(op_impl.0.src1_rid);

                lwe_ciphertext_cleartext_mul_assign(
                    &mut cpu_s0,
                    Cleartext(op_impl.0.mul_factor.0 as u64),
                );
                lwe_ciphertext_add_assign(&mut cpu_s0, &cpu_s1);

                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
                
            }
            hpu_asm::DOp::ADDS(op_impl) => {
                self.show_trivial_reg(op_impl.0.src_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src_rid);
                let msg_cst = match op_impl.0.msg_cst {
                    hpu_asm::ImmId::Cst(cst) => cst as u64,
                    _ => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
                
            }
            hpu_asm::DOp::SUBS(op_impl) => {
                self.show_trivial_reg(op_impl.0.src_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src_rid);
                let msg_cst = match op_impl.0.msg_cst {
                    hpu_asm::ImmId::Cst(cst) => cst as u64,
                    _ => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_sub_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
                
            }
            hpu_asm::DOp::SSUB(op_impl) => {
                self.show_trivial_reg(op_impl.0.src_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src_rid);
                lwe_ciphertext_opposite_assign(&mut cpu_s0);
                let msg_cst = match op_impl.0.msg_cst {
                    hpu_asm::ImmId::Cst(cst) => cst as u64,
                    _ => panic!("Template must have been resolved before execution"),
                };
                let msg_encoded = msg_cst * self.params.rtl_params.pbs_params.delta();
                lwe_ciphertext_plaintext_add_assign(&mut cpu_s0, Plaintext(msg_encoded));
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
                
            }
            hpu_asm::DOp::MULS(op_impl) => {
                self.show_trivial_reg(op_impl.0.src_rid);

                // NB: The first src is used as destination to prevent useless
                // allocation
                let mut cpu_s0 = self.reg2cpu(op_impl.0.src_rid);
                let msg_cst = match op_impl.0.msg_cst {
                    hpu_asm::ImmId::Cst(cst) => cst as u64,
                    _ => panic!("Template must have been resolved before execution"),
                };
                lwe_ciphertext_cleartext_mul_assign(&mut cpu_s0, Cleartext(msg_cst));
                self.cpu2reg(op_impl.0.dst_rid, cpu_s0.as_view());

                self.show_trivial_reg(op_impl.0.dst_rid);
                
            }
            hpu_asm::DOp::PBS(op_impl) => {
                self.apply_pbs2reg(1, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?;
                
            }
            hpu_asm::DOp::PBS_ML2(op_impl) => {
                self.apply_pbs2reg(2, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?;
                
            }
            hpu_asm::DOp::PBS_ML4(op_impl) => {
                self.apply_pbs2reg(4, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?;
                
            }
            hpu_asm::DOp::PBS_ML8(op_impl) => {
                self.apply_pbs2reg(8, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?;
                
            }
            hpu_asm::DOp::PBS_F(op_impl) => {
                self.apply_pbs2reg(1, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?;
                
            }
            hpu_asm::DOp::PBS_ML2_F(op_impl) => {
                self.apply_pbs2reg(2, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?;
                
            }
            hpu_asm::DOp::PBS_ML4_F(op_impl) => {
                self.apply_pbs2reg(4, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?;
                
            }
            hpu_asm::DOp::PBS_ML8_F(op_impl) => {
                self.apply_pbs2reg(8, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?;
                
            }
        }
        // Dump operation src/dst in file if required
        self.dump_op_reg(&dop_inner);
        Ok(())
    }

    async fn retire(&self, dop: DOpPayload) -> Result<(), anyhow::Error> {
        {
            let inner = self.inner.lock().unwrap();
            log!(|self| log::Category::Own, log::Verbosity::Debug => inner.pc, dop);
        }

        let dop_inner = dop.inner.clone();
        // Read operands
        match &dop_inner {
            hpu_asm::DOp::SYNC(_) => {
                if self.params.sim_trace {
                    let mut inner = self.inner.lock().unwrap();
                    let HpuCoreInner{ref mut sim_model, ref mut sim_tracer,..}= *inner;
                    sim_model.report(hpuc_sim::Cycle(self.props.clock_domain().from_tick(cur_tick()).into()), sim_tracer);
                }

                // Push ack in stream
                let ack_pkt = Packet::wrap_payload(dop, Default::default());
                self.ack.fwd_pkt(ack_pkt).await;

                // Generate executed DOp order
                // TODO enable back report
                // #[cfg(feature = "isc-order-check")]
                // if let Some(dump_path) = self.options.dump_out.as_ref() {
                //     let iopcode = iop.opcode().0;

                //     let asm_p = format!("{dump_path}/dop/dop_executed_{iopcode:0>2x}.asm");
                //     let hex_p = format!("{dump_path}/dop/dop_executed_{iopcode:0>2x}.hex");
                //     let dop_prog = hpu_asm::Program::new(
                //         self.dops_exec_order
                //             .iter()
                //             .map(|op| hpu_asm::AsmOp::Stmt(op.clone()))
                //             .collect::<Vec<_>>(),
                //     );
                //     dop_prog.write_asm(&asm_p).unwrap();
                //     dop_prog.write_hex(&hex_p).unwrap();
                // }

                // TODO enable back report
                // // Generate report
                // let time_rpt = self.isc.time_report();
                // let dop_rpt = self.isc.dop_report();
                // let pe_rpt = self.isc.pe_report();
                // tracing::info!("Report for IOp: {}", iop);
                // tracing::info!("{time_rpt:?}");
                // tracing::info!("{dop_rpt}");
                // tracing::info!("{pe_rpt}");

                // if let Some(mut rpt_file) = self.options.report_file((&iop).into()) {
                //     writeln!(rpt_file, "Report for IOp: {}", iop).unwrap();
                //     writeln!(rpt_file, "{time_rpt:?}").unwrap();
                //     writeln!(rpt_file, "{dop_rpt}").unwrap();
                //     writeln!(rpt_file, "{pe_rpt}").unwrap();
                // }

                // TODO enable back trace
                // -> Use ra2m trace feature
                // let trace = self.isc.reset_trace();
                // trace.iter().for_each(|pt| tracing::trace!("{pt}"));
                // if let Some(mut trace_file) = self.options.report_trace((&iop).into()) {
                //     let json_string =
                //         serde_json::to_string(&trace).expect("Could not serialize trace");
                //     writeln!(trace_file, "{}", json_string).unwrap();
                // }
            }
            _ => {}
        }
        Ok(())
    }

    /// Compute dst_rid <- Pbs(src_rid, lut)
    /// Use a function to prevent code duplication in PBS/PBS_F implementation
    /// NB: Current Pbs lookup function arn't reverted from Hbm memory
    /// TODO: Read PbsLut from Hbm instead of online generation based on Pbs Id
    async fn apply_pbs2reg(
        & self,
        opcode_lut_nb: u8,
        dst_rid: hpu_asm::RegId,
        src_rid: hpu_asm::RegId,
        gid: hpu_asm::PbsGid,
    ) -> Result<(), anyhow::Error> {
        let mut cpu_reg = self.reg2cpu(src_rid);
        let lut = hpu_asm::Pbs::from_hex(gid).expect("Invalid PBS Gid");
        // TODO use an assert or a simple warning
        // In practice, hardware apply the LUT but extract only opcode_lut_nb Ct
        assert_eq!(
            lut.lut_nb(),
            opcode_lut_nb,
            "ERROR: Mismatch between PBS ML configuration and selected Lut."
        );

        assert_eq!(
            dst_rid.0,
            (dst_rid.0 >> lut.lut_lg()) << lut.lut_lg(),
            "Pbs destination register must be aligned with lut size"
        );

        // Generate Lut
        let hpu_lut = create_hpu_lookuptable(&self.params.rtl_params, &lut);
        let tfhe_lut = GlweCiphertext::from(hpu_lut.as_view());

        // Compute Lut properties
        let (modulus_sup, box_size, fn_stride) = {
            let pbs_p = &self.params.rtl_params.pbs_params;
            let modulus_sup = 1_usize << (pbs_p.message_width + pbs_p.carry_width);
            let box_size = pbs_p.polynomial_size / modulus_sup;
            // Max valid degree for a ciphertext when using the LUT we generate
            // If MaxDegree == 1, we can have two input values 0 and 1, so we need MaxDegree + 1
            // boxes
            let max_degree = modulus_sup / lut.lut_nb() as usize;
            let fn_stride = max_degree * box_size;
            (modulus_sup, box_size, fn_stride)
        };

        if self.params.trivial {
            self.show_trivial_reg(src_rid);

            let ct_value = self.trivial_decode(*cpu_reg.get_body().data) as usize;
            let padding_bit_set = ct_value >= modulus_sup;
            let first_index_in_lut = {
                let ct_value = ct_value % modulus_sup;
                ct_value * box_size
            };

            for fn_idx in 0..lut.lut_nb() as usize {
                let (index_in_lut, wrap_around_negation) = {
                    let raw_index = first_index_in_lut + fn_idx * fn_stride;
                    let wrap_around = raw_index / tfhe_lut.polynomial_size().0;
                    (
                        raw_index % tfhe_lut.polynomial_size().0,
                        (wrap_around % 2) == 1,
                    )
                };
                let pbs_out = if padding_bit_set ^ wrap_around_negation {
                    tfhe_lut.get_body().as_ref()[index_in_lut].wrapping_neg()
                } else {
                    tfhe_lut.get_body().as_ref()[index_in_lut]
                };

                *cpu_reg.get_mut_body().data = pbs_out;

                let manylut_rid = hpu_asm::RegId(dst_rid.0 + fn_idx as u8);
                self.cpu2reg(manylut_rid, cpu_reg.as_view());
                self.show_trivial_reg(manylut_rid);
            }
        } else {
            let mut tfhe_lut = tfhe_lut;
            self.with_server_key(|ksk, bfr_after_ks, bsk|
            {
                keyswitch_lwe_ciphertext_with_scalar_change(ksk, &cpu_reg, bfr_after_ks);

            let modulus_switch_type = self.params.rtl_params.pbs_params.modulus_switch_type;

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
            }).await?;

            assert_eq!(
                dst_rid.0,
                (dst_rid.0 >> lut.lut_lg()) << lut.lut_lg(),
                "Pbs destination register must be aligned with lut size"
            );

            // Compute ManyLut function stride
            let fn_stride = {
                let pbs_p = &self.params.rtl_params.pbs_params;
                let modulus_sup = 1_usize << (pbs_p.message_width + pbs_p.carry_width);
                let box_size = pbs_p.polynomial_size / modulus_sup;
                // Max valid degree for a ciphertext when using the LUT we generate
                // If MaxDegree == 1, we can have two input values 0 and 1, so we need MaxDegree + 1
                // boxes
                let max_degree = modulus_sup / lut.lut_nb() as usize;
                max_degree * box_size
            };

            for fn_idx in 0..lut.lut_nb() as usize {
                let monomial_degree = MonomialDegree(fn_idx * fn_stride);
                extract_lwe_sample_from_glwe_ciphertext(&tfhe_lut, &mut cpu_reg, monomial_degree);
                let manylut_rid = hpu_asm::RegId(dst_rid.0 + fn_idx as u8);
                self.cpu2reg(manylut_rid, cpu_reg.as_view());
            }
        }
        Ok(())
    }


    // NB: to prevent issues with borrow checker we have to clone the value from
    // the regfile. A clone is also required for conversion
    // Thus, directly cast value in Cpu version to prevent extra clone
    /// Extract a cpu value from register file
    fn reg2cpu(&self, reg_id: hpu_asm::RegId) -> LweCiphertextOwned<u64> {
        let inner = self.inner.lock().unwrap();
        let reg = inner.regfile[reg_id.0 as usize].as_view();
        LweCiphertextOwned::from(reg)
    }

    /// Insert a cpu value into the register file
    fn cpu2reg(&self, reg_id: hpu_asm::RegId, cpu: LweCiphertextView<u64>) {
        let mut inner = self.inner.lock().unwrap();
        let hpu = HpuLweCiphertextOwned::<u64>::create_from(cpu, self.params.rtl_params.clone());
        std::iter::zip(
            inner.regfile[reg_id.0 as usize]
                .as_mut_view()
                .into_container(),
            hpu.into_container(),
        )
        .for_each(|(reg, hpu)| {
            reg.copy_from_slice(hpu.as_slice());
        });
    }

    /// Closure used to work with server_key
    /// Check the register state and extract sks from memory if needed
    async fn with_server_key(
        &self,
        f_on_sks: impl FnOnce(
        &LweKeyswitchKeyOwned<u32>,
        &mut LweCiphertextOwned<u32>,
        &NttLweBootstrapKeyOwned<u64>,)
    ) -> Result<(), anyhow::Error> {
        let sks_is_none= {
            let inner = self.inner.lock().unwrap();
            inner.sks.is_none()
                };
        // Retrieved key from memory in internal cache
        if sks_is_none {
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
                let mut bsk = HpuLweBootstrapKeyOwned::new(0, self.params.rtl_params.clone());

                // Copy content from Hbm
                let hw_slice = bsk.as_mut_view().into_container();
                for (hpu, mem_kind) in 
                std::iter::zip(hw_slice, self.params.bsk_pc.iter()){

                        // View cache container as bytes
                        let hpu_u8= bytemuck::cast_slice_mut::<u64, u8>(hpu);

                        let addr= Addr::Phys(match mem_kind {
                            MemKind::Ddr { offset } => *offset,
                            MemKind::Hbm { pc } => self.params.hbm_global_ofst + pc * self.params.hbm_pc_ofst,
                        });

                        // TODO read offset from register
                        // let ofst = {
                        //     let [msb, lsb] = self.regmap.addr_offset().bsk[id];
                        //     ((msb as usize) << 32) + lsb as usize
                        // };

                        // Issue read request
                        let mem_req = membus::MemBus::new_wrapped(self.props.uid(), membus::Command::Read,
                                addr,
                                        Pattern::Simple(hpu_u8.len().Byte()),None, None);

                            let resp = self.mem.b_req_resp(mem_req).await?;
                            let data = resp.payload().data();
                            hpu_u8.clone_from_slice(data.as_slice());
                    }
                bsk
            };
            let hpu_ksk = {
                // Create Hpu ksk container
                let mut ksk = HpuLweKeyswitchKeyOwned::new(0, self.params.rtl_params.clone());

                // Copy content from Hbm
                let hw_slice = ksk.as_mut_view().into_container();
                for (hpu, mem_kind) in 
                std::iter::zip(hw_slice, self.params.ksk_pc.iter()) {
                        // View cache container as bytes
                        let hpu_u8= bytemuck::cast_slice_mut::<u64, u8>(hpu);

                        let addr= Addr::Phys(match mem_kind {
                            MemKind::Ddr { offset } => *offset,
                            MemKind::Hbm { pc } => self.params.hbm_global_ofst + pc * self.params.hbm_pc_ofst,
                        });
                        // TODO read offset from register
                        // let ofst = {
                        //     let [msb, lsb] = self.regmap.addr_offset().ksk[id];
                        //     ((msb as usize) << 32) + lsb as usize
                        // };

                        // Issue read request
                        let mem_req = membus::MemBus::new_wrapped(self.props.uid(), membus::Command::Read,
                                addr,
                                        Pattern::Simple(hpu_u8.len().Byte()),None, None);

                            let resp = self.mem.b_req_resp(mem_req).await?;
                            let data = resp.payload().data();
                            hpu_u8.clone_from_slice(data.as_slice());
                    }
                ksk
            };

            // Allocate Pbs intermediate buffer
            let pbs_p = KeySwitch32PBSParameters::from(self.params.rtl_params.clone());
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
        let ct_chunk_size_b = 
            page_align(
                hpu_big_lwe_ciphertext_size(&self.params.rtl_params)
                    .div_ceil(self.params.rtl_params.pc_params.pem_pc)
                    * std::mem::size_of::<u64>());
        // Ct_ofst is equal over PC
        let ct_ofst = cid.0 as usize
            * ct_chunk_size_b;

        self.params.ct_pc.iter().map(|mem_kind| 
            // WARN: this only work if ct_mem is allocated at begin of each channel
            // TODO read offset from regmap register
            
            Addr::Phys(match mem_kind {
                MemKind::Ddr { offset } => offset + ct_ofst,
                MemKind::Hbm { pc } => self.params.hbm_global_ofst + pc* self.params.hbm_pc_ofst + ct_ofst,
            })).collect::<Vec<_>>()
    }

    /// Utility function to get hpu ciphertext pattern for one Pc
    fn ct_pc_pattern(&self) -> Pattern {
        let ct_chunk_size_b = 
            page_align(
                hpu_big_lwe_ciphertext_size(&self.params.rtl_params)
                    .div_ceil(self.params.rtl_params.pc_params.pem_pc)
                    * std::mem::size_of::<u64>());

        Pattern::Simple(ct_chunk_size_b.Byte())
    }
}


impl HpuCore {
    fn dump_op_reg(&self, op: &hpu_asm::DOp) {
    //     if self.options.dump_out.is_some() && self.options.dump_reg {
    //         let dump_out = self.options.dump_out.as_ref().unwrap();

    //         // Dump register value
    //         let regid = match op {
    //             hpu_asm::DOp::LD(hpu_asm::dop::DOpLd(inner))
    //             | hpu_asm::DOp::ST(hpu_asm::dop::DOpSt(inner)) => inner.rid.0 as usize,
    //             hpu_asm::DOp::ADDS(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::SUBS(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::SSUB(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::MULS(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::ADD(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::SUB(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::MAC(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::PBS(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::PBS_ML2(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::PBS_ML4(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::PBS_ML8(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::PBS_F(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::PBS_ML2_F(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::PBS_ML4_F(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             hpu_asm::DOp::PBS_ML8_F(op_impl) => op_impl.0.dst_rid.0 as usize,
    //             _ => return,
    //         };
    //         let regf = self.regfile[regid].as_view();

    //         // Create base-path
    //         let base_path = format!("{}/blwe/run/blwe_isc{}_reg", dump_out, self.pc,);
    //         self.dump_regf(regf, &base_path);
    //     }
    }

    /// Dump associated regf value in a file
    fn dump_regf(&self, regf: HpuLweCiphertextView<u64>, base_path: &str) {
        // // Iterate over slice
        // regf.into_container()
        //     .iter()
        //     .enumerate()
        //     .for_each(|(i, slice)| {
        //         // Create file-path
        //         let file_path = format!("{base_path}_{:0>1x}.hex", i);
        //         let mut wr_f = MockupOptions::open_wr_file(&file_path);

        //         writeln!(&mut wr_f, "# LweCiphertext slice #{}", i).unwrap();
        //         // Compact Blwe on 32b if possible
        //         if self.params.rtl_params.ntt_params.ct_width <= u32::BITS {
        //             let slice_32b = slice.iter().map(|x| *x as u32).collect::<Vec<u32>>();
        //             slice_32b.as_slice().write_hex(
        //                 &mut wr_f,
        //                 self.params.rtl_params.pc_params.pem_bytes_w,
        //                 Some("XX"),
        //             );
        //         } else {
        //             slice.write_hex(
        //                 &mut wr_f,
        //                 self.params.rtl_params.pc_params.pem_bytes_w,
        //                 Some("XX"),
        //             );
        //         }
        //     });
    }
}


// A set of structure used to bridge hpuc_sim simulation model within Ra2m
// simulation kernel
struct HpuEventStore<E: hpuc_sim::Event>{
    ra2m_clk_d: ClockDomain,
    triggers: BinaryHeap<hpuc_sim::Trigger<E>>
}

impl<E: hpuc_sim::Event> HpuEventStore<E> {
    fn new(ra2m_clk_d: ClockDomain) -> Self {
        Self{
            ra2m_clk_d,
            triggers: BinaryHeap::new()
        }
    }

    fn pop_batch(&mut self) -> Vec<hpuc_sim::Trigger<E>> {
      let mut batch = Vec::new();

      // Extract targeted cycle
      let pop_at = if let Some(hpuc_sim::Trigger{at,..}) = self.triggers.peek() { 
          at.clone()
      } else {// early return
          return batch;
      };

    // Pop all subsequent Ord::Equal events
    while let Some(next) = self.triggers.peek() {
        if next.at.cmp(&pop_at) == std::cmp::Ordering::Equal {
            batch.push(self.triggers.pop().unwrap());
        } else {
            break;
        }
    }

    batch
    }

    fn pop_delta(&mut self, delta: hpuc_sim::Cycle) -> Option<hpuc_sim::Trigger<E>> {
        // Pop next subsequent Ord::Equal events if any
        if let Some(next) = self.triggers.peek() {
            if next.at.cmp(&delta) == std::cmp::Ordering::Equal {
                Some(self.triggers.pop().unwrap())
            } else {
                None
            }
        } else {None}
    }
}

impl<E: hpuc_sim::Event> hpuc_sim::Dispatch for HpuEventStore<E> {
    type Event = E;

    fn contains_event(&self, event: &Self::Event, filter: Option<hpuc_sim::Cycle>) -> bool {
        if let Some(filter_at) = filter.as_ref() {
            self.triggers
                .iter()
                .find(|hpuc_sim::Trigger{ at, event: e }| (e == event) && (at == filter_at))
                .is_some()
        } else {
            self.triggers
                .iter()
                .map(|trigger| &trigger.event)
                .find(|e| *e == event)
                .is_some()
        }

    }

    fn dispatch(&mut self, event: Self::Event, delay: Option<hpuc_sim::Cycle>) {
        let ra2m_cycle = self.ra2m_clk_d.from_tick(cur_tick());
        let dispatch_cycle = hpuc_sim::Cycle(ra2m_cycle.into()) + delay.unwrap_or(hpuc_sim::Cycle::ZERO);

        // NB: Discard event dispach in the current cycle if already present
        if !self.contains_event(&event, Some(dispatch_cycle)) {
            self.triggers.push(hpuc_sim::Trigger {
                at: dispatch_cycle,
                event,
            });
        }
    }

}


// Convert tfhe-rs::DOp in hpuc_sim::DOp
// Required current hpu_core context for DOpId extraction
fn into_compiler_view(pc: usize, asm_dop: &hpu_asm::DOp) -> hpu_sim::DOp{
    use hpuc_langs::doplang::{Argument, MASK_NONE, MASK_PBS2, MASK_PBS4, MASK_PBS8};
    use hpu_sim::{DOp, DOpId, RawDOp};

    let id = DOpId(pc);
    let raw = match asm_dop {
        hpu_asm::DOp::ADD(inner) => RawDOp::ADD{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src1: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src0_rid.0 as usize},
            src2: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src1_rid.0 as usize},

        },
        hpu_asm::DOp::SUB(inner) => RawDOp::SUB{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src1: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src0_rid.0 as usize},
            src2: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src1_rid.0 as usize},
            },
        hpu_asm::DOp::MAC(inner) => RawDOp::MAC{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src1: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src0_rid.0 as usize},
            src2: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src1_rid.0 as usize},
            cst: Argument::PtConst{val: inner.0.mul_factor.0 as usize},
        },
        hpu_asm::DOp::ADDS(inner) => RawDOp::ADDS{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src_rid.0 as usize},
            cst: Argument::PtConst { val: inner.0.msg_cst.unwrap_cst() as usize},
        },
        hpu_asm::DOp::SUBS(inner) => RawDOp::SUBS{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src_rid.0 as usize},
            cst: Argument::PtConst { val: inner.0.msg_cst.unwrap_cst() as usize},
        },
        hpu_asm::DOp::SSUB(inner) => RawDOp::SSUB{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src_rid.0 as usize},
            cst: Argument::PtConst { val: inner.0.msg_cst.unwrap_cst() as usize},
        },
        hpu_asm::DOp::MULS(inner) => RawDOp::MULS{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src_rid.0 as usize},
            cst: Argument::PtConst { val: inner.0.msg_cst.unwrap_cst() as usize},
        },
        hpu_asm::DOp::LD(inner) => RawDOp::LD{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.rid.0 as usize},
            src: Argument::CtIo{addr: inner.0.slot.unwrap_addr() as usize}
        },
        hpu_asm::DOp::ST(inner) => RawDOp::ST{
            dst: Argument::CtIo{addr: inner.0.slot.unwrap_addr() as usize},
            src: Argument::CtReg{mask: MASK_NONE, addr: inner.0.rid.0 as usize},
        },
        hpu_asm::DOp::SYNC(_inner) => RawDOp::SYNC,
        hpu_asm::DOp::PBS(inner) => RawDOp::PBS{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src_rid.0 as usize},
            lut: Argument::LutId {id: inner.0.gid.0 as usize,},

        },
        hpu_asm::DOp::PBS_F(inner) => RawDOp::PBS_F{
            dst: Argument::CtReg{mask: MASK_NONE, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_NONE, addr: inner.0.src_rid.0 as usize},
            lut: Argument::LutId {id: inner.0.gid.0 as usize,},
        },
        hpu_asm::DOp::PBS_ML2(inner) => RawDOp::PBS_ML2{
            dst: Argument::CtReg{mask: MASK_PBS2, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_PBS2, addr: inner.0.src_rid.0 as usize},
            lut: Argument::LutId {id: inner.0.gid.0 as usize,},
        },
        hpu_asm::DOp::PBS_ML2_F(inner) => RawDOp::PBS_ML2_F{
            dst: Argument::CtReg{mask: MASK_PBS2, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_PBS2, addr: inner.0.src_rid.0 as usize},
            lut: Argument::LutId {id: inner.0.gid.0 as usize,},
        },
        hpu_asm::DOp::PBS_ML4(inner) => RawDOp::PBS_ML4{
            dst: Argument::CtReg{mask: MASK_PBS4, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_PBS4, addr: inner.0.src_rid.0 as usize},
            lut: Argument::LutId {id: inner.0.gid.0 as usize,},
        },
        hpu_asm::DOp::PBS_ML4_F(inner) => RawDOp::PBS_ML4_F{
            dst: Argument::CtReg{mask: MASK_PBS4, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_PBS4, addr: inner.0.src_rid.0 as usize},
            lut: Argument::LutId {id: inner.0.gid.0 as usize,},
        },
        hpu_asm::DOp::PBS_ML8(inner) => RawDOp::PBS_ML8{
            dst: Argument::CtReg{mask: MASK_PBS8, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_PBS8, addr: inner.0.src_rid.0 as usize},
            lut: Argument::LutId {id: inner.0.gid.0 as usize,},
        },
        hpu_asm::DOp::PBS_ML8_F(inner) => RawDOp::PBS_ML8_F{
            dst: Argument::CtReg{mask: MASK_PBS8, addr: inner.0.dst_rid.0 as usize},
            src: Argument::CtReg{mask: MASK_PBS8, addr: inner.0.src_rid.0 as usize},
            lut: Argument::LutId {id: inner.0.gid.0 as usize,},
        },
        hpu_asm::DOp::LD_B2B(_) | hpu_asm::DOp::WAIT(_) | hpu_asm::DOp::NOTIFY(_)=> {
            panic!("Error: DOp {asm_dop:?} must have been handled by Ucore")
        }
    };
    DOp{ raw, id }
}
