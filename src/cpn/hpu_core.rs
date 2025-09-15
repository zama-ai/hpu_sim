//! Depict Hpu computation core

use ra2m::prelude::protocol::addr::{Addr, Pattern};
use ra2m::prelude::protocol::membus::Command;
use ra2m::prelude::{protocol::membus::MemBus, *};

use tfhe::tfhe_hpu_backend::asm::PbsLut;
use tfhe::tfhe_hpu_backend::prelude::*;

use super::DOpPayload;
use std::sync::{Arc, Mutex};

/// HpuCore parameters
#[derive(Debug, Clone)]
pub struct HpuCoreParams {
    pub rtl_params: HpuParameters,

    // Used memory pseudo-channel
    pub ct_pc: Vec<MemKind>,
    pub bsk_pc: Vec<MemKind>,
    pub ksk_pc: Vec<MemKind>,
    // Hbm global offset for Dma xfer addr computation
    pub hbm_global_ofst: usize,
    // Hbm pc offset for Dma xfer addr computation
    pub hbm_pc_ofst: usize,

    /// Do trivial computation
    pub trivial: bool,
}

/// Store internal state of HpuCore module
struct HpuCoreInner {
    /// On-chip regfile
    regfile: Vec<HpuLweCiphertextOwned<u64>>,
    /// Program counter
    pc: usize,


    
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
    pub fn new(params: &HpuCoreParams) -> Self {
        let regfile = (0..params.rtl_params.regf_params.reg_nb)
            .map(|_| HpuLweCiphertextOwned::new(0, params.rtl_params.clone()))
            .collect::<Vec<_>>();

        Self { regfile, pc: 0 , sks: None}
    }
}

#[derive(Module)]
pub struct HpuCore {
    params: HpuCoreParams,
    props: Arc<module::Properties>,

    /// mem: Key and ciphertext
    #[port]
    mem: port::ReqRespPort<MemBus>,

    /// req: Received DOp request
    #[port]
    req: port::SlavePort<DOpPayload>,
    /// outbound: Send DOp Ack
    #[port]
    ack: port::MasterPort<DOpPayload>,
    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    inner: Mutex<HpuCoreInner>,
}

#[default_teardown]
impl HpuCore {
    pub fn new(params: HpuCoreParams, props: module::Properties) -> Self {
        let props = Arc::new(props);
        Self {
            mem: port::ReqRespPort::new("mem", props.clone(), Some(1), None),
            req: port::SlavePort::new("req", props.clone(), None, None),
            ack: port::MasterPort::new("ack", props.clone(), None, None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(HpuCoreInner::new(&params)),
            params,
            props,
        }
    }

    #[init]
    fn _init(self: Arc<Self>) {
        let mut prc = self.prc.lock().unwrap();
        let asc = self.clone();
        prc.push(spawn_prc!(Self::loopback(asc)));
    }
}

impl HpuCore {
    async fn loopback(self: Arc<Self>) {
        loop {
            // NB: Should use the wait_pkt_ep version but DOp don't implement the RxStatus
            let dop = self
                .req
                .wait_pkt_ep(None)
                .await
                .expect("Issue with DOpPayload xfer")
                .unwrap_payload();

            log!(|self| log::Category::Own, log::Verbosity::Info => dop);
            match &dop.inner {
                hpu_asm::DOp::SYNC(_dop_sync) => {
                    // loopback DOp as ack
                    let ack_pkt = Packet::wrap_payload(dop, Default::default());
                    self.ack.fwd_pkt(ack_pkt).await;
                }
                _ => {}
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
use tfhe::tfhe_hpu_backend::fw::isc_sim::{PeConfigStore, Scheduler};

use tfhe::tfhe_hpu_backend::interface::io_dump::HexMem;
use tfhe::tfhe_hpu_backend::prelude::*;

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
    async fn exec(&mut self, dop: DOpPayload) -> Result<(), anyhow::Error> {
        {
            let inner = self.inner.lock().unwrap();
            log!(|self| log::Category::Own, log::Verbosity::Debug => inner.pc, dop);
        }

        let dop_inner = dop.inner.clone();
        // Read operands
        match &dop_inner {
            hpu_asm::DOp::SYNC(_) => {
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
            hpu_asm::DOp::LD_B2B(_) | hpu_asm::DOp::WAIT(_) | hpu_asm::DOp::NOTIFY(_)=> {
                panic!("Error: DOp {dop:?} must have been handled by Ucore")
            }

            hpu_asm::DOp::LD(hpu_asm::dop::DOpLd(insn)) => {
                let mut inner = self.inner.lock().unwrap();
                let dst = &mut inner.regfile[insn.rid.0 as usize];
                let cid_ofst = match insn.slot {
                    hpu_asm::MemId::Addr(ct_id) => ct_id,
                    _ => panic!("Template must have been resolved before execution"),
                };

                let ct_addrs = self.cid_to_addr(cid_ofst);

                // FIXME: check behavior of b_req_resp_burst cf Ra2m doc
                // -> Use burst instead of two separate requests
                for (hpu_slice, addr) in std::iter::zip(
                    dst.as_mut_view().into_container(),
                    ct_addrs,
                ) {
                let mem_req = MemBus::new_wrapped(self.props.uid(), Command::Read,
                        addr,
                                self.ct_pc_pattern(),None, None);

                    let resp = self.mem.b_req_resp(mem_req).await?;
                    let data = resp.payload().data();
                    // NB: Chunk are extended to enforce page align buffer
                    // -> To prevent error during copy, with shrink the mem buffer to
                    // the real   size before-hand
                    let size_b = std::mem::size_of_val(data);
                    let data_u64 = bytemuck::cast_slice::<u8, u64>(&data.as_slice()[0..size_b]);
                    hpu_slice.clone_from_slice(data_u64);
                }
                self.show_trivial_reg(insn.rid);
            }

            hpu_asm::DOp::ST(hpu_asm::dop::DOpSt(insn)) => {
                let inner = self.inner.lock().unwrap();

                let src= &inner.regfile[insn.rid.0 as usize];
                let cid_ofst = match insn.slot {
                    hpu_asm::MemId::Addr(ct_id) => ct_id,
                    _ => panic!("Template must have been resolved before execution"),
                };

                let ct_addrs = self.cid_to_addr( cid_ofst);

                // FIXME: check behavior of b_req_resp_burst cf Ra2m doc
                // -> Use burst instead of two separate requests
                for (hpu_slice, addr) in std::iter::zip(
                    src.as_view().into_container(),
                    ct_addrs,
                ) {
                    let data_u8 = bytemuck::cast_slice::<u64, u8>(&hpu_slice);

                    let mem_req = MemBus::new_wrapped(self.props.uid(), Command::Write,
                        addr,
                                self.ct_pc_pattern(),Some(data_u8), None);

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
                self.apply_pbs2reg(1, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?
            }
            hpu_asm::DOp::PBS_ML2(op_impl) => {
                self.apply_pbs2reg(2, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?
            }
            hpu_asm::DOp::PBS_ML4(op_impl) => {
                self.apply_pbs2reg(4, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?
            }
            hpu_asm::DOp::PBS_ML8(op_impl) => {
                self.apply_pbs2reg(8, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?
            }
            hpu_asm::DOp::PBS_F(op_impl) => {
                self.apply_pbs2reg(1, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?
            }
            hpu_asm::DOp::PBS_ML2_F(op_impl) => {
                self.apply_pbs2reg(2, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?
            }
            hpu_asm::DOp::PBS_ML4_F(op_impl) => {
                self.apply_pbs2reg(4, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?
            }
            hpu_asm::DOp::PBS_ML8_F(op_impl) => {
                self.apply_pbs2reg(8, op_impl.0.dst_rid, op_impl.0.src_rid, op_impl.0.gid).await?
            }
        }

        // Dump operation src/dst in file if required
        self.dump_op_reg(&dop_inner);

        // Increment program counter
        self.inner.lock().unwrap().pc += 1;
        Ok(())
    }

    /// Compute dst_rid <- Pbs(src_rid, lut)
    /// Use a function to prevent code duplication in PBS/PBS_F implementation
    /// NB: Current Pbs lookup function arn't reverted from Hbm memory
    /// TODO: Read PbsLut from Hbm instead of online generation based on Pbs Id
    async fn apply_pbs2reg(
        &mut self,
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
            let modulus_sup = 1_usize << pbs_p.message_width + pbs_p.carry_width;
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
            // Get keys and computation buffer
            let (ksk, ref mut bfr_after_ks, bsk) = self.get_server_key().await?;

            // TODO add a check on trivialness for fast simulation ?
            keyswitch_lwe_ciphertext_with_scalar_change(ksk, &cpu_reg, bfr_after_ks);
            blind_rotate_ntt64_bnf_assign(bfr_after_ks, &mut tfhe_lut, &bsk);

            assert_eq!(
                dst_rid.0,
                (dst_rid.0 >> lut.lut_lg()) << lut.lut_lg(),
                "Pbs destination register must be aligned with lut size"
            );

            // Compute ManyLut function stride
            let fn_stride = {
                let pbs_p = &self.params.rtl_params.pbs_params;
                let modulus_sup = 1_usize << pbs_p.message_width + pbs_p.carry_width;
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
    fn cpu2reg(&mut self, reg_id: hpu_asm::RegId, cpu: LweCiphertextView<u64>) {
        let inner = self.inner.lock().unwrap();
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

    /// Get the inner server key used for computation
    /// Check the register state and extract sks from memory if needed
    async fn get_server_key(
        &mut self,
    ) -> Result<(
        &LweKeyswitchKeyOwned<u32>,
        &mut LweCiphertextOwned<u32>,
        &NttLweBootstrapKeyOwned<u64>,
    ), anyhow::Error> {
        let sks_is_none= {
            let inner = self.inner.lock().unwrap();
            inner.sks.is_none()
                };
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
                for (id, (hpu, mem_kind)) in 
                std::iter::zip(hw_slice, self.params.bsk_pc.iter())
                    .enumerate(){

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
                        let mem_req = MemBus::new_wrapped(self.props.uid(), Command::Read,
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
                let mut ksk = HpuLweBootstrapKeyOwned::new(0, self.params.rtl_params.clone());

                // Copy content from Hbm
                let hw_slice = ksk.as_mut_view().into_container();
                for (id, (hpu, mem_kind)) in 
                std::iter::zip(hw_slice, self.params.ksk_pc.iter()).enumerate() {
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
                        let mem_req = MemBus::new_wrapped(self.props.uid(), Command::Read,
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
        let (ksk, bfr, bsk) = self.sks.as_mut().unwrap();
        Ok((ksk, bfr, bsk))
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
                MemKind::Hbm { pc } => self.params.hbm_global_ofst + pc* self.params.hbm_pc_ofst,
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
