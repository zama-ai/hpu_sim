//! Modelize register map behaviour
//!
//! Only implement the configuration part, no runtime register modelized

use ra2m::prelude::{
    protocol::{
        Mode,
        addr::{Addr, Pattern, SubRangeAddr},
        membus,
    },
    *,
};
use std::sync::{Arc, Mutex};
use tfhe::core_crypto::hpu::parameters::HpuNoiseDistributionInputRaw;

use hpu_regmap::FlatRegmap;
use tfhe::tfhe_hpu_backend::interface::rtl::params::*;
use tfhe::tfhe_hpu_backend::prelude::*;

/// Regmap parameters
#[derive(Debug, Clone)]
pub struct RegmapParams {
    pub regmap_files: Vec<String>,
    pub rtl: HpuParameters,
    pub latency: types::Latency,
}

/// Store internal state of Regmap module
struct RegmapInner {
    bsk: KeyState,
    ksk: KeyState,
    bpip: BpipState,
    addr_ofst: AddrOffset,
}

impl RegmapInner {
    pub fn new() -> Self {
        Self {
            bsk: Default::default(),
            ksk: Default::default(),
            bpip: Default::default(),
            addr_ofst: Default::default(),
        }
    }
}

#[derive(Module)]
pub struct Regmap {
    params: RegmapParams,
    props: Arc<module::Properties>,

    #[port]
    port: port::ReqRespPort<membus::MemBus>,

    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    regmap: FlatRegmap,
    inner: Mutex<RegmapInner>,
}

#[default_teardown]
impl Regmap {
    pub fn new(params: RegmapParams, props: module::Properties) -> Self {
        let props = Arc::new(props);

        let regmap_str = params
            .regmap_files
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>();

        Self {
            port: port::ReqRespPort::new("port", props.clone(), None, None),
            prc: Mutex::new(Vec::new()),
            regmap: FlatRegmap::from_file(&regmap_str),
            inner: Mutex::new(RegmapInner::new()),
            params,
            props,
        }
    }

    #[init]
    fn _init(self: Arc<Self>) {
        let mut prc = self.prc.lock().unwrap();

        // Notify register map addr_range
        let asc = self.clone();
        let addr_range = vec![Addr::Range(
            *self.regmap.offset(),
            self.regmap.range().Byte(),
        )];
        prc.push(spawn_prc!(async {
            match membus::addr_range_register(asc.props.uid(), &asc.port, &addr_range).await {
                Ok(_) => {}
                Err(err) => {
                    log!(|asc| log::Category::Protocol, log::Verbosity::Warning => err );
                }
            }
        }));

        // Start response_layer task
        let asc = self.clone();
        prc.push(spawn_prc!(Self::response_layer(asc)));
    }
}

impl Regmap {
    fn handle_request(&self, req: &mut membus::MemBus) -> Option<time::Tick> {
        let mut delay: time::Tick = Default::default();

        // Register as request handler
        req.trace_mut()
            .push(history::Handler::base(*self.properties().uid()));

        // Compute frontend delay
        // => Time required to decode the address and access the internal register array
        delay += self
            .params
            .latency
            .into_tick(self.properties().clock_domain());

        // Decode address
        let addr = match req.subrange_addr() {
            SubRangeAddr::Phys(t) => *t,
            _ => {
                req.set_mode(Mode::Error(membus::MemBusError::SubRange(
                    *req.subrange_addr(),
                )));
                return Some(delay);
            }
        };

        // Decode access pattern and command
        // In case of error, set mode field accordingly
        match req.pattern() {
            Pattern::Simple(d) => {
                if usize::from(d) != std::mem::size_of::<u32>() {
                    req.set_mode(Mode::Error(membus::MemBusError::Pattern(*req.pattern())));
                    return Some(delay);
                } else {
                    match req.cmd() {
                        membus::Command::Read => {
                            let val_u32 = self.read_reg(addr as u64);
                            req.data_mut().extend_from_slice(&val_u32.to_ne_bytes());
                        }
                        membus::Command::Write => {
                            let val_u32 =
                                u32::from_ne_bytes(req.data().as_slice().try_into().unwrap());
                            self.write_reg(addr as u64, val_u32);
                        }
                        _ => {
                            req.set_mode(Mode::Error(membus::MemBusError::Cmd(*req.cmd())));
                            return Some(delay);
                        }
                    };
                }
            }
            _ => {
                req.set_mode(Mode::Error(membus::MemBusError::Pattern(*req.pattern())));
                return Some(delay);
            }
        }

        // Everything goes well, set success status and return
        req.set_mode(Mode::Response);
        Some(delay)
    }

    async fn response_layer(self: Arc<Self>) {
        loop {
            match self
                .port
                .wait_req_forge_resp(|req| self.handle_request(req))
                .await
            {
                Ok(_) => {}
                Err(err) => {
                    log!(|self| log::Category::Protocol, log::Verbosity::Warning => err );
                }
            };
        }
    }
}

// Function and struct used to depict the untime behaviour of register map
#[derive(Default)]
pub(crate) struct KeyState {
    avail: bool,
    rst_pdg: bool,
}

#[derive(Default)]
pub(crate) struct BpipState {
    pub(crate) used: bool,
    pub(crate) use_opportunism: bool,
    pub(crate) timeout: u32,
}

#[derive(Default)]
pub(crate) struct AddrOffset {
    pub(crate) bsk: [[u32; 2]; super::HBM_BSK_PC_MAX],
    pub(crate) ksk: [[u32; 2]; super::HBM_KSK_PC_MAX],
    pub(crate) lut: [u32; 2],
    pub(crate) ldst: [[u32; 2]; super::MEM_CT_PC_MAX],
    pub(crate) trace: [u32; 2],
}

/// Implement revert register access
/// -> Emulate Rtl response of register read/write
impl Regmap {
    /// Get register name from addr
    fn get_register_name(&self, addr: u64) -> &str {
        let register = self
            .regmap
            .register()
            .iter()
            .find(|(_name, reg)| *reg.offset() == (addr as usize))
            .expect("Register addr not found in registermap");

        register.0
    }
    #[allow(unused)]
    pub(crate) fn get_register_addr(&self, name: &str) -> u64 {
        *(self
            .regmap
            .register()
            .get(name)
            .unwrap_or_else(|| panic!("invalid register name {name}"))
            .offset()) as u64
    }

    /// Kind of register reverse
    /// Return register value from parameter value
    pub fn read_reg(&self, addr: u64) -> u32 {
        let register_name = self.get_register_name(addr);
        let mut inner = self.inner.lock().unwrap();
        match register_name {
            "info::ntt_structure" => {
                let ntt_p = &self.params.rtl.ntt_params;
                (ntt_p.radix + (ntt_p.psi << 8) /*+(ntt_p.div << 16)*/ + (ntt_p.delta << 24)) as u32
            }
            "info::ntt_rdx_cut" => {
                let ntt_p = &self.params.rtl.ntt_params;
                let cut_w = match &ntt_p.core_arch {
                    HpuNttCoreArch::GF64(cut_w) => cut_w,
                    _ => &vec![ntt_p.delta as u8],
                };
                cut_w
                    .iter()
                    .enumerate()
                    .fold(0, |acc, (id, val)| acc + ((*val as u32) << (id * 4)))
            }
            "info::ntt_architecture" => match self.params.rtl.ntt_params.core_arch {
                HpuNttCoreArch::WmmCompactPcg => NTT_CORE_ARCH_OFS + 4,
                HpuNttCoreArch::WmmUnfoldPcg => NTT_CORE_ARCH_OFS + 4,
                HpuNttCoreArch::GF64(_) => NTT_CORE_ARCH_OFS + 5,
            },
            "info::ntt_pbs" => {
                let ntt_p = &self.params.rtl.ntt_params;
                (ntt_p.batch_pbs_nb + (ntt_p.total_pbs_nb << 8)) as u32
            }
            "info::ntt_modulo" => {
                MOD_NTT_NAME_OFS + (self.params.rtl.ntt_params.prime_modulus.clone() as u8) as u32
            }

            "info::application" => {
                if CONCRETE_BOOLEAN == self.params.rtl.pbs_params {
                    APPLICATION_NAME_OFS
                } else if MSG2_CARRY2 == self.params.rtl.pbs_params {
                    APPLICATION_NAME_OFS + 1
                } else if MSG2_CARRY2_64B == self.params.rtl.pbs_params {
                    APPLICATION_NAME_OFS + 3
                } else if MSG2_CARRY2_44B == self.params.rtl.pbs_params {
                    APPLICATION_NAME_OFS + 4
                } else if MSG2_CARRY2_64B_FAKE == self.params.rtl.pbs_params {
                    APPLICATION_NAME_OFS + 9
                } else if MSG2_CARRY2_GAUSSIAN == self.params.rtl.pbs_params {
                    APPLICATION_NAME_OFS + 10
                } else if MSG2_CARRY2_TUNIFORM == self.params.rtl.pbs_params {
                    APPLICATION_NAME_OFS + 11
                } else if MSG2_CARRY2_PFAIL64_132B_GAUSSIAN_1F72DBA == self.params.rtl.pbs_params {
                    APPLICATION_NAME_OFS + 12
                } else {
                    // Custom simulation parameters set
                    // -> Return 1 without NAME_OFS
                    1
                }
            }
            "info::ks_structure" => {
                let ks_p = &self.params.rtl.ks_params;
                (ks_p.lbx + (ks_p.lby << 8) + (ks_p.lbz << 16)) as u32
            }
            "info::ks_crypto_param" => {
                let ks_p = &self.params.rtl.ks_params;
                let pbs_p = &self.params.rtl.pbs_params;
                (ks_p.width + (pbs_p.ks_level << 8) + (pbs_p.ks_base_log << 16)) as u32
            }
            "info::hbm_axi4_nb" => {
                let pc_p = &self.params.rtl.pc_params;
                // TODO: Cut number currently not reverted
                (pc_p.bsk_pc + (pc_p.ksk_pc << 8) + (pc_p.pem_pc << 16)) as u32
            }
            "info::hbm_axi4_dataw_ksk" => {
                let bytes_w = &self.params.rtl.pc_params.ksk_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "info::hbm_axi4_dataw_bsk" => {
                let bytes_w = &self.params.rtl.pc_params.bsk_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "info::hbm_axi4_dataw_pem" => {
                let bytes_w = &self.params.rtl.pc_params.pem_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "info::hbm_axi4_dataw_glwe" => {
                let bytes_w = &self.params.rtl.pc_params.glwe_bytes_w;
                *bytes_w as u32 * u8::BITS
            }

            "info::regf_structure" => {
                let regf_p = &self.params.rtl.regf_params;
                (regf_p.reg_nb + (regf_p.coef_nb << 8)) as u32
            }
            "info::isc_structure" => {
                let isc_p = &self.params.rtl.isc_params;
                (isc_p.depth + (isc_p.min_iop_size << 8)) as u32
            }

            "bsk_avail::avail" => inner.bsk.avail as u32,
            "bsk_avail::reset" => {
                if inner.bsk.rst_pdg {
                    inner.bsk.rst_pdg = false;
                    1 << 31
                } else {
                    0
                }
            }
            "ksk_avail::avail" => inner.ksk.avail as u32,
            "ksk_avail::reset" => {
                if inner.ksk.rst_pdg {
                    inner.ksk.rst_pdg = false;
                    1 << 31
                } else {
                    0
                }
            }

            // Bpip configuration registers
            "bpip::use" => {
                ((inner.bpip.used as u8) + ((inner.bpip.use_opportunism as u8) << 1)) as u32
            }
            "bpip::timeout" => inner.bpip.timeout,

            // Add offset configuration registers
            "hbm_axi4_addr_1in3::ct_pc0_msb" => inner.addr_ofst.ldst[0][0],
            "hbm_axi4_addr_1in3::ct_pc0_lsb" => inner.addr_ofst.ldst[0][1],
            "hbm_axi4_addr_1in3::ct_pc1_msb" => inner.addr_ofst.ldst[1][0],
            "hbm_axi4_addr_1in3::ct_pc1_lsb" => inner.addr_ofst.ldst[1][1],
            "hbm_axi4_addr_3in3::bsk_pc0_msb" => inner.addr_ofst.bsk[0][0],
            "hbm_axi4_addr_3in3::bsk_pc0_lsb" => inner.addr_ofst.bsk[0][1],
            "hbm_axi4_addr_3in3::bsk_pc1_msb" => inner.addr_ofst.bsk[1][0],
            "hbm_axi4_addr_3in3::bsk_pc1_lsb" => inner.addr_ofst.bsk[1][1],
            "hbm_axi4_addr_3in3::bsk_pc2_msb" => inner.addr_ofst.bsk[2][0],
            "hbm_axi4_addr_3in3::bsk_pc2_lsb" => inner.addr_ofst.bsk[2][1],
            "hbm_axi4_addr_3in3::bsk_pc3_msb" => inner.addr_ofst.bsk[3][0],
            "hbm_axi4_addr_3in3::bsk_pc3_lsb" => inner.addr_ofst.bsk[3][1],
            "hbm_axi4_addr_3in3::bsk_pc4_msb" => inner.addr_ofst.bsk[4][0],
            "hbm_axi4_addr_3in3::bsk_pc4_lsb" => inner.addr_ofst.bsk[4][1],
            "hbm_axi4_addr_3in3::bsk_pc5_msb" => inner.addr_ofst.bsk[5][0],
            "hbm_axi4_addr_3in3::bsk_pc5_lsb" => inner.addr_ofst.bsk[5][1],
            "hbm_axi4_addr_3in3::bsk_pc6_msb" => inner.addr_ofst.bsk[6][0],
            "hbm_axi4_addr_3in3::bsk_pc6_lsb" => inner.addr_ofst.bsk[6][1],
            "hbm_axi4_addr_3in3::bsk_pc7_msb" => inner.addr_ofst.bsk[7][0],
            "hbm_axi4_addr_3in3::bsk_pc7_lsb" => inner.addr_ofst.bsk[7][1],
            "hbm_axi4_addr_3in3::bsk_pc8_msb" => inner.addr_ofst.bsk[8][0],
            "hbm_axi4_addr_3in3::bsk_pc8_lsb" => inner.addr_ofst.bsk[8][1],
            "hbm_axi4_addr_3in3::bsk_pc9_msb" => inner.addr_ofst.bsk[9][0],
            "hbm_axi4_addr_3in3::bsk_pc9_lsb" => inner.addr_ofst.bsk[9][1],
            "hbm_axi4_addr_3in3::bsk_pc10_msb" => inner.addr_ofst.bsk[10][0],
            "hbm_axi4_addr_3in3::bsk_pc10_lsb" => inner.addr_ofst.bsk[10][1],
            "hbm_axi4_addr_3in3::bsk_pc11_msb" => inner.addr_ofst.bsk[11][0],
            "hbm_axi4_addr_3in3::bsk_pc11_lsb" => inner.addr_ofst.bsk[11][1],
            "hbm_axi4_addr_3in3::bsk_pc12_msb" => inner.addr_ofst.bsk[12][0],
            "hbm_axi4_addr_3in3::bsk_pc12_lsb" => inner.addr_ofst.bsk[12][1],
            "hbm_axi4_addr_3in3::bsk_pc13_msb" => inner.addr_ofst.bsk[13][0],
            "hbm_axi4_addr_3in3::bsk_pc13_lsb" => inner.addr_ofst.bsk[13][1],
            "hbm_axi4_addr_3in3::bsk_pc14_msb" => inner.addr_ofst.bsk[14][0],
            "hbm_axi4_addr_3in3::bsk_pc14_lsb" => inner.addr_ofst.bsk[14][1],
            "hbm_axi4_addr_3in3::bsk_pc15_msb" => inner.addr_ofst.bsk[15][0],
            "hbm_axi4_addr_3in3::bsk_pc15_lsb" => inner.addr_ofst.bsk[15][1],
            "hbm_axi4_addr_1in3::ksk_pc0_msb" => inner.addr_ofst.ksk[0][0],
            "hbm_axi4_addr_1in3::ksk_pc0_lsb" => inner.addr_ofst.ksk[0][1],
            "hbm_axi4_addr_1in3::ksk_pc1_msb" => inner.addr_ofst.ksk[1][0],
            "hbm_axi4_addr_1in3::ksk_pc1_lsb" => inner.addr_ofst.ksk[1][1],
            "hbm_axi4_addr_1in3::ksk_pc2_msb" => inner.addr_ofst.ksk[2][0],
            "hbm_axi4_addr_1in3::ksk_pc2_lsb" => inner.addr_ofst.ksk[2][1],
            "hbm_axi4_addr_1in3::ksk_pc3_msb" => inner.addr_ofst.ksk[3][0],
            "hbm_axi4_addr_1in3::ksk_pc3_lsb" => inner.addr_ofst.ksk[3][1],
            "hbm_axi4_addr_1in3::ksk_pc4_msb" => inner.addr_ofst.ksk[4][0],
            "hbm_axi4_addr_1in3::ksk_pc4_lsb" => inner.addr_ofst.ksk[4][1],
            "hbm_axi4_addr_1in3::ksk_pc5_msb" => inner.addr_ofst.ksk[5][0],
            "hbm_axi4_addr_1in3::ksk_pc5_lsb" => inner.addr_ofst.ksk[5][1],
            "hbm_axi4_addr_1in3::ksk_pc6_msb" => inner.addr_ofst.ksk[6][0],
            "hbm_axi4_addr_1in3::ksk_pc6_lsb" => inner.addr_ofst.ksk[6][1],
            "hbm_axi4_addr_1in3::ksk_pc7_msb" => inner.addr_ofst.ksk[7][0],
            "hbm_axi4_addr_1in3::ksk_pc7_lsb" => inner.addr_ofst.ksk[7][1],
            "hbm_axi4_addr_1in3::ksk_pc8_msb" => inner.addr_ofst.ksk[8][0],
            "hbm_axi4_addr_1in3::ksk_pc8_lsb" => inner.addr_ofst.ksk[8][1],
            "hbm_axi4_addr_1in3::ksk_pc9_msb" => inner.addr_ofst.ksk[9][0],
            "hbm_axi4_addr_1in3::ksk_pc9_lsb" => inner.addr_ofst.ksk[9][1],
            "hbm_axi4_addr_1in3::ksk_pc10_msb" => inner.addr_ofst.ksk[10][0],
            "hbm_axi4_addr_1in3::ksk_pc10_lsb" => inner.addr_ofst.ksk[10][1],
            "hbm_axi4_addr_1in3::ksk_pc11_msb" => inner.addr_ofst.ksk[11][0],
            "hbm_axi4_addr_1in3::ksk_pc11_lsb" => inner.addr_ofst.ksk[11][1],
            "hbm_axi4_addr_1in3::ksk_pc12_msb" => inner.addr_ofst.ksk[12][0],
            "hbm_axi4_addr_1in3::ksk_pc12_lsb" => inner.addr_ofst.ksk[12][1],
            "hbm_axi4_addr_1in3::ksk_pc13_msb" => inner.addr_ofst.ksk[13][0],
            "hbm_axi4_addr_1in3::ksk_pc13_lsb" => inner.addr_ofst.ksk[13][1],
            "hbm_axi4_addr_1in3::ksk_pc14_msb" => inner.addr_ofst.ksk[14][0],
            "hbm_axi4_addr_1in3::ksk_pc14_lsb" => inner.addr_ofst.ksk[14][1],
            "hbm_axi4_addr_1in3::ksk_pc15_msb" => inner.addr_ofst.ksk[15][0],
            "hbm_axi4_addr_1in3::ksk_pc15_lsb" => inner.addr_ofst.ksk[15][1],
            "hbm_axi4_addr_1in3::glwe_pc0_msb" => inner.addr_ofst.lut[0],
            "hbm_axi4_addr_1in3::glwe_pc0_lsb" => inner.addr_ofst.lut[1],
            "hbm_axi4_addr_1in3::trc_pc0_msb" => inner.addr_ofst.trace[0],
            "hbm_axi4_addr_1in3::trc_pc0_lsb" => inner.addr_ofst.trace[1],

            // sim_dummy section
            // Used to give extra information with simulation context
            "pbs_parameters::lwe_dimension" => self.params.rtl.pbs_params.lwe_dimension as u32,
            "pbs_parameters::glwe_dimension" => self.params.rtl.pbs_params.glwe_dimension as u32,
            "pbs_parameters::polynomial_size" => self.params.rtl.pbs_params.polynomial_size as u32,
            "pbs_parameters::pbs_base_log" => self.params.rtl.pbs_params.pbs_base_log as u32,
            "pbs_parameters::pbs_level" => self.params.rtl.pbs_params.pbs_level as u32,
            "pbs_parameters::ks_base_log" => self.params.rtl.pbs_params.ks_base_log as u32,
            "pbs_parameters::ks_level" => self.params.rtl.pbs_params.ks_level as u32,
            "pbs_parameters::message_width" => self.params.rtl.pbs_params.message_width as u32,
            "pbs_parameters::carry_width" => self.params.rtl.pbs_params.carry_width as u32,
            "pbs_parameters::ciphertext_width" => {
                self.params.rtl.pbs_params.ciphertext_width as u32
            }
            "pbs_noise_lwe::mode" => {
                HpuNoiseDistributionInputRaw::from(
                    self.params.rtl.pbs_params.lwe_noise_distribution,
                )
                .mode
            }
            "pbs_noise_lwe::raw_0" => {
                HpuNoiseDistributionInputRaw::from(
                    self.params.rtl.pbs_params.lwe_noise_distribution,
                )
                .raw[0]
            }
            "pbs_noise_lwe::raw_1" => {
                HpuNoiseDistributionInputRaw::from(
                    self.params.rtl.pbs_params.lwe_noise_distribution,
                )
                .raw[1]
            }
            "pbs_noise_glwe::mode" => {
                HpuNoiseDistributionInputRaw::from(
                    self.params.rtl.pbs_params.glwe_noise_distribution,
                )
                .mode
            }
            "pbs_noise_glwe::raw_0" => {
                HpuNoiseDistributionInputRaw::from(
                    self.params.rtl.pbs_params.glwe_noise_distribution,
                )
                .raw[0]
            }
            "pbs_noise_glwe::raw_1" => {
                HpuNoiseDistributionInputRaw::from(
                    self.params.rtl.pbs_params.glwe_noise_distribution,
                )
                .raw[1]
            }

            _ => {
                log!(|self| log::Category::Own, log::Verbosity::Info => register_name => "Register not hooked for reading, return 0");
                0
            }
        }
    }

    pub fn write_reg(&self, addr: u64, value: u32) {
        let register_name = self.get_register_name(addr);
        let mut inner = self.inner.lock().unwrap();
        match register_name {
            "bsk_avail::avail" => {
                inner.bsk.avail = (value & 0x1) == 0x1;
            }
            "bsk_avail::reset" => {
                if (value & 0x1) == 0x1 {
                    inner.bsk.rst_pdg = true;
                    inner.bsk.avail = false;
                    event::Event::triggered(&forge_event_name!(|self| "BskKeyReset"), None);
                }
            }
            "ksk_avail::avail" => {
                inner.ksk.avail = (value & 0x1) == 0x1;
            }
            "ksk_avail::reset" => {
                if (value & 0x1) == 0x1 {
                    inner.ksk.rst_pdg = true;
                    inner.ksk.avail = false;
                    event::Event::triggered(&forge_event_name!(|self| "KskKeyReset"), None);
                }
            }

            // Bpip configuration registers
            "bpip::use" => {
                inner.bpip.used = (value & 0x1) == 0x1;
                inner.bpip.use_opportunism = (value & 0x2) == 0x2;
            }
            "bpip::timeout" => {
                inner.bpip.timeout = value;
            }
            // Add offset configuration registers
            "hbm_axi4_addr_1in3::ct_pc0_msb" => {
                inner.addr_ofst.ldst[0][0] = value;
            }
            "hbm_axi4_addr_1in3::ct_pc0_lsb" => {
                inner.addr_ofst.ldst[0][1] = value;
            }
            "hbm_axi4_addr_1in3::ct_pc1_msb" => {
                inner.addr_ofst.ldst[1][0] = value;
            }
            "hbm_axi4_addr_1in3::ct_pc1_lsb" => {
                inner.addr_ofst.ldst[1][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc0_msb" => {
                inner.addr_ofst.bsk[0][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc0_lsb" => {
                inner.addr_ofst.bsk[0][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc1_msb" => {
                inner.addr_ofst.bsk[1][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc1_lsb" => {
                inner.addr_ofst.bsk[1][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc2_msb" => {
                inner.addr_ofst.bsk[2][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc2_lsb" => {
                inner.addr_ofst.bsk[2][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc3_msb" => {
                inner.addr_ofst.bsk[3][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc3_lsb" => {
                inner.addr_ofst.bsk[3][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc4_msb" => {
                inner.addr_ofst.bsk[4][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc4_lsb" => {
                inner.addr_ofst.bsk[4][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc5_msb" => {
                inner.addr_ofst.bsk[5][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc5_lsb" => {
                inner.addr_ofst.bsk[5][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc6_msb" => {
                inner.addr_ofst.bsk[6][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc6_lsb" => {
                inner.addr_ofst.bsk[6][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc7_msb" => {
                inner.addr_ofst.bsk[7][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc7_lsb" => {
                inner.addr_ofst.bsk[7][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc8_msb" => {
                inner.addr_ofst.bsk[8][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc8_lsb" => {
                inner.addr_ofst.bsk[8][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc9_msb" => {
                inner.addr_ofst.bsk[9][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc9_lsb" => {
                inner.addr_ofst.bsk[9][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc10_msb" => {
                inner.addr_ofst.bsk[10][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc10_lsb" => {
                inner.addr_ofst.bsk[10][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc11_msb" => {
                inner.addr_ofst.bsk[11][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc11_lsb" => {
                inner.addr_ofst.bsk[11][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc12_msb" => {
                inner.addr_ofst.bsk[12][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc12_lsb" => {
                inner.addr_ofst.bsk[12][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc13_msb" => {
                inner.addr_ofst.bsk[13][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc13_lsb" => {
                inner.addr_ofst.bsk[13][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc14_msb" => {
                inner.addr_ofst.bsk[14][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc14_lsb" => {
                inner.addr_ofst.bsk[14][1] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc15_msb" => {
                inner.addr_ofst.bsk[15][0] = value;
            }
            "hbm_axi4_addr_3in3::bsk_pc15_lsb" => {
                inner.addr_ofst.bsk[15][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc0_msb" => {
                inner.addr_ofst.ksk[0][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc0_lsb" => {
                inner.addr_ofst.ksk[0][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc1_msb" => {
                inner.addr_ofst.ksk[1][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc1_lsb" => {
                inner.addr_ofst.ksk[1][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc2_msb" => {
                inner.addr_ofst.ksk[2][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc2_lsb" => {
                inner.addr_ofst.ksk[2][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc3_msb" => {
                inner.addr_ofst.ksk[3][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc3_lsb" => {
                inner.addr_ofst.ksk[3][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc4_msb" => {
                inner.addr_ofst.ksk[4][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc4_lsb" => {
                inner.addr_ofst.ksk[4][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc5_msb" => {
                inner.addr_ofst.ksk[5][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc5_lsb" => {
                inner.addr_ofst.ksk[5][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc6_msb" => {
                inner.addr_ofst.ksk[6][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc6_lsb" => {
                inner.addr_ofst.ksk[6][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc7_msb" => {
                inner.addr_ofst.ksk[7][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc7_lsb" => {
                inner.addr_ofst.ksk[7][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc8_msb" => {
                inner.addr_ofst.ksk[8][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc8_lsb" => {
                inner.addr_ofst.ksk[8][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc9_msb" => {
                inner.addr_ofst.ksk[9][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc9_lsb" => {
                inner.addr_ofst.ksk[9][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc10_msb" => {
                inner.addr_ofst.ksk[10][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc10_lsb" => {
                inner.addr_ofst.ksk[10][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc11_msb" => {
                inner.addr_ofst.ksk[11][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc11_lsb" => {
                inner.addr_ofst.ksk[11][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc12_msb" => {
                inner.addr_ofst.ksk[12][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc12_lsb" => {
                inner.addr_ofst.ksk[12][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc13_msb" => {
                inner.addr_ofst.ksk[13][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc13_lsb" => {
                inner.addr_ofst.ksk[13][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc14_msb" => {
                inner.addr_ofst.ksk[14][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc14_lsb" => {
                inner.addr_ofst.ksk[14][1] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc15_msb" => {
                inner.addr_ofst.ksk[15][0] = value;
            }
            "hbm_axi4_addr_1in3::ksk_pc15_lsb" => {
                inner.addr_ofst.ksk[15][1] = value;
            }
            "hbm_axi4_addr_1in3::glwe_pc0_msb" => {
                inner.addr_ofst.lut[0] = value;
            }
            "hbm_axi4_addr_1in3::glwe_pc0_lsb" => {
                inner.addr_ofst.lut[1] = value;
            }
            "hbm_axi4_addr_1in3::trc_pc0_msb" => {
                inner.addr_ofst.trace[0] = value;
            }
            "hbm_axi4_addr_1in3::trc_pc0_lsb" => {
                inner.addr_ofst.trace[1] = value;
            }

            _ => {
                log!(|self| log::Category::Own, log::Verbosity::Info => register_name => "Register not hooked for writing");
            }
        }
    }
}
