//! Hpu Simulation model
//! Emulate Hpu behavior for simulation
//! Enable to test tfhe-rs application that required tfhe-hpu-backend without the real hardware.
//! It rely on the `ffi-sim` interface of `tfhe-hpu-backend` and on ipc-channel for communication
//!
//! WARN: User must start the HpuSim binary before tfhe-rs application

use hpu_sim::{
    cpn::{HpuCoreParams, HpuNode, HpuNodeParams, RegmapParams, UCoreParams},
    params::{ComputeParamsName, PerfParamsName},
};
use ra2m::prelude::*;
use tfhe::tfhe_hpu_backend::{asm::dop::UcorePayload, prelude::*};

static OUTPUT_FOLDER: &str = "/tmp/hpu_sim";

/// Define CLI arguments
use clap::Parser;
#[derive(clap::Parser, Debug, Clone)]
#[clap(long_about = "Hpu Simulation mockup.")]
pub struct Args {
    // Configuration ----------------------------------------------------
    /// Fpga fake configuration
    /// Toml file similar to the one used with the real hpu-backend
    /// Enable to retrieved ipc_name, register_file and board definition
    #[clap(
        long,
        value_parser,
        default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
    )]
    pub config: ShellString,

    /// Comupute parameters
    /// Depicts hardware crypto-parameters and architecture details
    /// => Used for tfhe-rs inner computation and stimulus generation
    #[clap(long, value_parser, default_value = "TUniform64bFast")]
    pub compute_params: ComputeParamsName,

    /// Performance parameters
    /// Depicts hardware crypto-parameters and architecture details
    /// => Used for performance estimation
    #[clap(long, value_parser, default_value = "TUniform64bPFail128Psi64")]
    pub perf_params: PerfParamsName,

    // Override params --------------------------------------------------
    // Quick way to override parameters through ClI instead of editing the
    // configuration file
    // Used to override some parameters at runtime
    /// Override Number of Register
    #[clap(long, value_parser)]
    register: Option<usize>,

    /// Override HPU lookahead buffer depth
    /// Number of instruction that are considered in advance
    #[clap(long, value_parser)]
    isc_depth: Option<usize>,

    /// Consider all received ciphertext as trivial ciphertext
    /// Execute Pbs in a trivial manner and display value in tracing::debug
    /// Useful for IOp algorithm debug
    /// WARN: Only work if user application send trivial ciphertext
    #[clap(long, value_parser)]
    trivial: bool,

    /// Disable tfhe-rs computation
    /// Fast simulation with false results but accurate performance estimation
    #[clap(long, value_parser)]
    noops: bool,

    // Simulation configuration -----------------------------------------
    /// Simulation timing mode
    /// Could be:
    ///  * LooselyTimed      : [LT, lt, LooselyTimed, Loosely]
    ///  * ApproximatelyTimed: [AT, at, ApproxTimed, Approx]
    #[clap(long, value_parser, default_value = "AT")]
    timing_mode: time::TimingMode,

    /// Simulation duration [val_unit]
    #[clap(long, value_parser, default_value = "100_ms")]
    duration: unit::Time,

    /// Number of tick per second (resolution) [val_unit]
    #[clap(long, value_parser, default_value = "1_ps")]
    timescale: unit::Time,

    /// Frequency
    /// Only use for report display
    #[clap(long, value_parser, default_value = "400_MHz")]
    frequency: unit::Frequency,

    // Log configuration ----------------------------------------------------
    /// Tweak component logging
    /// Provide list regex=dflt_verb:{cat:verb, ...} to alter component log_filter
    #[clap(long, value_parser)]
    log_args: Option<Vec<log::Args>>,

    // Tweak component tracing
    /// Provide list regex={cat:verb, ...} to alter component hw_tracer
    #[clap(long, value_parser)]
    trace_args: Option<Vec<trace::Args>>,

    // Dump options ---------------------------------------------------------
    // NB: Input/Output dump are handle at user-side (i.e. in application binary)
    //     Here only handle internal value such as reg-dump
    /// Dump content of register after each DOp execution
    #[clap(long, value_parser)]
    dump_reg: bool,
}

/// Elaboration phases
/// Built the hpu_sim architecture based on inner modules and user arguments
fn elaborate(
    config: &HpuConfig,
    hpu_params: &HpuParameters,
    args: &Args,
) -> Result<module::Area, anyhow::Error> {
    // Some sanity check on configuration and usefull information extraction
    let (ipc_name, iopq_config, ackq_config) = match &config.fpga.ffi {
        FFIMode::Sim {
            ipc_name,
            iopq,
            ackq,
        } => Ok((ipc_name.expand(), iopq, ackq)),
        _ => Err(anyhow::anyhow!(
            "HpuSim only work with FFIMode::Sim. Check used configuration",
        )),
    }?;

    let mut root = module::Area::new(module::Properties::new(
        "root".to_owned(),
        types::ClockDomain::new(args.frequency),
    ));

    // Cluster level component
    // Switch to properly dispatch NetworkDma request
    let switch = Arc::new(ra2m_cpn::net::Switch::<u8, protocol::membus::MemBus>::new(
        ra2m_cpn::net::SwitchParams {
            inflight_req: 10,
            switch_latency: types::Latency::Cycle(2.cycles()),
            bandwidth: 25.GB_s(),
            port_cap: None,
        },
        root.child_properties("b2b_switch", Default::default()),
    ));
    root.insert_module(switch.clone());
    let ctrl_switch = Arc::new(ra2m_cpn::net::SplitSwitch::<u8, UcorePayload>::new(
        ra2m_cpn::net::SwitchParams {
            inflight_req: 10,
            switch_latency: types::Latency::Cycle(2.cycles()),
            bandwidth: 25.GB_s(),
            port_cap: None,
        },
        root.child_properties("ctrl_xbar", Default::default()),
    ));
    root.insert_module(ctrl_switch.clone());

    // List of nodes
    let mut node_params = HpuNodeParams {
        hpu_core: HpuCoreParams {
            compute_params: hpu_params.clone(),
            sim_config: hc_sim::hpu::HpuConfig::from(&args.perf_params),
            sim_trace: true,
            trivial: args.trivial,
            noops: args.noops,
            dump_reg: args.dump_reg,

            ct_pc: config.board.ct_pc.clone(),
            ksk_pc: config.board.ksk_pc.clone(),
            bsk_pc: config.board.bsk_pc.clone(),
            trace_pc: config.board.trace_pc,
            trace_depth: config.board.trace_depth,
            hbm_global_ofst: 0x40_0000_0000,
            hbm_pc_ofst: 0x2000_0000,
        },
        ucore: UCoreParams {
            cluster_nodes: config.fpga.node_id.clone(),
            fw_pc: config.board.fw_pc,
            ct_pc: config.board.ct_pc.clone(),
            ct_user: config.board.user_size,
            ct_b2b: config.board.b2b_size,
            ct_heap: config.board.heap_size,
            axis_depth: 256,
            polling_rate: config.fpga.polling_us.us(),
            iopq: iopq_config.clone(),
            ackq: ackq_config.clone(),

            rtl_params: hpu_params.clone(),
            hbm_global_ofst: 0x40_0000_0000,
            hbm_pc_ofst: 0x2000_0000,
        },
        regmap: RegmapParams {
            regmap_files: config
                .fpga
                .regmap
                .iter()
                .map(|path| path.expand())
                .collect::<Vec<_>>(),
            rtl: hpu_params.clone(),
            latency: types::Latency::Cycle(1.cycles()),
        },
        xbar: ra2m_cpn::mem::XBarParams {
            inflight_req: 10,
            frontend_latency: types::Latency::Cycle(2.cycles()),
            forward_latency: types::Latency::Cycle(1.cycles()),
            bandwidth: 1.PiB_s(), // Kind of disabling BW limitation
            inbound_cap: None,
            outbound_cap: None,
        },
        ddr: ra2m_cpn::mem::NpRamParams {
            ports: 1,
            size: 4.GiB(),
            base_addr: Some(0x2000_0000),
            latency: types::Latency::Cycle(1.cycles()),
            bandwidth: 25.6.GB_s(),
            binfile: None,
        },
        // NB: Hbm2e is capped as 16GiB, but we used 2 here
        // Double peak bandwidth and size
        hbm: ra2m_cpn::mem::NpRamParams {
            ports: 2,
            size: 32.GiB(),
            base_addr: Some(0x40_0000_0000),
            latency: types::Latency::Cycle(1.cycles()),
            bandwidth: 6.4.TB_s(),
            binfile: None,
        },
        dma: ra2m_cpn::net::NDmaParams {
            node_id: 0,
            inflight_req: config.board.ct_pc.len(), // NB: pc request are issued in burst
            frontend_latency: types::Latency::Cycle(1.cycles()),
            forward_latency: types::Latency::Cycle(1.cycles()),
            bandwidth: 25.GB_s(),
        },
        ipc: ra2m_cpn::ffi_bridge::ipc::H2sBridgeParams {
            ipc_path: "".to_string(),
            addr_range: (0, 384.GiB()),
            inflight_req: 10,
            polling_rate: config.fpga.polling_us.us(),
            keep_alive: Some(250.ms()),
        },
    };

    for id in config.fpga.node_id.iter() {
        let name = format!("node_{id}");
        let ipc_path = format!("{ipc_name}_{id}");
        node_params.dma.node_id = *id;
        node_params.ipc.ipc_path = ipc_path;
        root.insert_module(Arc::new(HpuNode::new(
            node_params.clone(),
            root.child_properties(&name, Default::default()),
        )?));

        // Attach to cluster Switch
        // NB: each switch interface currently used two ports
        let net_out = format!("{name}::net_outbound");
        root.inner_bind("b2b_switch::ingress", &net_out)?;
        let net_in = format!("{name}::net_inbound");
        root.inner_bind("b2b_switch::egress", &net_in)?;
        // TODO fixme port_nb must be return by bind function over PortVec
        switch.register_port(id, *id as usize)?;

        // Attach to cluster CtrlSwitch
        let ctrl = format!("{name}::ctrl");
        root.inner_bind("ctrl_xbar::port", &ctrl)?;
        // TODO fixme port_nb must be return by bind function over PortVec
        ctrl_switch.register_port(id, *id as usize)?;
    }

    fn show(module: &dyn Module) {
        for m in module.inner_match(".*") {
            println!("{} => {}", m.properties().uid(), m.properties().path());
            if !m.is_leaf() {
                show(m)
            }
        }
    }

    show(&root);

    Ok(root)
}

async fn simulate(model: module::Area, args: &Args) -> Result<(), anyhow::Error> {
    Output::init(OUTPUT_FOLDER);
    // Create global simulation state and custom scheduler for hardware task
    let mut sched = init_simulation(0, args.timescale, args.timing_mode, 1024);

    // Init modules and configure logging/tracing
    let model = Arc::new(model);
    user_log_args(&model, args.log_args.clone());
    user_trace_args(&model, args.trace_args.clone());
    model.clone().init();

    // Start scheduler
    let (tick, kind) = sched.simulate(args.duration.into()).await;
    println!("Simulation exit @{tick} from {kind:?}");
    model.teardown();
    Ok(())
}

/// HpuSim main function
/// Wrap in main later to enable singlelmt -thread configuration
async fn hpu_sim() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    println!("User Options: {args:?}");

    // Load parameters from configuration file ------------------------------------
    let config = HpuConfig::from_toml(&args.config.expand());
    let hpu_params = {
        let mut params = HpuParameters::from(&args.compute_params);

        // Override some parameters if required
        if let Some(register) = args.register.as_ref() {
            params.regf_params.reg_nb = *register;
        }
        if let Some(isc_depth) = args.isc_depth.as_ref() {
            params.isc_params.depth = *isc_depth;
        }
        params
    };
    println!("HpuSim parameters after override with CLI: {hpu_params:?}");

    let model = elaborate(&config, &hpu_params, &args)?;
    simulate(model, &args).await?;
    Ok(())
}

// #[cfg(not(feature = "tokio-mt"))]
// #[tokio::main(worker_threads = 1)]
// async fn main() -> Result<(), anyhow::Error> {
//     println!("Use Single-threaded Tokio runtime [not feature: \"tokio-mt\"]");
//     hpu_sim().await
// }

// #[cfg(feature = "tokio-mt")]
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Use multi-threaded Tokio runtime [feature: \"tokio-mt\"]");
    hpu_sim().await
}
