//! Hpu Simulation model
//! Emulate Hpu behavior for simulation
//! Enable to test tfhe-rs application that required tfhe-hpu-backend without the real hardware.
//! It rely on the `ffi-sim` interface of `tfhe-hpu-backend` and on ipc-channel for communication
//!
//! WARN: User must start the HpuSim binary before tfhe-rs application

use std::fs::OpenOptions;
use std::path::Path;

use hpu_sim::cpn::{HpuCoreParams, HpuNode, HpuNodeParams, UCoreParams, ucore::QueueProperties};
use ra2m::prelude::*;
use tfhe::tfhe_hpu_backend::prelude::*;

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

    /// Tfhe scheme parameters
    /// Depicts the used tfhe-rs parameters set
    #[clap(
        long,
        value_parser,
        default_value = "${HPU_SIM_DIR}/params/gaussian_64b_fast.toml"
    )]
    pub params: ShellString,

    /// Hpu rtl parameters
    /// Also contains the properties of nodes (i.e. on-board memory size and so on)
    #[clap(
        long,
        value_parser,
        default_value = "${HPU_SIM_DIR}/params/gaussian_64b_fast.toml"
    )]
    pub rtl_params: ShellString,

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
    #[clap(long, value_parser, default_value = "350_MHz")]
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
}

/// Elaboration phases
/// Built the hpu_sim architecture based on inner modules and user arguments
fn elaborate(
    config: &HpuConfig,
    params: &HpuParameters,
    args: &Args,
) -> Result<module::Area, anyhow::Error> {
    // Some sanity check on configuration and usefull information extraction
    let ipc_name = match &config.fpga.ffi {
        FFIMode::Sim { ipc_name } => Ok(ipc_name.expand()),
        _ => Err(anyhow::anyhow!(
            "HpuSim only work with FFIMode::Sim. Check used configuration",
        )),
    }?;

    let mut root = module::Area::new(module::Properties::new(
        "root".to_owned(),
        types::ClockDomain::new(args.frequency.clone()),
    ));

    // Cluster level component
    // Cluster router, currently rely on Xbar and here to mimic inter-node communication
    root.insert_module(Arc::new(ra2m_cpn::mem::XBar::new(
        ra2m_cpn::mem::XBarParams {
            inflight_req: 10,
            frontend_latency: types::Latency::Cycle(2.cycles()),
            forward_latency: types::Latency::Cycle(1.cycles()),
            bandwidth: 10.MiB_s(),
            inbound_cap: None,
            outbound_cap: None,
        },
        root.child_properties("n2n_xbar", Default::default()),
    )));

    // List of nodes
    let mut node_params = HpuNodeParams {
        hpu_core: HpuCoreParams {},
        ucore: UCoreParams {
            node_id: 0,
            fw_pc: config.board.fw_pc,
            ct_mem: config.board.ct_mem,
            axis_depth: 256,
            polling_rate: config.fpga.polling_us.us(),
            iopq: QueueProperties {
                head: 0,
                tail: 8,
                data: 0x10,
                size: 256,
            },

            ackq: QueueProperties {
                head: 0,
                tail: 8,
                data: 0x10,
                size: 256,
            },
        },
        ddr: ra2m_cpn::mem::NpRamParams {
            ports: 2,
            size: 10.MB(),
            base_addr: Some(0),
            latency: types::Latency::Cycle(1.cycles()),
            bandwidth: 1.GB_s(),
            binfile: None,
        },
        hbm: ra2m_cpn::mem::NpRamParams {
            ports: 3,
            size: 10.MB(),
            base_addr: Some(0x1000000),
            latency: types::Latency::Cycle(1.cycles()),
            bandwidth: 1.GB_s(),
            binfile: None,
        },
        dma: ra2m_cpn::mem::DmaParams {
            inflight_req: 4,
            frontend_latency: types::Latency::Cycle(1.cycles()),
            forward_latency: types::Latency::Cycle(1.cycles()),
            bandwidth: 1.GB_s(),
        },
        ipc: ra2m_cpn::ffi::ipc::H2sBridgeParams {
            ipc_path: "".to_string(),
            addr_range: (0, 1.GB()),
            inflight_req: 10,
            polling_rate: config.fpga.polling_us.us(),
        },
    };

    for id in config.fpga.node_id.iter() {
        let name = format!("node_{id}");
        let ipc_path = format!("{ipc_name}_node_{id}");
        node_params.ucore.node_id = *id;
        node_params.ipc.ipc_path = ipc_path;
        root.insert_module(Arc::new(HpuNode::new(
            node_params.clone(),
            root.child_properties(&name, Default::default()),
        )?));

        // Attach to cluster router
        // Currently simplified version with xbar and std dma instead of custom Dma over MAC
        // Node Dma is master and Hbm is slave
        let dma_port = format!("{name}::dma_outbound");
        root.inner_bind("n2n_xbar::inbound", &dma_port)?;

        let hbm_port = format!("{name}::mem");
        root.inner_bind("n2n_xbar::outbound", &hbm_port)?;
    }

    Ok(root)
}

async fn simulate(model: module::Area, args: &Args) -> Result<(), anyhow::Error> {
    Output::init("/tmp/hpu_sim");
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
    let params = {
        let mut rtl_params = HpuParameters::from_toml(&args.params.expand());

        // Override some parameters if required
        if let Some(register) = args.register.as_ref() {
            rtl_params.regf_params.reg_nb = *register;
        }
        if let Some(isc_depth) = args.isc_depth.as_ref() {
            rtl_params.isc_params.depth = *isc_depth;
        }
        rtl_params
    };
    println!("HpuSim parameters after override with CLI: {params:?}");

    let model = elaborate(&config, &params, &args)?;
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
