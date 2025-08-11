//! Depict HpuNode
//!
//! HpuNode contains:
//! * Memory (DDR/Hbm)
//! * Ucore
//! * HpuCore (i.e isc + Pe)
//! * InterBoard interface
//! * Host interface
//!
//! No custom logic inside HpuNode, it's only a think wrapper around inner modules.

use ra2m::prelude::anyhow::Error;
use ra2m::prelude::*;
use ra2m::ra2m_cpn::{ffi, mem};

use super::*;

/// HpuCore parameters
#[derive(Debug, Clone)]
pub struct HpuNodeParams {
    pub hpu_core: HpuCoreParams,
    pub ucore: UCoreParams,
    pub regmap: RegmapParams,
    pub ddr: mem::NpRamParams,
    pub hbm: mem::NpRamParams,
    pub dma: mem::DmaParams,
    pub ipc: ffi::ipc::H2sBridgeParams,
}

pub struct HpuNode {
    params: HpuNodeParams,
    inner: Arc<module::Area>,
}

impl HpuNode {
    pub fn new(params: HpuNodeParams, props: module::Properties) -> Result<Self, Error> {
        // Instanciate and bind module
        let mut inner = module::Area::new(props);

        // Xbar ==============================================================
        inner.insert_module(Arc::new(mem::XBar::new(
            mem::XBarParams {
                inflight_req: 10,
                frontend_latency: types::Latency::Cycle(2.cycles()),
                forward_latency: types::Latency::Cycle(1.cycles()),
                bandwidth: 10.MiB_s(),
                inbound_cap: None,
                outbound_cap: None,
            },
            inner.child_properties("host_xbar", Default::default()),
        )));

        // DDR ===============================================================
        inner.insert_module(Arc::new(mem::NpRam::new(
            params.ddr.clone(),
            inner.child_properties("ddr", Default::default()),
        )));

        // Attach to Pcie Xbar
        inner.inner_bind("host_xbar::outbound", "ddr::resp_port")?;

        // HBM ===============================================================
        inner.insert_module(Arc::new(mem::NpRam::new(
            params.hbm.clone(),
            inner.child_properties("hbm", Default::default()),
        )));

        // Attach to Pcie Xbar
        inner.inner_bind("host_xbar::outbound", "hbm::resp_port")?;

        // Ucore =============================================================
        inner.insert_module(Arc::new(UCore::new(
            params.ucore.clone(),
            inner.child_properties("ucore", Default::default()),
        )));
        // Attach to Ddr
        inner.inner_bind("ucore::mem", "ddr::resp_port")?;

        // Regmap ============================================================
        inner.insert_module(Arc::new(Regmap::new(
            params.regmap.clone(),
            inner.child_properties("regmap", Default::default()),
        )));
        // Attach to Ddr
        inner.inner_bind("host_xbar::outbound", "regmap::port")?;

        // DMA ===============================================================
        inner.insert_module(Arc::new(mem::Dma::new(
            params.dma.clone(),
            inner.child_properties("dma", Default::default()),
        )));

        // Attach to Hbm
        inner.inner_bind("ucore::dma", "dma::inbound")?;

        // HpuCore ===========================================================
        inner.insert_module(Arc::new(HpuCore::new(
            params.hpu_core.clone(),
            inner.child_properties("hpu_core", Default::default()),
        )));

        // Attach to Hbm
        inner.inner_bind("hpu_core::mem", "hbm::resp_port")?;
        inner.inner_bind("ucore::hpu_req", "hpu_core::req")?;
        inner.inner_bind("ucore::hpu_ack", "hpu_core::ack")?;

        // Host FFI ==========================================================
        // Create Host to Sim bridge
        inner.insert_module(Arc::new(ffi::ipc::H2sBridge::new(
            params.ipc.clone(),
            inner.child_properties("H2sBridge", Default::default()),
        )));
        // Attach to Xbar
        inner.inner_bind("host_xbar::inbound", "H2sBridge::port")?;

        // Expose some inner port
        // Use at higher level for inter-node communication
        inner.expose_port(
            "dma_outbound".to_string(),
            "dma".to_string(),
            "outbound".to_string(),
        );
        inner.expose_port(
            "mem".to_string(),
            "hbm".to_string(),
            "resp_port".to_string(),
        );

        Ok(Self {
            params,
            inner: Arc::new(inner),
        })
    }
}

// Deleguate Module impl to inner Area
impl Module for HpuNode {
    fn properties(&self) -> &Arc<Properties> {
        self.inner.properties()
    }
    fn port(&self, name: &str) -> &dyn port::Port {
        self.inner.port(name)
    }
    fn init(self: Arc<Self>) {
        self.inner.clone().init()
    }
    fn inner_match(&self, name: &str) -> Vec<&dyn Module> {
        self.inner.inner_match(name)
    }
    fn is_leaf(&self) -> bool {
        self.inner.is_leaf()
    }
    fn teardown(self: Arc<Self>) {
        self.inner.clone().teardown()
    }
}
