//! Depict HpuNode
//!
//! HpuNode contains:
//! * Memory (DDR/Hbm)
//! * Ucore
//! * HpuCore (i.e isc + Pe)
//! * InterBoard interface (NetworkDma)
//! * Host interface
//!
//! No custom logic inside HpuNode, it's only a think wrapper around inner modules.

use ra2m::prelude::anyhow::Error;
use ra2m::prelude::*;
use ra2m::ra2m_cpn::{ffi, mem, net};

use super::*;

/// HpuCore parameters
#[derive(Debug, Clone)]
pub struct HpuNodeParams {
    pub hpu_core: HpuCoreParams,
    pub ucore: UCoreParams,
    pub regmap: RegmapParams,
    pub xbar: mem::XBarParams,
    pub ddr: mem::NpRamParams,
    pub hbm: mem::NpRamParams,
    pub dma: net::NDmaParams<u8>,
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

        // ===================================================================
        // Addressable modules: Ddr/Hbm and regmap
        // ===================================================================
        inner.insert_module(Arc::new(mem::NpRam::new(
            params.ddr.clone(),
            inner.child_properties("ddr", Default::default()),
        )));
        inner.insert_module(Arc::new(mem::NpRam::new(
            params.hbm.clone(),
            inner.child_properties("hbm", Default::default()),
        )));
        inner.insert_module(Arc::new(Regmap::new(
            params.regmap.clone(),
            inner.child_properties("regmap", Default::default()),
        )));

        // ===================================================================
        // Global interconnect
        // ===================================================================
        inner.insert_module(Arc::new(mem::XBar::new(
            params.xbar.clone(),
            inner.child_properties("xbar", Default::default()),
        )));

        // Attach to memories and regmap
        inner.inner_bind("xbar::outbound", "ddr::resp_port")?;
        inner.inner_bind("xbar::outbound", "hbm::resp_port")?;
        inner.inner_bind("xbar::outbound", "regmap::port")?;

        // ===================================================================
        // Hpu inner parts
        // ===================================================================
        // UCore
        inner.insert_module(Arc::new(UCore::new(
            params.ucore.clone(),
            inner.child_properties("ucore", Default::default()),
        )));
        inner.inner_bind("ucore::mem", "xbar::inbound")?;

        // HpuCore
        inner.insert_module(Arc::new(HpuCore::new(
            params.hpu_core.clone(),
            inner.child_properties("hpu_core", Default::default()),
        )));
        inner.inner_bind("hpu_core::mem", "xbar::inbound")?;
        inner.inner_bind("ucore::hpu_req", "hpu_core::req")?;
        inner.inner_bind("ucore::hpu_ack", "hpu_core::ack")?;

        // ===================================================================
        // Hpu board interface
        // ===================================================================
        inner.insert_module(Arc::new(net::NDma::new(
            params.dma.clone(),
            inner.child_properties("ndma", Default::default()),
        )));
        inner.inner_bind("ucore::dma", "ndma::inbound")?;
        inner.inner_bind("ndma::mem", "xbar::inbound")?;

        // Expose some inner port
        // Use at higher level for inter-node communication
        inner.expose_port(
            "net_inbound".to_string(),
            "ndma".to_string(),
            "net_inbound".to_string(),
        );
        inner.expose_port(
            "net_outbound".to_string(),
            "ndma".to_string(),
            "net_outbound".to_string(),
        );
        inner.expose_port("ctrl".to_string(), "ucore".to_string(), "ctrl".to_string());

        // ===================================================================
        // Hpu Host FFI
        // ===================================================================
        // Create Host to Sim bridge
        inner.insert_module(Arc::new(ffi::ipc::H2sBridge::new(
            params.ipc.clone(),
            inner.child_properties("H2sBridge", Default::default()),
        )));
        // Attach to Xbar
        inner.inner_bind("H2sBridge::port", "xbar::inbound")?;

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
