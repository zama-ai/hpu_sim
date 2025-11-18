//! Depict HpuCluster
//!
//! HpuCluster contains a set of HpuNodes.
//! Each node has it's own host interface and are connected together through a Xbar
//! No custom logic inside HpuCluster, it's only a think wrapper around inner modules.

use ra2m::prelude::anyhow::Error;
use ra2m::prelude::*;
use ra2m::ra2m_cpn::mem;

use super::*;

/// HpuCore parameters
#[derive(Debug, Clone)]
pub struct HpuClusterParams {
    hpu_node: Vec<HpuNodeParams>,
}

pub struct HpuCluster {
    params: HpuClusterParams,
    inner: module::Area,
}

impl HpuCluster {
    pub fn new(params: HpuClusterParams, props: module::Properties) -> Result<Self, Error> {
        // Instanciate and bind module
        let mut inner = module::Area::new(props);

        // Inter-nodes Xbar ===================================================
        inner.insert_module(Arc::new(mem::XBar::new(
            mem::XBarParams {
                inflight_req: 10,
                frontend_latency: types::Latency::Cycle(2.cycles()),
                forward_latency: types::Latency::Cycle(1.cycles()),
                bandwidth: 10.MiB_s(),
                inbound_cap: None,
                outbound_cap: None,
            },
            inner.child_properties("cluster_xbar", Default::default()),
        )));

        // Nodes =============================================================
        for (i, node) in params.hpu_node.iter().enumerate() {
            let name = format!("node_{i}");
            inner.insert_module(Arc::new(HpuNode::new(
                node.clone(),
                inner.child_properties(&name, Default::default()),
            )?));

            // Attach to board Xbar
            // Currently simplified version with xbar and std dma instead of custom Dma over MAC
            // Node Dma is master and Hbm is slave
            let dma_port = format!("{name}::dma::resp_port");
            inner.inner_bind("host_xbar::outbound", &dma_port)?;
            let hbm_port = format!("{name}::hbm::resp_port");
            inner.inner_bind("host_xbar::outbound", &hbm_port)?;
        }

        Ok(Self { params, inner })
    }
}
