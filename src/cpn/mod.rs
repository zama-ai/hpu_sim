use ra2m::prelude::*;
use tfhe::tfhe_hpu_backend::prelude::*;

pub mod hpu_core;
pub use hpu_core::{HpuCore, HpuCoreParams};
pub mod hpu_node;
pub use hpu_node::{HpuNode, HpuNodeParams};
pub mod hpu_cluster;
pub use hpu_cluster::{HpuCluster, HpuClusterParams};
pub mod ucore;
pub use ucore::{UCore, UCoreParams};

pub mod regmap;
pub use regmap::{Regmap, RegmapParams};

// Some properties regarding memory PC
pub const MEM_CT_PC_MAX: usize = 2;
pub const HBM_BSK_PC_MAX: usize = 16;
pub const HBM_KSK_PC_MAX: usize = 16;

//Come type use as cpn interface.
// Thin wrapper around tfhe_hpu_backend type with extra trait for simulation logging/tracing
#[derive(Debug, serde::Serialize, serde::Deserialize, Trace)]
#[history(trace)]
pub struct DOpPayload {
    inner: hpu_asm::DOp,

    // inner assembly view as String
    // Use for tracing only, since we cannot implement foreign trait Traceable on foreign type DOp
    #[trace]
    asm_view: String,

    /// Contain history of the handling information of a given access through its route across the
    /// architecture (From the requester up to the responder and back for acknowledgement)
    trace: types::History,
}

impl DOpPayload {
    pub fn new(dop: hpu_asm::DOp) -> Self {
        let asm_view = dop.to_string();
        Self {
            inner: dop,
            asm_view,
            trace: Default::default(),
        }
    }
}

impl TxStatus for DOpPayload {
    fn tx_check(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
impl RxStatus for DOpPayload {
    fn rx_check(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
