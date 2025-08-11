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

/// Some properties regarding memory PC
pub const MEM_CT_PC_MAX: usize = 2;
pub const HBM_BSK_PC_MAX: usize = 16;
pub const HBM_KSK_PC_MAX: usize = 16;
