use std::collections::VecDeque;

use ra2m::prelude::*;
use tfhe::tfhe_hpu_backend::prelude::*;

pub mod hpu_core;
pub use hpu_core::{HpuCore, HpuCoreParams, IscCommand};
pub mod hpu_node;
pub use hpu_node::{HpuNode, HpuNodeParams};
pub mod hpu_cluster;
pub use hpu_cluster::{HpuCluster, HpuClusterParams};
pub mod ucore;
pub use ucore::{UCore, UCoreParams};

pub mod regmap;
pub use regmap::{Regmap, RegmapParams};

use bitfield_struct::bitfield;
use thiserror::Error;

// Some properties regarding memory PC
pub const MEM_CT_PC_MAX: usize = 2;
pub const HBM_BSK_PC_MAX: usize = 16;
pub const HBM_KSK_PC_MAX: usize = 16;

//Common type use as cpn interface.
// Thin wrapper around tfhe_hpu_backend type with extra trait for simulation logging/tracing
#[derive(Debug, serde::Serialize, serde::Deserialize, Trace)]
#[history(trace)]
#[trace_custom(IscCommand)]
pub struct DOpPayload {
    inner: hpu_asm::DOp,

    // inner assembly view as String
    // Use for tracing only, since we cannot implement foreign trait Traceable on foreign type DOp
    #[trace]
    asm_view: String,

    /// Contain history of the handling information of a given access through its route across the
    /// architecture (From the requester up to the responder and back for acknowledgement)
    trace: types::History<IscCommand>,
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

impl std::fmt::Display for DOpPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DOpPayload {} [{}]", self.asm_view, self.trace)
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

// Isc trace byte layout
// Define format of isc_trace words
#[derive(Debug)]
pub struct IscTrace {
    state: IscPoolState,
    insn: u32,
    timestamp: u32,
}

#[derive(Default, Debug)]
pub struct IscPoolState {
    flags: IscPoolFlags,
    wr_lock: u32,
    rd_lock: u32,
    issue_lock: u32,
    sync_id: u32,
}

#[bitfield(u32)]
pub struct IscPoolFlags {
    pdg: bool,
    rd_pdg: bool,
    vld: bool,
    #[bits(3)]
    state: u8,
    #[bits(26)]
    _reserved: u32,
}

/// Parsing error
#[derive(Error, Debug, Clone)]
pub enum TraceParsingError {
    #[error("Incomplete stream")]
    EmptyStream,
}

impl IscTrace {
    pub fn from_words(stream: &mut VecDeque<u32>) -> Result<Self, TraceParsingError> {
        // Keep track of the current peak index
        let mut peak_words = 0;

        let state = {
            let flags = if let Some(word) = stream.get(peak_words) {
                peak_words += 1;
                IscPoolFlags::from_bits(*word)
            } else {
                return Err(TraceParsingError::EmptyStream);
            };
            let wr_lock = if let Some(word) = stream.get(peak_words) {
                peak_words += 1;
                *word
            } else {
                return Err(TraceParsingError::EmptyStream);
            };
            let rd_lock = if let Some(word) = stream.get(peak_words) {
                peak_words += 1;
                *word
            } else {
                return Err(TraceParsingError::EmptyStream);
            };
            let issue_lock = if let Some(word) = stream.get(peak_words) {
                peak_words += 1;
                *word
            } else {
                return Err(TraceParsingError::EmptyStream);
            };
            let sync_id = if let Some(word) = stream.get(peak_words) {
                peak_words += 1;
                *word
            } else {
                return Err(TraceParsingError::EmptyStream);
            };

            IscPoolState {
                flags,
                wr_lock,
                rd_lock,
                issue_lock,
                sync_id,
            }
        };
        let insn = if let Some(word) = stream.get(peak_words) {
            peak_words += 1;
            *word
        } else {
            return Err(TraceParsingError::EmptyStream);
        };

        let timestamp = if let Some(word) = stream.get(peak_words) {
            peak_words += 1;
            *word
        } else {
            return Err(TraceParsingError::EmptyStream);
        };

        Ok(Self {
            state,
            insn,
            timestamp,
        })
    }

    pub fn to_words(&self) -> Vec<u32> {
        let mut words = Vec::new();

        words.push(self.state.flags.0);
        words.push(self.state.wr_lock);
        words.push(self.state.rd_lock);
        words.push(self.state.issue_lock);
        words.push(self.state.sync_id);
        words.push(self.insn);
        words.push(self.timestamp);
        words
    }
}
