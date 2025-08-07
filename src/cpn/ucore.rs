//! Depict MicroCore
//! I.e. kind of embedded processor that Handle IOp/DOp translation

use ra2m::prelude::{protocol::dma::DmaBus, protocol::membus::MemBus, *};
use tfhe::tfhe_hpu_backend::asm;

use std::sync::{Arc, Mutex};

/// UCore parameters
#[derive(Debug, Clone)]
pub struct UCoreParams {
    pub axis_depth: usize,
    // TODO
}

/// Store internal state of UCore module
struct UCoreInner {
    // TODO
}

impl UCoreInner {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Module)]
pub struct UCore {
    params: UCoreParams,
    props: Arc<module::Properties>,

    /// Membus to access associated on-board memory
    #[port]
    mem: port::ReqRespPort<MemBus>,
    /// Half-duplex port to issue request to Hpu
    #[port]
    hpu_req: port::MasterPort<asm::DOp>,
    /// Half-duplex port to received ack from Hpu
    #[port]
    hpu_ack: port::SlavePort<asm::DOp>,
    /// dma: Issue Dma request for interboard communication
    #[port]
    dma: port::ReqRespPort<DmaBus>,

    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    inner: Mutex<UCoreInner>,
}

#[default_init]
#[default_teardown]
impl UCore {
    pub fn new(params: UCoreParams, props: module::Properties) -> Self {
        let props = Arc::new(props);

        Self {
            mem: port::ReqRespPort::new("mem", props.clone(), Some(1), None),
            hpu_req: port::MasterPort::new("hpu_req", props.clone(), Some(params.axis_depth), None),
            hpu_ack: port::SlavePort::new("hpu_ack", props.clone(), Some(params.axis_depth), None),
            dma: port::ReqRespPort::new("dma", props.clone(), Some(1), None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(UCoreInner::new()),
            params,
            props,
        }
    }
}
