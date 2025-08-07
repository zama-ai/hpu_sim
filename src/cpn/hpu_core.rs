//! Depict Hpu computation core

use ra2m::prelude::{protocol::membus::MemBus, *};

use tfhe::tfhe_hpu_backend::asm;

use std::sync::{Arc, Mutex};

/// HpuCore parameters
#[derive(Debug, Clone)]
pub struct HpuCoreParams {
    // TODO
}

/// Store internal state of HpuCore module
struct HpuCoreInner {
    // TODO
}

impl HpuCoreInner {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Module)]
pub struct HpuCore {
    params: HpuCoreParams,
    props: Arc<module::Properties>,

    /// mem: Key and ciphertext
    #[port]
    mem: port::ReqRespPort<MemBus>,

    /// req: Received DOp request
    #[port]
    req: port::SlavePort<asm::DOp>,
    /// outbound: Send DOp Ack
    #[port]
    ack: port::MasterPort<asm::DOp>,
    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    inner: Mutex<HpuCoreInner>,
}

#[default_init]
#[default_teardown]
impl HpuCore {
    pub fn new(params: HpuCoreParams, props: module::Properties) -> Self {
        let props = Arc::new(props);

        Self {
            mem: port::ReqRespPort::new("mem", props.clone(), Some(1), None),
            req: port::SlavePort::new("req", props.clone(), None, None),
            ack: port::MasterPort::new("ack", props.clone(), None, None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(HpuCoreInner::new()),
            params,
            props,
        }
    }
}
