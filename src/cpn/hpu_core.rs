//! Depict Hpu computation core

use ra2m::prelude::{protocol::membus::MemBus, *};

use tfhe::tfhe_hpu_backend::prelude::*;

use super::DOpPayload;
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
    req: port::SlavePort<DOpPayload>,
    /// outbound: Send DOp Ack
    #[port]
    ack: port::MasterPort<DOpPayload>,
    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    inner: Mutex<HpuCoreInner>,
}

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

    #[init]
    fn _init(self: Arc<Self>) {
        let mut prc = self.prc.lock().unwrap();
        let asc = self.clone();
        prc.push(spawn_prc!(Self::loopback(asc)));
    }
}

impl HpuCore {
    async fn loopback(self: Arc<Self>) {
        loop {
            // NB: Should use the wait_pkt_ep version but DOp don't implement the RxStatus
            let dop = self
                .req
                .wait_pkt_ep(None)
                .await
                .expect("Issue with DOpPayload xfer")
                .unwrap_payload();

            log!(|self| log::Category::Own, log::Verbosity::Info => dop);
            match &dop.inner {
                hpu_asm::DOp::SYNC(_dop_sync) => {
                    // loopback DOp as ack
                    let ack_pkt = Packet::wrap_payload(dop, Default::default());
                    self.ack.fwd_pkt(ack_pkt).await;
                }
                _ => {}
            }
        }
    }
}
