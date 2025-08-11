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
            let pkt = self.req.wait_pkt().await;
            log!(|self| log::Category::Own, log::Verbosity::Info => pkt);

            println!("Received DOp {:?}", pkt.payload());
            match pkt.payload() {
                asm::DOp::SYNC(_dop_sync) => {
                    // loopback DOp as ack
                    let ack_pkt = Packet::wrap_payload(pkt.payload().clone(), Default::default());
                    self.ack.fwd_pkt(ack_pkt).await;
                }
                _ => {}
            }
        }
    }
}
