//! Depict MicroCore
//! I.e. kind of embedded processor that Handle IOp/DOp translation

use ra2m::prelude::{
    protocol::{addr::Addr, dma::DmaBus, membus::MemBus, network::Network},
    *,
};
use tfhe::tfhe_hpu_backend::{
    asm::{
        ToHex,
        dop::{Opcode, PeUcoreInsn},
    },
    prelude::*,
};

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use super::DOpPayload;

/// UCore parameters
#[derive(Debug, Clone)]
pub struct UCoreParams {
    pub node_id: u8,
    pub fw_pc: MemKind,

    /// Ciphertext memory
    /// Expressed the number of ciphertext slot to allocate
    pub ct_mem: usize,
    pub ct_heap: usize,

    pub axis_depth: usize,
    pub polling_rate: unit::Time,

    pub iopq: QueueConfig,
    pub ackq: QueueConfig,
}

/// Store internal state of UCore module
struct UCoreInner {
    iop_stream: VecDeque<hpu_asm::iop::IOpWordRepr>,
    event_list: HashMap<(hpu_asm::IOpId, hpu_asm::dop::UcoreAlias), Event>,
    // TODO
}

impl UCoreInner {
    pub fn new() -> Self {
        Self {
            iop_stream: VecDeque::new(),
            event_list: HashMap::new(),
        }
    }
}

/// Event states and associated data
#[derive(Debug, Clone)]
enum Event {
    Received(hpu_asm::dop::UcorePayload),
    Resolved(hpu_asm::MemId),
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
    hpu_req: port::MasterPort<DOpPayload>,
    /// Half-duplex port to received ack from Hpu
    #[port]
    hpu_ack: port::SlavePort<DOpPayload>,

    /// Ctrl: Issue/Received control token for interboard synchronisation
    #[port]
    ctrl: port::ReqRespPort<Network<u8, hpu_asm::dop::UcorePayload>>,

    /// dma: Issue Dma request for interboard communication
    #[port]
    dma: port::ReqRespPort<DmaBus<(u8, Addr)>>,

    prc: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    inner: Mutex<UCoreInner>,
}

#[default_teardown]
impl UCore {
    pub fn new(params: UCoreParams, props: module::Properties) -> Self {
        let props = Arc::new(props);

        Self {
            mem: port::ReqRespPort::new("mem", props.clone(), Some(1), None),
            hpu_req: port::MasterPort::new("hpu_req", props.clone(), Some(params.axis_depth), None),
            hpu_ack: port::SlavePort::new("hpu_ack", props.clone(), Some(params.axis_depth), None),
            ctrl: port::ReqRespPort::new("ctrl", props.clone(), None, None),
            dma: port::ReqRespPort::new("dma", props.clone(), Some(1), None),
            prc: Mutex::new(Vec::new()),
            inner: Mutex::new(UCoreInner::new()),
            params,
            props,
        }
    }

    #[init]
    fn _init(self: Arc<Self>) {
        let mut prc = self.prc.lock().unwrap();
        let asc = self.clone();
        prc.push(spawn_prc!(Self::iopq_flush(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::hpu_feed(asc)));
        let asc = self.clone();
        prc.push(spawn_prc!(Self::ackq_flush(asc)));

        // Handle sync payload
        let asc = self.clone();
        prc.push(spawn_prc!(Self::ctrl_flush(asc)));
    }
}

/// Implement a set of runtime task executed by Ucore
impl UCore {
    /// This function poll iopq in memory and buffered value in iop_stream
    async fn iopq_flush(self: Arc<Self>) {
        let QueueConfig {
            head_ofst,
            tail_ofst,
            data_ofst,
            size_w,
            mem,
        } = &self.params.iopq;
        let base_addr = match mem {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { .. } => {
                panic!("Queue must be in DDR, it's currently the only way to have predictive addr")
            }
        };

        loop {
            delay::Delay::wait_for(self.params.polling_rate.into()).await;

            let iop_head = {
                let mut iop_head = 0_u32;
                self.mem
                    .read(self.properties(), base_addr + *head_ofst, &mut iop_head)
                    .await
                    .expect("Error while reading Iopq head");
                iop_head
            };

            let iop_tail = {
                let mut iop_tail = 0_u32;
                self.mem
                    .read(self.properties(), base_addr + *tail_ofst, &mut iop_tail)
                    .await
                    .expect("Error while reading Iopq head");
                iop_tail
            };

            let word_avail = (iop_head - iop_tail) % *size_w as u32;
            let bytes_avail = word_avail as usize * std::mem::size_of::<u32>();
            let chunk_start = base_addr
                + *data_ofst
                + ((iop_tail as usize % *size_w) * std::mem::size_of::<u32>() as usize);
            if word_avail != 0 {
                // Read body
                let data_u8 = self
                    .mem
                    .read_bytes(self.properties(), chunk_start, bytes_avail)
                    .await
                    .expect("Error while reading Iopq body");
                let data_u32 = bytemuck::cast_slice::<u8, u32>(&data_u8);

                // append to inner deque buffer
                self.inner
                    .lock()
                    .unwrap()
                    .iop_stream
                    .extend(data_u32.iter());

                // Ack for value consumption
                self.mem
                    .write(self.properties(), base_addr + *tail_ofst, &iop_head)
                    .await
                    .expect("Error while writing Iopq tail");
            }
        }
    }

    async fn ackq_flush(self: Arc<Self>) {
        let QueueConfig {
            head_ofst,
            tail_ofst,
            data_ofst,
            size_w,
            mem,
        } = &self.params.ackq;
        let base_addr = match mem {
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { pc } => {
                panic!("Queue must be in DDR, it's currently the only way to have predictive addr")
            }
        };

        loop {
            // Check for room in the ack queue
            let iop_head = {
                let mut iop_head = 0_u32;
                self.mem
                    .read(self.properties(), base_addr + *head_ofst, &mut iop_head)
                    .await
                    .expect("Error while reading Ackq head");
                iop_head
            };

            let iop_tail = {
                let mut iop_tail = 0_u32;
                self.mem
                    .read(self.properties(), base_addr + *tail_ofst, &mut iop_tail)
                    .await
                    .expect("Error while reading Ackq head");
                iop_tail
            };

            let word_free = *size_w as u32 - ((iop_head - iop_tail) % *size_w as u32);
            let chunk_start = base_addr
                + *data_ofst
                + ((iop_head as usize % *size_w) * std::mem::size_of::<u32>() as usize);
            if word_free != 0 {
                let dop = self
                    .hpu_ack
                    .wait_pkt_ep(None)
                    .await
                    .expect("Issue with DOpPayload xfer")
                    .unwrap_payload();
                let dop_hex = dop.inner.to_hex();

                // write body
                self.mem
                    .write(self.properties(), chunk_start, &dop_hex)
                    .await
                    .expect("Error while reading Ackq body");

                // Ack for value insertion
                self.mem
                    .write(self.properties(), base_addr + *head_ofst, &(iop_head + 1))
                    .await
                    .expect("Error while writing Iopq tail");
            } else {
                log!(|self| log::Category::Own, log::Verbosity::Info => => "Ackq is full");
            }
        }
    }

    async fn hpu_feed(self: Arc<Self>) {
        loop {
            // Extract one Iop from stream
            let iop_pdg = {
                let iop_stream = &mut self.inner.lock().unwrap().iop_stream;
                match hpu_asm::IOp::from_words(iop_stream) {
                    Err(_) => {
                        // not enough data to match
                        None
                    }
                    Ok(iop) => Some(iop),
                }
            };

            if let Some(iop) = iop_pdg {
                log!(|self| log::Category::Own, log::Verbosity::Debug => iop => "Will process following iop");

                // Retrived DOp stream from memory
                let dops = self.load_fw(&iop).await;
                // handle Dop
                self.clone()
                    .exec_or_deferred(&iop, &dops)
                    .await
                    .expect("Issue with ucore exec_or_deferred");
            } else {
                delay::Delay::wait_for(self.params.polling_rate.into()).await;
            }
        }
    }

    /// This function handle ctrl message and update internal table accordingly
    async fn ctrl_flush(self: Arc<Self>) {
        loop {
            let ucore_pld = self
                .ctrl
                .rx()
                .wait_pkt_ep(None)
                .await
                .expect("Issue with Ctrl xfer")
                .inner_unwrap()
                .unwrap_payload();

            self.insert_event(ucore_pld);
        }
    }
}

/// Implement a set of utility functions
/// Mainly extracted from the mockup
impl UCore {
    /// Convert words offset/addr/size in bytes
    fn words_to_bytes<W>(words: usize) -> usize {
        words * std::mem::size_of::<W>()
    }

    /// Convert bytes offset/addr/size in words
    fn bytes_to_words<W>(words: usize) -> usize {
        words / std::mem::size_of::<W>()
    }

    /// Read DOp stream from Firmware memory
    async fn load_fw(&self, iop: &hpu_asm::IOp) -> Vec<hpu_asm::DOp> {
        let hid = self.params.node_id;

        let fw_base_addr = match self.params.fw_pc {
            // TODO swap with global addr space (i.e. all cpn behind same xbar to prevent such gym)
            MemKind::Ddr { offset } => offset,
            MemKind::Hbm { .. } => {
                panic!("Ucore can't access HBM. Fw translation table must be stored in DDR");
            }
        };

        let dop_ofst = {
            let mut val = 0_u32;
            self.mem
                .read(
                    self.properties(),
                    fw_base_addr + Self::words_to_bytes::<u32>(iop.fw_entry(hid)),
                    &mut val,
                )
                .await
                .expect("Error while reading Iopq body");
            val as usize
        };
        let dop_len = {
            let mut val = 0_u32;
            self.mem
                .read(
                    self.properties(),
                    fw_base_addr + dop_ofst as usize,
                    &mut val,
                )
                .await
                .expect("Error while reading fw");
            Self::words_to_bytes::<u32>(val as usize)
        };
        let dop_stream_u8 = self
            .mem
            .read_bytes(
                self.properties(),
                fw_base_addr + dop_ofst + std::mem::size_of::<u32>(),
                dop_len,
            )
            .await
            .expect("Error while reading fw");
        let dop_stream_u32 = bytemuck::cast_slice::<u8, u32>(&dop_stream_u8);

        // Parse DOp stream
        dop_stream_u32
            .iter()
            .map(|bin| hpu_asm::DOp::from_hex(*bin).expect("Invalid DOp"))
            .collect::<Vec<hpu_asm::DOp>>()
    }

    /// Rtl ucore emulation
    /// Some Dop are directly executed by the ucore other one are deferred to HPU
    async fn exec_or_deferred(
        self: Arc<Self>,
        iop: &hpu_asm::IOp,
        dops: &[hpu_asm::DOp],
    ) -> Result<(), anyhow::Error> {
        for dop in dops {
            // Execute DOp directly or [patch] & deferred to Hpu
            let deferred_dop = match dop {
                // Direct execution by Ucore
                hpu_asm::DOp::SYNC(hpu_asm::dop::DOpSync(inner)) => {
                    // Build Ucore payload based on context and current DOp
                    let (iid, slot) = match inner.alias {
                        hpu_asm::dop::UcoreAlias::Src { tid, bid } => {
                            let op = iop.src()[tid as usize];
                            (op.props.iid, hpu_asm::MemId::Addr(op.addr.base_cid))
                        }
                        hpu_asm::dop::UcoreAlias::Dst { tid, bid } => {
                            let op = iop.dst()[tid as usize];
                            (op.props.iid, hpu_asm::MemId::Addr(op.addr.base_cid))
                        }
                        hpu_asm::dop::UcoreAlias::Heap { bid } => {
                            // NB: B2B heap follow user space CT
                            // TODO: Add dedicated size for B2B_heap ?
                            let mid = hpu_asm::MemId::Addr(hpu_asm::CtId(
                                (self.params.ct_mem - self.params.ct_heap) as u16 + bid,
                            ));
                            (iop.get_iid(), mid)
                        }
                        hpu_asm::dop::UcoreAlias::None => panic!(
                            "DOp stream must not contains Hpu vanilla SYNC. This DOp must be only added by the Ucore at the end of the stream"
                        ),
                    };

                    let from_id = hpu_asm::NodeId(self.params.node_id);
                    let to_id = inner.hid;

                    let ucore_pld = hpu_asm::dop::UcorePayload {
                        slot,
                        alias: inner.alias,
                        hid: from_id,
                        iid,
                        opcode: inner.opcode,
                    };
                    self.ctrl
                        .tx()
                        .send_pkt(Network::new_wrapped(from_id.0, to_id.0, ucore_pld, None))
                        .await?;

                    None
                }
                hpu_asm::DOp::WAIT(hpu_asm::dop::DOpWait(inner)) => {
                    // Get assaciated IOpId based on alias content
                    let iid = match inner.alias {
                        hpu_asm::dop::UcoreAlias::Src { tid, bid } => {
                            iop.src()[tid as usize].props.iid
                        }
                        hpu_asm::dop::UcoreAlias::Dst { tid, bid } => {
                            iop.dst()[tid as usize].props.iid
                        }
                        hpu_asm::dop::UcoreAlias::Heap { bid } => iop.dst()[0].props.iid,
                        hpu_asm::dop::UcoreAlias::None => panic!(
                            "DOp stream must not contains Hpu vanilla SYNC. This DOp must be only added by the Ucore at the end of the stream"
                        ),
                    };
                    self.wait(iid, inner.alias).await;

                    None
                }
                hpu_asm::DOp::LD_B2B(hpu_asm::dop::DOpLdB2B(inner)) => {
                    let mut inner = inner.clone();
                    let iop = iop.clone();

                    //1.  Do virtual to physical Id mapping
                    inner.hid = iop
                        .phys_id(inner.hid)
                        .expect(
                            "Invalid IOp mapping. DOp stream contains an unavailable Hpu TargetId",
                        )
                        .into();

                    //2. Register background worker
                    // This worker will wait on associated event and triggered the dma acess
                    let asc = self.clone();
                    spawn_prc!(Self::ld_b2b_bg(asc, iop, inner));
                    None
                }

                _ => {
                    let mut dop_patch = dop.clone();
                    match &mut dop_patch {
                        // Patching and deferred execution
                        // LD/ST patching
                        // Do MemId template resolution
                        // Warn: With Multi-Hpu support Src/Dst could be located on another Hpu
                        hpu_asm::DOp::LD(hpu_asm::dop::DOpLd(inner))
                        | hpu_asm::DOp::ST(hpu_asm::dop::DOpSt(inner)) => {
                            inner.slot = match inner.slot {
                                hpu_asm::MemId::Heap { bid } => hpu_asm::MemId::Addr(
                                    hpu_asm::CtId((self.params.ct_mem - 1) as u16 - bid),
                                ),
                                hpu_asm::MemId::Src { tid, bid } => {
                                    let operand = iop.src()[tid as usize];
                                    if operand.props.pos.0 == self.params.node_id {
                                        // Local access -> Usual patching
                                        hpu_asm::MemId::Addr(hpu_asm::CtId(
                                            operand.addr.base_cid.0 + bid as u16,
                                        ))
                                    } else {
                                        // Remote access
                                        let ucore_dop = PeUcoreInsn {
                                            alias: hpu_asm::dop::UcoreAlias::Src {
                                                tid,
                                                bid: Some(bid),
                                            },
                                            hid: operand.props.pos,
                                            opcode: hpu_asm::dop::Opcode::LD_B2B(),
                                        };
                                        self.clone()
                                            .ld_b2b_bg(iop.clone(), ucore_dop)
                                            .await
                                            .expect("Issue with ld_b2b background task")
                                    }
                                }
                                hpu_asm::MemId::Dst { tid, bid } => {
                                    let operand = iop.dst()[tid as usize];
                                    hpu_asm::MemId::Addr(hpu_asm::CtId(
                                        operand.addr.base_cid.0 + bid as u16,
                                    ))
                                }
                                hpu_asm::MemId::Addr(ct_id) => hpu_asm::MemId::Addr(ct_id),
                            };
                            Some(dop_patch)
                        }
                        // Immediat patching
                        hpu_asm::DOp::ADDS(hpu_asm::dop::DOpAdds(inner))
                        | hpu_asm::DOp::SUBS(hpu_asm::dop::DOpSubs(inner))
                        | hpu_asm::DOp::SSUB(hpu_asm::dop::DOpSsub(inner))
                        | hpu_asm::DOp::MULS(hpu_asm::dop::DOpMuls(inner)) => {
                            patch_imm(iop, &mut inner.msg_cst);
                            Some(dop_patch)
                        }
                        // Deferred execution
                        _ => Some(dop_patch),
                    }
                }
            };

            if let Some(dop) = deferred_dop {
                // Wrapped DOp in packet and send them to HpuCore
                let dop_pkt = Packet::wrap_payload(DOpPayload::new(dop), Default::default());
                self.hpu_req.send_pkt(dop_pkt).await?;
            }
        }
        // Ucore is in charge of Sync insertion
        // TODO check format of inserted DOp
        // TODO rework Ctor (split usual host sync from B2B sync ?)
        let sync_dop = hpu_asm::dop::DOpSync::new(
            hpu_asm::NodeId(self.params.node_id),
            hpu_asm::dop::UcoreAlias::None,
        )
        .into();
        let sync_dop_pkt = Packet::wrap_payload(DOpPayload::new(sync_dop), Default::default());
        self.hpu_req.send_pkt(sync_dop_pkt).await?;
        log!(|self| log::Category::Own, log::Verbosity::Trace => iop => "IOp translate and deferred to Hpu");
        Ok(())
    }

    /// Wait an event to be received
    async fn wait(&self, iid: hpu_asm::IOpId, alias: hpu_asm::dop::UcoreAlias) {
        // Hang DOp translation until associated event is founded
        loop {
            let wait_ready = {
                let inner_data = self.inner.lock().unwrap();
                inner_data.event_list.contains_key(&(iid, alias))
            };

            if wait_ready {
                break;
            } else {
                event::Event::wait(&forge_event_name!(|self| "sync_evt")).await;
            }
        }
    }

    /// Background task to wait for Sync event and start matching DMA request
    async fn ld_b2b_bg(
        self: Arc<Self>,
        iop: hpu_asm::IOp,
        dop: PeUcoreInsn,
    ) -> Result<hpu_asm::MemId, anyhow::Error> {
        loop {
            let (iid, alias, event) = {
                let inner = self.inner.lock().unwrap();

                let (iid, alias) = match dop.alias {
                    hpu_asm::dop::UcoreAlias::Src { tid, bid } => {
                        let op = iop.src()[tid as usize];
                        (op.props.iid, dop.alias)
                    }
                    hpu_asm::dop::UcoreAlias::Dst { tid, bid } => {
                        let op = iop.dst()[tid as usize];
                        (op.props.iid, dop.alias)
                    }
                    hpu_asm::dop::UcoreAlias::Heap { bid } => (iop.get_iid(), dop.alias),
                    hpu_asm::dop::UcoreAlias::None => panic!(
                        "Couldn't load untagged value from another board. For simple \"rendez-vous\" use WAIT instead"
                    ),
                };
                (iid, alias, inner.event_list.get(&(iid, alias)).cloned())
            };

            match event {
                Some(Event::Resolved(mid)) => {
                    // Nothing to do, value already fetch on board
                    log!(|self| log::Category::Own, log::Verbosity::Info => iop, dop, mid => "Resolved");
                    return Ok(mid);
                }
                Some(Event::Received(payload)) => {
                    log!(|self| log::Category::Own, log::Verbosity::Info => iop, dop, payload => "Received");
                    // Value ready but not retrieved yet
                    // Start B2B Dma for each ciphertext flit
                    // TODO: Issue a dma request for each ciphertext bank
                    // TODO: Compute correct addr/lenght
                    let src_addr = Addr::Phys(0); // TODO must depends on payload.slot
                    let dst_mid = hpu_asm::MemId::Heap { bid: 0 }; // TODO must depends on dop.alias
                    let dst_addr = Addr::Phys(0); // TODO must depends on dop.alias
                    let dma_pkt = DmaBus::new_wrapped(
                        (payload.hid.0, src_addr),
                        (self.params.node_id, dst_addr),
                        protocol::addr::Pattern::Simple(10.MiB()),
                        None,
                    );
                    let _ = self.dma.b_req_resp(dma_pkt).await?;

                    // Update event state
                    let mut inner = self.inner.lock().unwrap();
                    let event = inner.event_list.get_mut(&(iid, alias)).unwrap();
                    *event = Event::Resolved(dst_mid);
                }
                None => {
                    log!(|self| log::Category::Own, log::Verbosity::Info => iop, dop => "Pending");
                    if iid == hpu_asm::SW_IOP_ID {
                        // Value generated by Sw and already uploaded in memory
                        // Automatically register it's entry
                        let (hid, slot) = match dop.alias {
                            hpu_asm::dop::UcoreAlias::Src { tid, bid } => (
                                iop.src()[tid as usize].props.pos,
                                hpu_asm::MemId::Src {
                                    tid,
                                    bid: bid.unwrap_or(0),
                                },
                            ),
                            _ => panic!("Invalid alias with SW generated operand"),
                        };
                        let ucore_pld = hpu_asm::dop::UcorePayload {
                            slot,
                            alias: dop.alias,
                            hid,
                            iid,
                            opcode: hpu_asm::dop::Opcode::SYNC(),
                        };
                        self.insert_event(ucore_pld);
                    } else {
                        self.wait(iid, dop.alias).await
                    }
                }
            }
        }
    }

    /// Check around event insertion in event_list
    fn insert_event(&self, ucore_pld: hpu_asm::dop::UcorePayload) {
        if ucore_pld.opcode.is_sync_inst() {
            // Update inner state table
            let mut inner = self.inner.lock().unwrap();
            let present = inner
                .event_list
                .insert((ucore_pld.iid, ucore_pld.alias), Event::Received(ucore_pld));
            if let Some(event) = present {
                panic!(
                    "Received duplicated SYNC event @{}:{} =>{event:?}",
                    ucore_pld.iid, ucore_pld.alias
                );
            }
            // Notify to wake up pending task
            event::Event::triggered(&forge_event_name!(|self| "sync_evt"), None);
        } else {
            panic!("Invalid Opcode received in UcorePayload control endpoint {ucore_pld:?}")
        }
    }
}

/// Utility function to patch immediat argument
fn patch_imm(iop: &hpu_asm::IOp, imm: &mut hpu_asm::ImmId) {
    *imm = match imm {
        hpu_asm::ImmId::Cst(val) => hpu_asm::ImmId::Cst(*val),
        hpu_asm::ImmId::Var { tid, bid } => {
            hpu_asm::ImmId::Cst(iop.imm()[*tid as usize].msg_block(*bid))
        }
    }
}
