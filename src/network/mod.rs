use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::proc_macros::rpc;
use std::collections::HashMap;
use std::{net::SocketAddr, sync::Arc};
use tokio;

use crate::types::{LedgerDiff, Signature, UserId};
// use jsonrpsee::core::middleware::RequestBodyLimitLayer;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::server::ServerBuilder;
// use jsonrpsee::server::middleware::http::RequestBodyLimitLayer;
use tokio::sync::{Mutex, mpsc, mpsc::Receiver, mpsc::Sender};
use tower::limit::ConcurrencyLimitLayer;

// How many DM messages from the network can be stored in the channel
const MAX_MSGS_PER_LINK_ID: usize = 20;

mod api {
    use super::*;
    // This generates: PeerApiServer (server trait to implement) and PeerApiClient (client stub used to call peers)
    #[rpc(server, client)]
    pub trait MyRpc<T> {
        #[method(name = "msg")]
        async fn msg(&self, msg: MsgLink<T>) -> RpcResult<()>;
    }

    pub struct MsgLinkServer<T> {
        registry: Registry<T>,
    }
    impl<T> MsgLinkServer<T> {
        pub fn new(registry: Registry<T>) -> Self {
            MsgLinkServer { registry }
        }
    }

    #[async_trait]
    impl<T> MyRpcServer<T> for MsgLinkServer<T>
    where
        T: Send + 'static,
    {
        async fn msg(&self, msg: MsgLink<T>) -> RpcResult<()> {
            let msg_id = msg.msg_id;
            self.registry.register(msg_id.clone()).await;
            self.registry.deliver(msg).await;
            Ok(())
        }
    }
}

type InnerRegistry<T> = HashMap<MsgLinkId, (Sender<MsgLink<T>>, Option<Receiver<MsgLink<T>>>)>;
#[derive(Clone)]
pub struct Registry<T> {
    msg_channel_map: Arc<Mutex<InnerRegistry<T>>>,
}
impl<T> Registry<T> {
    pub fn new() -> Self {
        Self {
            msg_channel_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    // If receiving messages for a MsgLinkId that hasnt been registered yet, it will store sender and receiver
    // If initiating a MsgLinkId, the rcvr will be returned automatically
    pub async fn register(&self, msg_id: MsgLinkId) {
        self.msg_channel_map
            .lock()
            .await
            .entry(msg_id)
            .or_insert_with(|| {
                let (tx, rx) = mpsc::channel(MAX_MSGS_PER_LINK_ID);
                (tx, Some(rx))
            });
    }
    // Return and empty the stored rx channel.  Note: this can only be done once
    pub async fn subscribe(&self, msg_id: MsgLinkId) -> Option<Receiver<MsgLink<T>>> {
        let mut inner = self.msg_channel_map.lock().await;
        let (_, rx) = inner.entry(msg_id).or_insert_with(|| {
            let (tx, rx) = mpsc::channel(16);
            (tx, Some(rx))
        });
        rx.take()
    }
    pub async fn deliver(&self, msg: MsgLink<T>) {
        if let Some((tx, _)) = self.msg_channel_map.lock().await.get(msg.get_msg_id()) {
            tx.send(msg).await.unwrap();
        }
    }
    pub async fn remove(&self, msg_id: MsgLinkId) {
        self.msg_channel_map.lock().await.remove(&msg_id);
    }
}

use api::{MsgLinkServer, MyRpcClient, MyRpcServer};

pub trait Data:
    Send + Sync + serde::Serialize + serde::de::DeserializeOwned + Clone + 'static
{
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum MsgLinkData {
    Send(Signature, Vec<LedgerDiff>),
}
impl Data for MsgLinkData {}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct MsgLink<T> {
    sender: UserId,
    msg_id: MsgLinkId,
    data: T,
}
impl<T> MsgLink<T> {
    pub fn new(sender: UserId, req_id: MsgLinkId, data: T) -> Self {
        Self {
            sender,
            msg_id: req_id,
            data,
        }
    }
    pub fn get_msg_id(&self) -> &MsgLinkId {
        &self.msg_id
    }
}
#[derive(PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
pub struct MsgLinkId(u128);
impl MsgLinkId {
    pub fn new(id: u128) -> Self {
        Self(id)
    }
}

pub fn create_msg_link_rpc_module<T: Data>(registry: Registry<T>) -> jsonrpsee::RpcModule<()> {
    let server_impl = MsgLinkServer::new(registry);
    // `into_rpc()` method was generated inside of the `RpcServer` trait under the hood.
    server_impl.into_rpc().remove_context()
}
pub struct Interface<T> {
    /// My IpAddr
    _addr: SocketAddr,
    /// TODO: My PubKey
    pubkey: UserId,
    /// Maps a UserId to their addr
    addr_book: Arc<Mutex<HashMap<UserId, SocketAddr>>>,
    /// Stores clients so I don't have to recreate them for each outgoing connection
    clients: Arc<Mutex<HashMap<SocketAddr, Arc<HttpClient>>>>,
    registry: Registry<T>,
}
impl<T: Data> Interface<T> {
    pub async fn new() -> Arc<Self> {
        let server = ServerBuilder::default()
            .set_http_middleware(
                tower::ServiceBuilder::new().layer(ConcurrencyLimitLayer::new(1000)), // .layer(RequestBodyLimitLayer::new(1024 * 1024)), // 1 MB
            )
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let registry = Registry::new();
        let iface = Arc::new(Interface {
            _addr: addr,
            addr_book: Arc::new(Mutex::new(HashMap::new())),
            pubkey: UserId::new(),
            clients: Arc::new(Mutex::new(HashMap::new())),
            registry: registry.clone(),
        });

        let server_handle = server.start(create_msg_link_rpc_module(registry));

        tokio::spawn(server_handle.stopped());

        iface
    }

    /// Test to have a communication exchange
    pub async fn send_msg(&self, rcvr: &UserId, msg_data: MsgLinkData, msg_link_id: MsgLinkId) {
        println!(
            "{:?}, {}, sending msg to {:?}, {:?}",
            self.pubkey, self._addr, rcvr, msg_data
        );
        let client = self.connect(rcvr).await;
        let msg_link = MsgLink::new(self.pubkey, msg_link_id, msg_data);
        self.registry.register(msg_link_id).await;
        client.msg(msg_link).await.unwrap();
    }

    pub async fn connect(&self, rcvr: &UserId) -> Arc<HttpClient> {
        let addr_book = self.addr_book.lock().await;
        let addr = addr_book.get(rcvr).unwrap();
        let mut clients = self.clients.lock().await;
        let client = clients.entry(*addr).or_insert_with(|| {
            let server_url = format!("http://{}", addr);
            Arc::new(HttpClientBuilder::default().build(&server_url).unwrap())
        });
        client.clone()
    }
    pub async fn add_addr_book(&self, id: UserId, addr: SocketAddr) {
        self.addr_book.lock().await.insert(id, addr);
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn interface_test() {
        let iface = Interface::new().await;
        let addr = iface._addr;
        let id = iface.pubkey;
        let msg_id = MsgLinkId::new(68);

        let mut rx = iface.registry.subscribe(msg_id.clone()).await.unwrap();

        tokio::task::spawn(async move {
            loop {
                let value: MsgLink<MsgLinkData> = rx.recv().await.unwrap();
                println!("receved {:?}", value);
            }
        });

        let iface2: Arc<Interface<MsgLinkData>> = Interface::new().await;
        iface2.add_addr_book(id, addr).await;
        let msg_link_data = MsgLinkData::Send("sign0x0dj03dm0".to_string(), Vec::new());
        iface2
            .send_msg(&id, msg_link_data.clone(), msg_id.clone())
            .await;
    }

    #[tokio::test]
    async fn registry_subscribe_only_once() {
        let registry: Registry<MsgLinkData> = Registry::new();
        let msg_id = MsgLinkId::new(98);

        // First subscribe should succeed
        let rx1 = registry.subscribe(msg_id).await;
        assert!(rx1.is_some(), "first subscribe should return a receiver");

        // Second subscribe should return None
        let rx2 = registry.subscribe(msg_id).await;
        assert!(rx2.is_none(), "second subscribe should return None");
    }
    #[tokio::test]
    async fn registry_send_before_subscribe() {
        let registry = Registry::new();
        let msg_id = MsgLinkId::new(789);
        let sender = UserId::new();

        let msg = MsgLink::new(sender, msg_id, MsgLinkData::Send("sig".to_string(), vec![]));

        // Register the msg_id but DO NOT subscribe yet
        registry.register(msg_id).await;

        // Deliver message before subscription
        registry.deliver(msg).await;

        // Now subscribe
        let mut rx = registry
            .subscribe(msg_id)
            .await
            .expect("receiver should exist");

        // The message should already be buffered
        let received = rx.recv().await.expect("should receive buffered msg");

        assert_eq!(*received.get_msg_id(), msg_id);
    }

    #[tokio::test]
    async fn interface_send_before_receiver_subscribes() {
        let iface1: Arc<Interface<MsgLinkData>> = Interface::new().await;
        let iface2 = Interface::new().await;

        // Exchange address
        iface1.add_addr_book(iface2.pubkey, iface2._addr).await;

        let msg_id = MsgLinkId::new(987);
        let msg_data = MsgLinkData::Send("sig-buffered".to_string(), Vec::new());

        // Send BEFORE iface2 subscribes or registers
        iface1
            .send_msg(&iface2.pubkey, msg_data.clone(), msg_id)
            .await;

        // Now iface2 subscribes AFTER the message arrived
        let mut rx = iface2
            .registry
            .subscribe(msg_id)
            .await
            .expect("receiver should exist");

        // The message should already be buffered
        let received: MsgLink<MsgLinkData> =
            tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .expect("timed out waiting for buffered msg")
                .expect("channel closed unexpectedly");

        assert_eq!(*received.get_msg_id(), msg_id);
    }
    #[tokio::test]
    async fn registry_multiple_msglinkids_interleaved_no_signature_usage() {
        let registry = Registry::new();
        let sender = UserId::new();

        let msg_id_a = MsgLinkId::new(222);
        let msg_id_b = MsgLinkId::new(333);

        registry.register(msg_id_a).await;
        registry.register(msg_id_b).await;

        // Interleave deliveries (payload contents don't matter)
        registry
            .deliver(MsgLink::new(
                sender,
                msg_id_a,
                MsgLinkData::Send("unused".to_string(), vec![]),
            ))
            .await;

        registry
            .deliver(MsgLink::new(
                sender,
                msg_id_b,
                MsgLinkData::Send("unused".to_string(), vec![]),
            ))
            .await;

        registry
            .deliver(MsgLink::new(
                sender,
                msg_id_a,
                MsgLinkData::Send("unused".to_string(), vec![]),
            ))
            .await;

        // Subscribe after all messages arrived
        let mut rx_a = registry
            .subscribe(msg_id_a)
            .await
            .expect("receiver A should exist");

        let mut rx_b = registry
            .subscribe(msg_id_b)
            .await
            .expect("receiver B should exist");

        // Count messages per MsgLinkId
        let mut count_a = 0;
        let mut count_b = 0;

        while let Ok(Some(_)) =
            tokio::time::timeout(std::time::Duration::from_millis(50), rx_a.recv()).await
        {
            count_a += 1;
        }

        while let Ok(Some(_)) =
            tokio::time::timeout(std::time::Duration::from_millis(50), rx_b.recv()).await
        {
            count_b += 1;
        }

        assert_eq!(count_a, 2, "MsgLinkId A should receive exactly 2 messages");
        assert_eq!(count_b, 1, "MsgLinkId B should receive exactly 1 messages");
    }
}
