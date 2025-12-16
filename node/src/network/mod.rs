use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::proc_macros::rpc;
use std::collections::HashMap;
use std::{net::SocketAddr, sync::Arc};
use tokio;

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::server::ServerBuilder;
use tokio::sync::{Mutex, mpsc, mpsc::Receiver, mpsc::Sender};
// use tower::limit::ConcurrencyLimitLayer;
use crate::types::UserId;

// How many DM messages from the network can be stored in the channel
const MAX_DMS_IN_CHANNEL: usize = 100;
const MAX_MSGS_PER_LINK_ID: usize = 20;

// TODO: instead of string, want to make `String` an event enum to produce events like MessageLinkReceived(id, data)
// Also want to this for the dm_channel.  Maybe even just have one event return type for both and type def it
// type RegistryChannel = (Sender<NetEvent>, Option<Receiver<NetEvent>>);
// enum NetEvent
type InnerRegistry = HashMap<MsgLinkId, (Sender<String>, Option<Receiver<String>>)>;
#[derive(Clone)]
struct Registry {
    msg_channel_map: Arc<Mutex<InnerRegistry>>,
    // Single consumer for dm_data (like every individual MsgLink).
    dm_channel: Arc<Mutex<(Sender<DirectMessage>, Option<Receiver<DirectMessage>>)>>,
}
impl Registry {
    pub fn new() -> Self {
        let (dm_tx, dm_rx) = mpsc::channel(MAX_DMS_IN_CHANNEL);
        Self {
            msg_channel_map: Arc::new(Mutex::new(HashMap::new())),
            dm_channel: Arc::new(Mutex::new((dm_tx, Some(dm_rx)))),
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
    pub async fn subscribe(&self, msg_id: MsgLinkId) -> Option<Receiver<String>> {
        let mut inner = self.msg_channel_map.lock().await;
        let (_, rx) = inner.entry(msg_id).or_insert_with(|| {
            let (tx, rx) = mpsc::channel(16);
            (tx, Some(rx))
        });
        rx.take()
    }
    pub async fn deliver(&self, msg_id: MsgLinkId, msg: String) {
        if let Some((tx, _)) = self.msg_channel_map.lock().await.get(&msg_id) {
            tx.send(msg).await.unwrap();
        }
    }
    pub async fn deliver_dm(&self, dm: DirectMessage) {
        self.dm_channel.lock().await.0.send(dm).await.unwrap();
    }
    pub async fn subcribe_dm(&self) -> Option<Receiver<DirectMessage>> {
        self.dm_channel.lock().await.1.take()
    }
    pub async fn remove(&self, msg_id: MsgLinkId) {
        self.msg_channel_map.lock().await.remove(&msg_id);
    }
}
// This generates: PeerApiServer (server trait to implement) and PeerApiClient (client stub used to call peers)
mod api {
    use super::*;
    #[rpc(server, client)]
    pub trait MyRpc {
        #[method(name = "ping")]
        async fn ping(&self) -> RpcResult<String>;
        #[method(name = "dm")]
        async fn dm(&self, msg: DirectMessage) -> RpcResult<()>;

        #[method(name = "msg")]
        async fn msg(&self, msg: MsgLink) -> RpcResult<()>;
        // #[method(name = "msg_reply")]
        // async fn msg_reply(&self, msg: MsgRequestId) -> RpcResult<()>;
    }

    pub struct RpcServerImpl {
        registry: Registry,
        _iface: Arc<Interface>,
    }
    impl RpcServerImpl {
        pub fn new(registry: Registry, _iface: Arc<Interface>) -> Self {
            RpcServerImpl { registry, _iface }
        }
    }

    #[async_trait]
    impl MyRpcServer for RpcServerImpl {
        async fn ping(&self) -> RpcResult<String> {
            Ok(format!("pong"))
        }
        async fn dm(&self, dm: DirectMessage) -> RpcResult<()> {
            self.registry.deliver_dm(dm).await;
            Ok(())
        }

        async fn msg(&self, msg: MsgLink) -> RpcResult<()> {
            let msg_id = msg.req_id;
            self.registry.register(msg_id.clone()).await;
            self.registry.deliver(msg_id, msg.data).await;
            Ok(())
        }
        //async fn msg_reply(&self, msg: MsgRequestId) -> RpcResult<()> {}
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    pub struct DirectMessage {
        sender: UserId,
        msg: String,
    }
    impl DirectMessage {
        pub fn new(sender: UserId, msg: &str) -> Self {
            DirectMessage {
                sender,
                msg: msg.to_string(),
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    pub struct MsgLink {
        sender: UserId,
        req_id: MsgLinkId,
        data: String,
    }
    impl MsgLink {
        pub fn new(sender: UserId, req_id: MsgLinkId, data: String) -> Self {
            Self {
                sender,
                req_id,
                data,
            }
        }
    }
}

use api::{MyRpcClient, MyRpcServer, RpcServerImpl};

use api::{DirectMessage, MsgLink};

#[derive(PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
pub struct MsgLinkId(u64);
impl MsgLinkId {
    pub fn new() -> Self {
        Self(rand::Rng::random(&mut rand::rng()))
    }
}
pub struct Interface {
    /// My IpAddr
    _addr: SocketAddr,
    /// TODO: My PubKey
    pubkey: UserId,
    /// Maps a UserId to their addr
    addr_book: Arc<Mutex<HashMap<UserId, SocketAddr>>>,
    /// Stores clients so I don't have to recreate them for each outgoing connection
    clients: Arc<Mutex<HashMap<SocketAddr, Arc<HttpClient>>>>,
    registry: Registry,
}
impl Interface {
    pub async fn new() -> Arc<Self> {
        let server = ServerBuilder::default()
            // TODO vvv
            // .set_http_middleware(tower::ServiceBuilder::new()
            //.layer(ConcurrencyLimitLayer::new(1000))
            //.layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1 MB
            //)
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
        // Pass notifees in so that new watch channels can be created with new MsgLinks
        let server_impl = RpcServerImpl::new(registry, iface.clone());
        // `into_rpc()` method was generated inside of the `RpcServer` trait under the hood.
        let server_handle = server.start(server_impl.into_rpc());

        tokio::spawn(server_handle.stopped());

        iface
    }
    pub async fn send_dm(&self, rcvr: &UserId, msg: &str) {
        let client = self.connect(rcvr).await;
        let dm = DirectMessage::new(self.pubkey, msg);
        client.dm(dm).await.unwrap();
        println!(
            "{:?}, {}, sent msg to {:?}, {:?}",
            self.pubkey, self._addr, rcvr, msg
        );
    }

    /// Test to have a communication exchange
    pub async fn send_msg(&self, rcvr: &UserId, msg: &str, msg_link_id: MsgLinkId) {
        let client = self.connect(rcvr).await;
        let msg_link = MsgLink::new(self.pubkey, msg_link_id, msg.to_string());
        self.registry.register(msg_link_id).await;
        client.msg(msg_link).await.unwrap();
        println!(
            "{:?}, {}, sent msg to {:?}, {:?}",
            self.pubkey, self._addr, rcvr, msg
        );
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
        let msg_id = MsgLinkId::new();

        let mut rx = iface.registry.subscribe(msg_id.clone()).await.unwrap();

        tokio::task::spawn(async move {
            loop {
                let value = rx.recv().await.unwrap();
                println!("receved {:?}", value);
            }
        });

        let iface2 = Interface::new().await;
        iface2.add_addr_book(id, addr).await;
        iface2
            .send_msg(&id, "test with same msg id", msg_id.clone())
            .await;
        loop {
            iface2.send_msg(&id, "u suck", MsgLinkId::new()).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    // #[tokio::test]
    // async fn interface_test() {
    //     let mut iface = Interface::start().await;
    //     let addr = iface._addr;
    //     let mut notifee = iface.new_data_notifee.clone();
    //     let cache = iface.cache.clone();
    //     let id = iface.pubkey;

    //     let mut iface2 = Interface::start().await;
    //     let addr2 = iface2._addr;
    //     let id2 = iface2.pubkey;

    //     // create address book with both of their entries in it
    //     // iface.add_addr_book(id2, addr2).await;
    //     // iface2.add_addr_book(id, addr).await;

    //     // spawn task to print iface1 incoming data
    //     tokio::task::spawn(async move {
    //         notifee.changed().await.unwrap();
    //         let x = cache.lock().await.data.pop().unwrap();
    //         println!("{x:?}");
    //     });
    //     // spawn task to send a message and wait for a reply
    //     tokio::task::spawn(async move {
    //         // iface2.send_dm_wait_reply(&id, "u r dumb").await;
    //     });

    //     // iface.send_dm(&id2, "no u").await;

    //     tokio::time::sleep(Duration::from_secs(3)).await;
    // }

    // #[tokio::test]
    // async fn it_works() {
    //     let (server_addr, mut new_data_rcvr, cache) = server().await;
    //     let server_url = format!("http://{}", server_addr);
    //     let client = HttpClientBuilder::default().build(&server_url).unwrap();

    //     println!("{}", client.ping().await.unwrap());
    //     client
    //         .dm(DirectMessage::new(UserId::new(), "yo dodo a"))
    //         .await
    //         .unwrap();
    //     tokio::task::spawn(async move {
    //         let mut count = 0;
    //         loop {
    //             tokio::time::sleep(Duration::from_secs(3)).await;
    //             client
    //                 .dm(DirectMessage::new(
    //                     UserId::new(),
    //                     format!("my guy {count}").as_str(),
    //                 ))
    //                 .await
    //                 .unwrap();
    //             count += 1;
    //         }
    //     });
    //     loop {
    //         new_data_rcvr.changed().await.unwrap();
    //         let item = cache.lock().await.data.pop().unwrap();
    //         println!("{item:?}");
    //     }
    // }
}
