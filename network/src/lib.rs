use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::{MethodCallback, MethodResponse, Methods, RpcModule, server};
use std::collections::HashMap;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio;

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use jsonrpsee::server::ServerBuilder;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::time::sleep;
// use tower::limit::ConcurrencyLimitLayer;
use types::UserId;

#[derive(Debug)]
enum Data {
    Init,
    // Tuple of UserId, msg
    DirectMessage(UserId, String),

    MsgRequestId(MsgRequestId),
}

// TODO: organize the data into purpose.  ie dm messages will go into DataCache::dms and ledger data will go into DataCache::ledger
// I can get rid of enum Data at this point and just store a vector of structs with info for each data type
struct DataCache {
    data: Vec<Data>,
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
        async fn msg(&self, msg: MsgRequestId) -> RpcResult<()>;
        // #[method(name = "msg_reply")]
        // async fn msg_reply(&self, msg: MsgRequestId) -> RpcResult<()>;
    }

    pub struct RpcServerImpl {
        notifier: watch::Sender<()>,
        cache: Arc<Mutex<DataCache>>,
        pub iface: Option<Arc<Interface>>,
    }
    impl RpcServerImpl {
        pub fn new(
            notifier: watch::Sender<()>,
            cache: Arc<Mutex<DataCache>>,
            iface: Option<Arc<Interface>>,
        ) -> Self {
            RpcServerImpl {
                notifier,
                cache,
                iface,
            }
        }
        /// Add data to relevant field on the ServerImpl and send notification
        async fn add_data(&self, data: Data) {
            self.cache.lock().await.data.push(data);
            self.notifier.send(()).unwrap();
        }
    }

    #[async_trait]
    impl MyRpcServer for RpcServerImpl {
        async fn ping(&self) -> RpcResult<String> {
            Ok(format!("pong"))
        }
        async fn dm(&self, dm: DirectMessage) -> RpcResult<()> {
            let data = Data::DirectMessage(dm.sender, dm.msg.to_string());
            self.add_data(data).await;
            Ok(())
        }
        async fn msg(&self, msg: MsgRequestId) -> RpcResult<()> {
            let data = Data::MsgRequestId(msg);
            self.add_data(data).await;
            // self.iface.unwrap().reply_msg(rcvr, msg);
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
    pub struct MsgRequestId {
        sender: UserId,
        req_id: RequestId,
        data: String,
    }
    impl MsgRequestId {
        pub fn new(sender: UserId, req_id: RequestId, data: String) -> Self {
            Self {
                sender,
                req_id,
                data,
            }
        }
    }
}

use api::{MyRpcClient, MyRpcServer, RpcServerImpl};

use crate::api::{DirectMessage, MsgRequestId};

#[derive(PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Debug, Clone)]
struct RequestId(u64);
impl RequestId {
    pub fn new() -> Self {
        Self(rand::Rng::random(&mut rand::rng()))
    }
}

pub struct Interface {
    /// My IpAddr
    _addr: SocketAddr,
    /// TODO: My PubKey
    pubkey: UserId,
    /// Watch channel thats updates when new items are received over the network
    new_data_notifee: watch::Receiver<()>,
    /// Data from the network
    cache: Arc<Mutex<DataCache>>,
    /// Maps a UserId to their addr
    addr_book: HashMap<UserId, SocketAddr>,
    /// Stores clients so I don't have to recreate them for each outgoing connection
    clients: HashMap<SocketAddr, Arc<HttpClient>>,
    /// Active RPC requests that are waiting for a reply value
    pending_dm_replies: HashMap<RequestId, oneshot::Sender<MsgRequestId>>,
}
impl Interface {
    fn new(
        _addr: SocketAddr,
        new_data_notifee: watch::Receiver<()>,
        cache: Arc<Mutex<DataCache>>,
    ) -> Self {
        Self {
            _addr,
            addr_book: HashMap::new(),
            pubkey: UserId::new(),
            new_data_notifee,
            cache,
            clients: HashMap::new(),
            pending_dm_replies: HashMap::new(),
        }
    }
    pub async fn start() -> Arc<Self> {
        let (sndr, rcvr) = watch::channel(());
        let cache: Arc<Mutex<DataCache>> = Arc::new(Mutex::new(DataCache { data: Vec::new() }));
        let mut server_impl = RpcServerImpl::new(sndr, cache.clone(), None);
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
        let iface = Arc::new(Interface::new(addr, rcvr, cache));
        server_impl.iface = Some(iface.clone());
        // `into_rpc()` method was generated inside of the `RpcServer` trait under the hood.
        let server_handle = server.start(server_impl.into_rpc());

        tokio::spawn(server_handle.stopped());

        iface
    }
    pub async fn send_dm(&mut self, rcvr: &UserId, msg: &str) {
        let client = self.connect(rcvr).await;
        let dm = DirectMessage::new(self.pubkey, msg);
        client.dm(dm).await.unwrap();
    }

    /// Test to have a communication exchange
    pub async fn send_msg_wait_reply(&mut self, rcvr: &UserId, msg: &str) {
        let client = self.connect(rcvr).await;

        // Create oneshot channel to receive the reply
        let (tx, rx) = oneshot::channel::<MsgRequestId>();
        let req_id = RequestId::new();
        self.pending_dm_replies.insert(req_id.clone(), tx);

        // send dm
        println!("sending msg");
        let data = MsgRequestId::new(self.pubkey, req_id, "expecting a reply".to_string());
        client.msg(data).await.unwrap();

        // wait for reply
        let reply = rx.await.unwrap();
        println!("i got this reply {:?}", reply);
    }

    pub async fn connect(&mut self, rcvr: &UserId) -> Arc<HttpClient> {
        let addr = self.addr_book.get(rcvr).unwrap();
        let client = self.clients.entry(*addr).or_insert_with(|| {
            let server_url = format!("http://{}", addr);
            Arc::new(HttpClientBuilder::default().build(&server_url).unwrap())
        });
        client.clone()
    }
    pub async fn add_addr_book(&mut self, id: UserId, addr: SocketAddr) {
        self.addr_book.insert(id, addr);
    }
}

#[cfg(test)]
mod tests {
    use jsonrpsee::RpcModule;

    use crate::api::DirectMessage;

    use super::*;

    #[tokio::test]
    async fn interface_test() {
        let mut iface = Interface::start().await;
        let addr = iface._addr;
        let mut notifee = iface.new_data_notifee.clone();
        let cache = iface.cache.clone();
        let id = iface.pubkey;

        let mut iface2 = Interface::start().await;
        let addr2 = iface2._addr;
        let id2 = iface2.pubkey;

        // create address book with both of their entries in it
        // iface.add_addr_book(id2, addr2).await;
        // iface2.add_addr_book(id, addr).await;

        // spawn task to print iface1 incoming data
        tokio::task::spawn(async move {
            notifee.changed().await.unwrap();
            let x = cache.lock().await.data.pop().unwrap();
            println!("{x:?}");
        });
        // spawn task to send a message and wait for a reply
        tokio::task::spawn(async move {
            // iface2.send_dm_wait_reply(&id, "u r dumb").await;
        });

        // iface.send_dm(&id2, "no u").await;

        tokio::time::sleep(Duration::from_secs(3)).await;
    }

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
