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

// TODO: organize the data into purpose.  ie dm messages will go into DataCache::dms and ledger data will go into DataCache::ledger
// I can get rid of enum Data at this point and just store a vector of structs with info for each data type
struct DataCache {
    dm_data: Vec<DirectMessage>,
    msg_link_data: Vec<MsgLink>,
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
        dm_data_notifier: watch::Sender<()>,
        msg_link_notifier: watch::Sender<()>,
        cache: Arc<Mutex<DataCache>>,
        iface: Arc<Interface>,
    }
    impl RpcServerImpl {
        pub fn new(
            dm_data_notifier: watch::Sender<()>,
            msg_link_notifier: watch::Sender<()>,
            cache: Arc<Mutex<DataCache>>,
            iface: Arc<Interface>,
        ) -> Self {
            RpcServerImpl {
                dm_data_notifier,
                msg_link_notifier,
                cache,
                iface,
            }
        }
        async fn add_dm_data(&self, dm_data: DirectMessage) {
            self.cache.lock().await.dm_data.push(dm_data);
            self.dm_data_notifier.send(()).unwrap();
        }
        async fn add_msg_link_data(&self, data: MsgLink) {
            self.cache.lock().await.msg_link_data.push(data);
            self.dm_data_notifier.send(()).unwrap();
        }
    }

    #[async_trait]
    impl MyRpcServer for RpcServerImpl {
        async fn ping(&self) -> RpcResult<String> {
            Ok(format!("pong"))
        }
        async fn dm(&self, dm: DirectMessage) -> RpcResult<()> {
            let data = DirectMessage::new(dm.sender, dm.msg.as_str());
            self.add_dm_data(data).await;
            Ok(())
        }

        async fn msg(&self, msg: MsgLink) -> RpcResult<()> {
            self.add_msg_link_data(msg).await;
            // notify?
            // do i need to send out an init

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

use crate::api::{DirectMessage, MsgLink};

#[derive(PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Debug, Clone)]
struct MsgLinkId(u64);
impl MsgLinkId {
    pub fn new() -> Self {
        Self(rand::Rng::random(&mut rand::rng()))
    }
}

struct Notifiees {
    dm_notifee: watch::Receiver<()>,
    msg_link_notifee: watch::Receiver<()>,
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
    /// Active RPC requests that are waiting for a reply value
    pending_dm_replies: HashMap<MsgLinkId, oneshot::Sender<MsgLink>>,
    /// Watch channels receivers subscribed to new network data
    notifees: Notifiees,
    cache: Arc<Mutex<DataCache>>,
}
impl Interface {
    pub async fn new() -> Arc<Self> {
        let cache: Arc<Mutex<DataCache>> = Arc::new(Mutex::new(DataCache {
            dm_data: Vec::new(),
            msg_link_data: Vec::new(),
        }));
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
        let (sndr, dm_notifee) = watch::channel(());
        let (sndr_msg_link, msg_link_notifee) = watch::channel(());
        let notifees = Notifiees {
            dm_notifee,
            msg_link_notifee,
        };
        let iface = Arc::new(Interface {
            _addr: addr,
            addr_book: Arc::new(Mutex::new(HashMap::new())),
            pubkey: UserId::new(),
            clients: Arc::new(Mutex::new(HashMap::new())),
            pending_dm_replies: HashMap::new(),
            notifees,
            cache: cache.clone(),
        });
        let server_impl = RpcServerImpl::new(sndr, sndr_msg_link, cache, iface.clone());
        // `into_rpc()` method was generated inside of the `RpcServer` trait under the hood.
        let server_handle = server.start(server_impl.into_rpc());

        tokio::spawn(server_handle.stopped());

        iface
    }
    pub async fn send_dm(&self, rcvr: &UserId, msg: &str) {
        let client = self.connect(rcvr).await;
        let dm = DirectMessage::new(self.pubkey, msg);
        client.dm(dm).await.unwrap();
    }

    /// Test to have a communication exchange
    pub async fn send_msg_wait_reply(&mut self, rcvr: &UserId, msg: &str) {
        let client = self.connect(rcvr).await;

        // Create oneshot channel to receive the reply
        let (tx, rx) = oneshot::channel::<MsgLink>();
        let req_id = MsgLinkId::new();
        self.pending_dm_replies.insert(req_id.clone(), tx);

        // send dm
        println!("sending msg");
        let data = MsgLink::new(self.pubkey, req_id, msg.to_string());
        // client.msg(data).await.unwrap();

        // wait for reply
        let reply = rx.await.unwrap();
        println!("i got this reply {:?}", reply);
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
    use jsonrpsee::RpcModule;

    use crate::api::DirectMessage;

    use super::*;

    #[tokio::test]
    async fn interface_test() {
        let iface = Interface::new().await;
        let addr = iface._addr;
        let id = iface.pubkey;

        let mut dm_notifee = iface.notifees.dm_notifee.clone();
        tokio::task::spawn(async move {
            loop {
                dm_notifee.changed().await.unwrap();
                println!("receved {:?}", iface.cache.lock().await.dm_data.pop());
            }
        });

        let iface2 = Interface::new().await;
        iface2.add_addr_book(id, addr).await;
        loop {
            iface2.send_dm(&id, "u suck").await;
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
