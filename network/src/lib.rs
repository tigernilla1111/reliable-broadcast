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
use tokio::sync::{Mutex, mpsc, watch};
use tokio::time::sleep;
// use tower::limit::ConcurrencyLimitLayer;
use types::UserId;

#[derive(Debug)]
enum Data {
    Init,
    // Tuple of UserId, msg
    DirectMessage(UserId, String),
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
    }

    pub struct RpcServerImpl {
        notifier: watch::Sender<()>,
        cache: Arc<Mutex<DataCache>>,
    }
    impl RpcServerImpl {
        pub fn new(notifier: watch::Sender<()>, cache: Arc<Mutex<DataCache>>) -> Self {
            RpcServerImpl { notifier, cache }
        }
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
    }

    #[derive(serde::Serialize, serde::Deserialize)]
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
}

use api::{MyRpcClient, MyRpcServer, RpcServerImpl};

use crate::api::DirectMessage;
async fn server() -> (SocketAddr, watch::Receiver<()>, Arc<Mutex<DataCache>>) {
    let (sndr, rcvr) = watch::channel(());
    let cache = Arc::new(Mutex::new(DataCache { data: Vec::new() }));
    let server_impl = RpcServerImpl::new(sndr, cache.clone());
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
    // `into_rpc()` method was generated inside of the `RpcServer` trait under the hood.
    let server_handle = server.start(server_impl.into_rpc());

    tokio::spawn(server_handle.stopped());

    (addr, rcvr, cache)
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
}

impl Interface {
    pub async fn start() -> Self {
        let (addr, new_data_notifee, cache) = server().await;
        Self {
            _addr: addr,
            new_data_notifee: new_data_notifee,
            cache,
            addr_book: HashMap::new(),
            pubkey: UserId::new(),
            clients: HashMap::new(),
        }
    }
    pub async fn dm(&mut self, rcvr: &UserId, msg: &str) {
        let client = self.connect(rcvr).await;
        let dm = DirectMessage::new(self.pubkey, msg);
        client.dm(dm).await.unwrap();
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
        let iface = Interface::start().await;
        let server_addr = iface._addr;
        let notifee = iface.new_data_notifee;
        let cache = iface.cache;

        let iface2 = Interface::start().await;
        // create address book with both of their entries in it
    }

    #[tokio::test]
    async fn it_works() {
        let (server_addr, mut new_data_rcvr, cache) = server().await;
        let server_url = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&server_url).unwrap();

        println!("{}", client.ping().await.unwrap());
        client
            .dm(DirectMessage::new(UserId::new(), "yo dodo a"))
            .await
            .unwrap();
        tokio::task::spawn(async move {
            let mut count = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                client
                    .dm(DirectMessage::new(
                        UserId::new(),
                        format!("my guy {count}").as_str(),
                    ))
                    .await
                    .unwrap();
                count += 1;
            }
        });
        loop {
            new_data_rcvr.changed().await.unwrap();
            let item = cache.lock().await.data.pop().unwrap();
            println!("{item:?}");
        }
    }
}
