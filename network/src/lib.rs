use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::{MethodCallback, MethodResponse, Methods, RpcModule, server};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio;

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
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

pub struct DataCache {
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
        async fn dm(&self, msg: &str) -> RpcResult<()>;
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
        async fn dm(&self, msg: &str) -> RpcResult<()> {
            let data = Data::DirectMessage(0u64, msg.to_string());
            self.add_data(data).await;
            Ok(())
        }
    }
}

use api::{MyRpcClient, MyRpcServer, RpcServerImpl};
pub async fn server() -> (SocketAddr, watch::Receiver<()>, Arc<Mutex<DataCache>>) {
    let (sndr, rcvr) = watch::channel(());
    let cache = Arc::new(Mutex::new(DataCache { data: Vec::new() }));
    let server_impl = RpcServerImpl::new(sndr, cache.clone());
    let server = ServerBuilder::default()
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

#[cfg(test)]
mod tests {
    use jsonrpsee::RpcModule;

    use super::*;

    #[tokio::test]
    async fn it_works() {
        let (server_addr, mut new_data_rcvr, cache) = server().await;
        let server_url = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&server_url).unwrap();

        println!("{}", client.ping().await.unwrap());
        client.dm("yo dodo a").await.unwrap();
        client.dm("YOOOOO").await.unwrap();
        client.dm("ARE YOU EVEN LISTENING").await.unwrap();
        tokio::task::spawn(async move {
            let mut count = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                client.dm(format!("my guy {count}").as_str()).await.unwrap();
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
