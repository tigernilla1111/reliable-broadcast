use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::proc_macros::rpc;
use std::collections::HashMap;
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tokio;
use tokio::net::ToSocketAddrs;

use crate::crypto::PublicKeyBytes;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::server::ServerBuilder;
use tokio::sync::{Mutex, mpsc, mpsc::Receiver, mpsc::Sender};
use tower::limit::ConcurrencyLimitLayer;

// How many DM messages from the network can be stored in the channel
const MAX_MSGS_PER_LINK_ID: usize = 10000;

mod api {
    use super::*;

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

/// Allows to have an arbitrary amount of Types of messages.
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

    // Return and empty the stored rx channel. Note: this can only be done once
    pub async fn subscribe(&self, msg_id: MsgLinkId) -> Option<Receiver<MsgLink<T>>> {
        let mut inner = self.msg_channel_map.lock().await;
        let (_, rx) = inner.entry(msg_id).or_insert_with(|| {
            let (tx, rx) = mpsc::channel(16);
            (tx, Some(rx))
        });
        rx.take()
    }

    pub async fn deliver(&self, msg: MsgLink<T>) -> Result<(), String> {
        let Some(tx) = self
            .msg_channel_map
            .lock()
            .await
            .get(msg.get_msg_id())
            .map(|(tx, _)| tx.clone())
        else {
            return Err(format!("no active channel for {:?}", msg.get_msg_id()));
        };
        return tx
            .send_timeout(msg, Duration::from_secs(1))
            .await
            .map_err(|e| e.to_string());
    }
}

use api::{MsgLinkServer, MyRpcClient, MyRpcServer};

pub trait Data:
    Send + Sync + serde::Serialize + serde::de::DeserializeOwned + Clone + std::fmt::Debug + 'static
{
}

impl<T> Data for T where
    T: Send
        + Sync
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + std::fmt::Debug
        + 'static
{
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct MsgLink<T> {
    pub sender: PublicKeyBytes,
    msg_id: MsgLinkId,
    pub data: T,
}

impl<T> MsgLink<T> {
    pub fn new(sender: PublicKeyBytes, msg_id: MsgLinkId, data: T) -> Self {
        Self {
            sender,
            msg_id,
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

    pub fn to_be_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl std::ops::Deref for MsgLinkId {
    type Target = u128;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn create_msg_link_rpc_module<T: Data>(registry: Registry<T>) -> jsonrpsee::RpcModule<()> {
    let server_impl = MsgLinkServer::new(registry);
    server_impl.into_rpc().remove_context()
}

#[derive(Clone)]
pub struct Interface<T> {
    /// My IpAddr
    pub addr: SocketAddr,
    addr_book: Arc<Mutex<HashMap<PublicKeyBytes, SocketAddr>>>,
    /// Stores clients so I don't have to recreate them for each outgoing connection
    clients: Arc<Mutex<HashMap<SocketAddr, Arc<HttpClient>>>>,
    pub registry: Registry<T>,
}

impl<T: Data> Interface<T> {
    pub async fn new(addr: impl ToSocketAddrs) -> Arc<Self> {
        let server = ServerBuilder::default()
            .set_http_middleware(
                tower::ServiceBuilder::new().layer(ConcurrencyLimitLayer::new(1000)),
            )
            .build(addr)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let registry = Registry::new();

        let iface = Arc::new(Interface {
            addr,
            clients: Arc::new(Mutex::new(HashMap::new())),
            registry: registry.clone(),
            addr_book: Arc::new(Mutex::new(HashMap::new())),
        });

        let server_handle = server.start(create_msg_link_rpc_module(registry));
        tokio::spawn(server_handle.stopped());

        iface
    }

    /// Registers the msg_link_id in the registry before sending
    pub async fn send_msg(
        &self,
        rcvr: &PublicKeyBytes,
        msg_data: &T,
        msg_link_id: MsgLinkId,
        sender: PublicKeyBytes,
    ) {
        let addr_book = self.addr_book.lock().await;
        let rcvr_addr = addr_book.get(rcvr).unwrap();
        let client = self.connect(rcvr_addr).await;
        let msg_link = MsgLink::new(sender, msg_link_id, msg_data.to_owned());
        client.msg(msg_link).await.unwrap();
    }

    pub async fn connect(&self, addr: &SocketAddr) -> Arc<HttpClient> {
        let mut clients = self.clients.lock().await;
        let client = clients.entry(*addr).or_insert_with(|| {
            let server_url = format!("http://{}", addr);
            Arc::new(HttpClientBuilder::default().build(&server_url).unwrap())
        });
        client.clone()
    }

    pub async fn add_addr(&self, pubkey: PublicKeyBytes, addr: SocketAddr) {
        self.addr_book.lock().await.insert(pubkey, addr);
    }
}
