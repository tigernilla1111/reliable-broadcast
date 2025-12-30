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

const MAX_MSGS_PER_LINK_ID: usize = 1_000;
const MAX_CONCURRENT_CONNECTIONS: usize = 1_000;
const CHANNEL_SEND_TIMEOUT_SECS: u64 = 1;
const RPC_REQUEST_TIMEOUT_SECS: u64 = 5;

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

            if let Err(e) = self.registry.deliver(msg).await {
                tracing::warn!(
                    msg_id = ?msg_id,
                    error = %e,
                    "failed to deliver message to channel"
                );
            }
            Ok(())
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("no active channel for msg_link_id {0:?}")]
    NoActiveChannel(MsgLinkId),

    #[error("channel send failed: {0}")]
    ChannelSendError(String),

    #[error("recipient address not found for {0:?}")]
    RecipientNotFound(PublicKeyBytes),

    #[error("RPC call failed: {0}")]
    RpcError(String),

    #[error("server builder failed: {0}")]
    ServerBuildError(String),
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
            let (tx, rx) = mpsc::channel(MAX_MSGS_PER_LINK_ID);
            (tx, Some(rx))
        });
        rx.take()
    }

    pub async fn deliver(&self, msg: MsgLink<T>) -> Result<(), NetworkError> {
        let msg_id = *msg.get_msg_id();

        let tx = self
            .msg_channel_map
            .lock()
            .await
            .get(&msg_id)
            .map(|(tx, _)| tx.clone())
            .ok_or(NetworkError::NoActiveChannel(msg_id))?;

        tx.send_timeout(msg, Duration::from_secs(CHANNEL_SEND_TIMEOUT_SECS))
            .await
            .map_err(|e| NetworkError::ChannelSendError(e.to_string()))
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
                tower::ServiceBuilder::new()
                    .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_CONNECTIONS)),
            )
            .build(addr)
            .await
            .expect("failed to build server");

        let addr = server.local_addr().expect("failed to get local addr");
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
        let Some(rcvr_addr) = addr_book.get(rcvr) else {
            tracing::warn!(
                recipient = ?rcvr,
                msg_link_id = ?msg_link_id,
                "recipient address not found in address book, skipping send"
            );
            return;
        };

        let client = self.connect(rcvr_addr).await;
        let msg_link = MsgLink::new(sender, msg_link_id, msg_data.to_owned());

        match tokio::time::timeout(
            Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS),
            client.msg(msg_link),
        )
        .await
        {
            Ok(Ok(_)) => {
                tracing::trace!(
                    recipient = ?rcvr,
                    msg_link_id = ?msg_link_id,
                    "message sent successfully"
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    recipient = ?rcvr,
                    msg_link_id = ?msg_link_id,
                    error = %e,
                    "RPC call failed"
                );
            }
            Err(_) => {
                tracing::warn!(
                    recipient = ?rcvr,
                    msg_link_id = ?msg_link_id,
                    "RPC call timed out after {} seconds",
                    RPC_REQUEST_TIMEOUT_SECS
                );
            }
        }
    }

    pub async fn connect(&self, addr: &SocketAddr) -> Arc<HttpClient> {
        let mut clients = self.clients.lock().await;
        let client = clients.entry(*addr).or_insert_with(|| {
            let server_url = format!("http://{}", addr);
            Arc::new(
                HttpClientBuilder::default()
                    .build(&server_url)
                    .expect("failed to build HTTP client"),
            )
        });
        client.clone()
    }

    pub async fn add_addr(&self, pubkey: PublicKeyBytes, addr: SocketAddr) {
        self.addr_book.lock().await.insert(pubkey, addr);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
    struct TestData {
        value: String,
    }

    #[tokio::test]
    async fn test_registry_subscribe_and_deliver() {
        // Test that messages can be delivered to subscribers
        let registry = Registry::<TestData>::new();
        let msg_link_id = MsgLinkId::new(1);
        let sender = PublicKeyBytes([1u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);

        // Subscribe to messages for this link ID
        let mut receiver = registry
            .subscribe(msg_link_id)
            .await
            .expect("should get receiver");

        // Deliver a message
        let test_data = TestData {
            value: "test".to_string(),
        };
        let test_msg = MsgLink::new(sender, msg_link_id, test_data.clone());

        registry
            .deliver(test_msg)
            .await
            .expect("deliver should succeed");

        // Receive the message
        let received = receiver.recv().await.expect("should receive message");
        assert_eq!(received.data, test_data);
        assert_eq!(received.sender, sender);
    }

    #[tokio::test]
    async fn test_registry_subscribe_only_once() {
        // Test that subscribe can only be called once per msg_link_id
        let registry = Registry::<TestData>::new();
        let msg_link_id = MsgLinkId::new(2);

        // First subscribe should work
        let first_rx = registry.subscribe(msg_link_id).await;
        assert!(first_rx.is_some());

        // Second subscribe should return None (receiver already taken)
        let second_rx = registry.subscribe(msg_link_id).await;
        assert!(second_rx.is_none());
    }

    #[tokio::test]
    async fn test_interface_send_and_receive_roundtrip() {
        // Test complete message send/receive between two interfaces
        let interface1 = Interface::<TestData>::new("127.0.0.1:0").await;
        let interface2 = Interface::<TestData>::new("127.0.0.1:0").await;

        let key1 = PublicKeyBytes([1u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);
        let key2 = PublicKeyBytes([2u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);

        // Add addresses to each other's address books
        interface1.add_addr(key2, interface2.addr).await;
        interface2.add_addr(key1, interface1.addr).await;

        let msg_link_id = MsgLinkId::new(100);

        // Interface2 subscribes to messages
        let mut receiver = interface2
            .registry
            .subscribe(msg_link_id)
            .await
            .expect("should get receiver");

        // Interface1 sends a message to interface2
        let test_data = TestData {
            value: "hello".to_string(),
        };
        interface1
            .send_msg(&key2, &test_data, msg_link_id, key1)
            .await;

        // Wait a bit for async message delivery
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Interface2 should receive the message
        let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("should not timeout")
            .expect("should receive message");

        assert_eq!(received.data.value, "hello");
        assert_eq!(received.sender, key1);
    }
}
