use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::proc_macros::rpc;
use std::collections::HashMap;
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tokio;
use tokio::net::ToSocketAddrs;

use crate::crypto::{PrivateKey, PublicKey, PublicKeyBytes, Signature};
// use jsonrpsee::core::middleware::RequestBodyLimitLayer;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::server::ServerBuilder;
// use jsonrpsee::server::middleware::http::RequestBodyLimitLayer;
use tokio::sync::{Mutex, mpsc, mpsc::Receiver, mpsc::Sender};
use tower::limit::ConcurrencyLimitLayer;

// How many DM messages from the network can be stored in the channel
const MAX_MSGS_PER_LINK_ID: usize = 10000;

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
    // Return and empty the stored rx channel.  Note: this can only be done once
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
    // pub async fn remove(&self, msg_id: MsgLinkId) {
    //     self.msg_channel_map.lock().await.remove(&msg_id);
    // }
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
    sender: PublicKeyBytes,
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
}
impl std::ops::Deref for MsgLinkId {
    type Target = u128;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn create_msg_link_rpc_module<T: Data>(registry: Registry<T>) -> jsonrpsee::RpcModule<()> {
    let server_impl = MsgLinkServer::new(registry);
    // `into_rpc()` method was generated inside of the `RpcServer` trait under the hood.
    server_impl.into_rpc().remove_context()
}
#[derive(Clone)]
pub struct Interface<T> {
    /// My IpAddr
    pub addr: SocketAddr,
    private_key: Arc<PrivateKey>,
    public_key: PublicKeyBytes,
    addr_book: Arc<Mutex<HashMap<PublicKeyBytes, SocketAddr>>>,
    /// Stores clients so I don't have to recreate them for each outgoing connection
    clients: Arc<Mutex<HashMap<SocketAddr, Arc<HttpClient>>>>,
    pub registry: Registry<T>,
}
impl<T: Data> Interface<T> {
    pub async fn new(addr: impl ToSocketAddrs) -> Arc<Self> {
        let server = ServerBuilder::default()
            .set_http_middleware(
                tower::ServiceBuilder::new().layer(ConcurrencyLimitLayer::new(1000)), // .layer(RequestBodyLimitLayer::new(1024 * 1024)), // 1 MB
            )
            .build(addr)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let registry = Registry::new();
        let private_key = PrivateKey::new();
        let public_key = private_key.to_public_key().to_bytes();
        let iface = Arc::new(Interface {
            addr,
            clients: Arc::new(Mutex::new(HashMap::new())),
            registry: registry.clone(),
            addr_book: Arc::new(Mutex::new(HashMap::new())),
            private_key: private_key.into(),
            public_key,
        });

        let server_handle = server.start(create_msg_link_rpc_module(registry));

        tokio::spawn(server_handle.stopped());

        iface
    }

    /// Registers the msg_link_id in the registry before sending
    pub async fn send_msg(&self, rcvr: &PublicKeyBytes, msg_data: &T, msg_link_id: MsgLinkId) {
        let addr_book = self.addr_book.lock().await;
        let rcvr = addr_book.get(rcvr).unwrap();
        // println!("{}, sending msg to {:?}, {:?}", self.addr, rcvr, msg_data);
        let client = self.connect(rcvr).await;
        let msg_link = MsgLink::new(*self.public_key(), msg_link_id, msg_data.to_owned());
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
    pub async fn add_addr(&self, pubkey: PublicKey, addr: SocketAddr) {
        self.addr_book.lock().await.insert(pubkey.to_bytes(), addr);
    }
    pub fn public_key(&self) -> &PublicKeyBytes {
        &self.public_key
    }
    pub fn get_sig_and_hash<S: serde::Serialize>(
        &self,
        data: &S,
        intiator: PublicKeyBytes,
        participants: &Vec<PublicKeyBytes>,
        msg_link_id: MsgLinkId,
    ) -> (Signature, crate::crypto::Sha512HashBytes) {
        self.private_key
            .get_sig_and_hash(data, intiator, participants, msg_link_id)
    }
}

// #[cfg(test)]
// mod tests {

//     use super::*;
//     use std::time::Duration;

//     #[tokio::test]
//     async fn interface_test() {
//         let iface1 = Interface::new("127.0.0.1:0").await;
//         let msg_id = MsgLinkId::new(68);

//         let mut rx = iface1.registry.subscribe(msg_id.clone()).await.unwrap();

//         tokio::task::spawn(async move {
//             loop {
//                 let value: MsgLink<String> = rx.recv().await.unwrap();
//                 println!("receved {:?}", value);
//             }
//         });

//         let iface2: Arc<Interface<String>> = Interface::new("127.0.0.1:0").await;

//         // Create a PublicKey for the address book
//         let pubkey1 = PrivateKey::new().to_public_key();

//         // Add pubkey1 -> iface1.addr mapping to iface2's addr_book
//         iface2.add_addr(pubkey1.clone(), iface1.addr).await;

//         let msg_data = "test_data_1".to_string();
//         iface2.send_msg(&pubkey1, &msg_data, msg_id.clone()).await;
//     }

//     #[tokio::test]
//     async fn registry_subscribe_only_once() {
//         let registry: Registry<String> = Registry::new();
//         let msg_id = MsgLinkId::new(98);

//         // First subscribe should succeed
//         let rx1 = registry.subscribe(msg_id).await;
//         assert!(rx1.is_some(), "first subscribe should return a receiver");

//         // Second subscribe should return None
//         let rx2 = registry.subscribe(msg_id).await;
//         assert!(rx2.is_none(), "second subscribe should return None");
//     }

//     #[tokio::test]
//     async fn registry_send_before_subscribe() {
//         let registry = Registry::new();
//         let msg_id = MsgLinkId::new(789);
//         let sender = PrivateKey::new().to_public_key().to_bytes();

//         let msg = MsgLink::new(sender, msg_id, "test_message".to_string());

//         // Register the msg_id but DO NOT subscribe yet
//         registry.register(msg_id).await;

//         // Deliver message before subscription
//         assert!(registry.deliver(msg).await.is_ok());

//         // Now subscribe
//         let mut rx = registry
//             .subscribe(msg_id)
//             .await
//             .expect("receiver should exist");

//         // The message should already be buffered
//         let received = rx.recv().await.expect("should receive buffered msg");

//         assert_eq!(*received.get_msg_id(), msg_id);
//     }

//     #[tokio::test]
//     async fn interface_send_before_receiver_subscribes() {
//         let iface1: Arc<Interface<String>> = Interface::new("127.0.0.1:0").await;
//         let iface2 = Interface::new("127.0.0.1:0").await;

//         // Create a PublicKey for the address book
//         let pubkey2 = PrivateKey::new().to_public_key();

//         // Add pubkey2 -> iface2.addr mapping to iface1's addr_book
//         iface1.add_addr(pubkey2.clone(), iface2.addr).await;

//         let msg_id = MsgLinkId::new(987);
//         let msg_data = "buffered_test_data".to_string();

//         // Send BEFORE iface2 subscribes or registers
//         iface1.send_msg(&pubkey2, &msg_data, msg_id).await;

//         // Now iface2 subscribes AFTER the message arrived
//         let mut rx = iface2
//             .registry
//             .subscribe(msg_id)
//             .await
//             .expect("receiver should exist");

//         // The message should already be buffered
//         let received: MsgLink<String> =
//             tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
//                 .await
//                 .expect("timed out waiting for buffered msg")
//                 .expect("channel closed unexpectedly");

//         assert_eq!(*received.get_msg_id(), msg_id);
//     }

//     #[tokio::test]
//     async fn registry_multiple_msglinkids_interleaved_no_signature_usage() {
//         let registry = Registry::new();
//         let sender = PrivateKey::new().to_public_key().to_bytes();

//         let msg_id_a = MsgLinkId::new(222);
//         let msg_id_b = MsgLinkId::new(333);

//         registry.register(msg_id_a).await;
//         registry.register(msg_id_b).await;

//         // Interleave deliveries (payload contents don't matter)
//         registry
//             .deliver(MsgLink::new(sender, msg_id_a, "test_a_1".to_string()))
//             .await
//             .unwrap();

//         registry
//             .deliver(MsgLink::new(sender, msg_id_b, "test_b_1".to_string()))
//             .await
//             .unwrap();

//         registry
//             .deliver(MsgLink::new(sender, msg_id_a, "test_a_2".to_string()))
//             .await
//             .unwrap();

//         // Subscribe after all messages arrived
//         let mut rx_a = registry
//             .subscribe(msg_id_a)
//             .await
//             .expect("receiver A should exist");

//         let mut rx_b = registry
//             .subscribe(msg_id_b)
//             .await
//             .expect("receiver B should exist");

//         // Count messages per MsgLinkId
//         let mut count_a = 0;
//         let mut count_b = 0;

//         while let Ok(Some(_)) =
//             tokio::time::timeout(std::time::Duration::from_millis(50), rx_a.recv()).await
//         {
//             count_a += 1;
//         }

//         while let Ok(Some(_)) =
//             tokio::time::timeout(std::time::Duration::from_millis(50), rx_b.recv()).await
//         {
//             count_b += 1;
//         }

//         assert_eq!(count_a, 2, "MsgLinkId A should receive exactly 2 messages");
//         assert_eq!(count_b, 1, "MsgLinkId B should receive exactly 1 messages");
//     }

//     #[tokio::test]
//     async fn interface_multiple_clients_same_msgid() {
//         let iface1: Arc<Interface<String>> = Interface::new("127.0.0.1:0").await;
//         let iface2: Arc<Interface<String>> = Interface::new("127.0.0.1:0").await;
//         let iface3: Arc<Interface<String>> = Interface::new("127.0.0.1:0").await;

//         let pubkey1_bytes = *iface1.public_key();
//         let pubkey2_bytes = *iface2.public_key();
//         let pubkey3_bytes = *iface3.public_key();

//         // Create a PublicKey for the address book
//         let pubkey1 = PrivateKey::new().to_public_key();

//         // Add pubkey1 -> iface1.addr mapping to iface2 and iface3's addr_books
//         iface2.add_addr(pubkey1.clone(), iface1.addr).await;
//         iface3.add_addr(pubkey1.clone(), iface1.addr).await;

//         let msg_id = MsgLinkId::new(555);
//         let mut rx = iface1.registry.subscribe(msg_id).await.unwrap();

//         // Two different clients send to the same msg_id
//         iface2
//             .send_msg(&pubkey1, &"test_from_client2".to_string(), msg_id)
//             .await;

//         iface3
//             .send_msg(&pubkey1, &"test_from_client3".to_string(), msg_id)
//             .await;

//         // Should receive both messages
//         let msg1 = tokio::time::timeout(Duration::from_secs(1), rx.recv())
//             .await
//             .expect("timeout")
//             .expect("channel closed");

//         let msg2 = tokio::time::timeout(Duration::from_secs(1), rx.recv())
//             .await
//             .expect("timeout")
//             .expect("channel closed");

//         // Verify both messages arrived (order may vary)
//         let senders: Vec<_> = vec![msg1.sender, msg2.sender];
//         assert!(senders.contains(&pubkey2_bytes));
//         assert!(senders.contains(&pubkey3_bytes));
//     }

//     #[tokio::test]
//     async fn registry_channel_overflow_behavior() {
//         let registry = Registry::new();
//         let msg_id = MsgLinkId::new(444);
//         let sender = PrivateKey::new().to_public_key().to_bytes();

//         registry.register(msg_id).await;

//         // Fill the channel beyond MAX_MSGS_PER_LINK_ID
//         for _ in 0..(MAX_MSGS_PER_LINK_ID + 5) {
//             let _ = registry
//                 .deliver(MsgLink::new(sender, msg_id, "test_data".to_string()))
//                 .await;
//         }

//         let mut rx = registry
//             .subscribe(msg_id)
//             .await
//             .expect("receiver should exist");

//         // Count how many messages were actually buffered
//         let mut count = 0;
//         while let Ok(Some(_)) =
//             tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await
//         {
//             count += 1;
//         }

//         // Should have received MAX_MSGS_PER_LINK_ID messages
//         assert_eq!(count, MAX_MSGS_PER_LINK_ID);
//     }
// }
