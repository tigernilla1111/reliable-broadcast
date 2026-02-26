//! Byzantine Reliable Broadcast protocol implementation
//!
//! Provides a three-phase broadcast protocol (Init → Echo → Ready) that ensures
//! all honest nodes deliver the same value even in the presence of Byzantine faults.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::crypto::{
    HashBytes, PrivateKey, PublicKeyBytes, SignatureBytes, verify_echo, verify_init, verify_ready,
};
use crate::network::{Data, Interface, MsgLink, MsgLinkId, Registry};

#[derive(Debug, thiserror::Error)]
pub enum BroadcastError {
    #[error("delivery threshold not met")]
    DeliveryThresholdNotMet,

    #[error("init message not received")]
    InitMessageNotReceived,

    #[error("failed to subscribe to msg_link_id {0:?}")]
    SubscriptionFailed(MsgLinkId),

    #[error("broadcast timed out after {0} seconds")]
    Timeout(u64),

    #[error("failed to sign message {0}")]
    SigningFailed(String),
}

/// Messages exchanged during the three-phase broadcast protocol
#[derive(Clone, serde::Deserialize, serde::Serialize, Debug)]
pub enum BroadcastRound<T> {
    /// Phase 1: Initiator sends data with signature to all participants
    Init(T, Vec<PublicKeyBytes>, SignatureBytes),
    /// Phase 2: Participants echo the hash they received
    Echo(HashBytes, SignatureBytes),
    /// Phase 3: Participants commit to deliver once threshold is reached
    Ready(HashBytes, SignatureBytes),
}

/// State for a single broadcast instance
struct BcastInstance<T> {
    hash_echo_count: HashMap<HashBytes, usize>,
    hash_ready_count: HashMap<HashBytes, usize>,
    senders: HashMap<PublicKeyBytes, (bool, bool)>,
    is_ready_msg_sent: bool,
    echo_threshold_reached: bool,
    ready_amp_threshold_reached: bool,
    delivery_threshold_reached: bool,
    participants: Vec<PublicKeyBytes>,
    msg_queue: Vec<MsgLink<BroadcastRound<T>>>,
    payload: T,
    payload_hash: HashBytes,
}

impl<T> BcastInstance<T> {
    fn new(payload: T, payload_hash: HashBytes, participants: Vec<PublicKeyBytes>) -> Self {
        Self {
            hash_echo_count: HashMap::new(),
            hash_ready_count: HashMap::new(),
            senders: HashMap::new(),
            is_ready_msg_sent: false,
            echo_threshold_reached: false,
            ready_amp_threshold_reached: false,
            delivery_threshold_reached: false,
            participants,
            payload,
            payload_hash,
            msg_queue: Vec::new(),
        }
    }

    // Byzantine fault tolerance thresholds - assuming up to f = (n-1)/3 Byzantine nodes

    /// Echos needed before sending Ready: guarantees at least one honest node echoed
    fn echo_to_ready_threshold(&self) -> usize {
        let n = self.participants.len();
        (n + ((n - 1) / 3)).div_ceil(2)
    }

    /// Readys that trigger amplification: f+1 means at least one honest node is ready
    fn ready_amp_threshold(&self) -> usize {
        let n = self.participants.len();
        ((n - 1) / 3) + 1
    }

    /// Readys needed for delivery: 2f+1 guarantees all honest nodes will eventually deliver
    fn delivery_threshold(&self) -> usize {
        let n = self.participants.len();
        (((n - 1) / 3) * 2) + 1
    }

    fn has_sent_echo(&self, pubkey: PublicKeyBytes) -> bool {
        self.senders.get(&pubkey).unwrap_or(&(false, false)).0
    }

    fn has_sent_ready(&self, pubkey: PublicKeyBytes) -> bool {
        self.senders.get(&pubkey).unwrap_or(&(false, false)).1
    }

    fn sent_echo(&mut self, pubkey: PublicKeyBytes) {
        let (has_sent_echo, _) = self.senders.entry(pubkey).or_insert((false, false));
        *has_sent_echo = true;
    }

    fn sent_ready(&mut self, pubkey: PublicKeyBytes) {
        let (_, has_sent_ready) = self.senders.entry(pubkey).or_insert((false, false));
        *has_sent_ready = true;
    }

    async fn count_echo(&mut self, hash: HashBytes, sender: PublicKeyBytes) {
        let num_hashes = self.hash_echo_count.entry(hash).or_insert(0);
        *num_hashes += 1;
        let count = *num_hashes;
        self.sent_echo(sender);

        if count >= self.echo_to_ready_threshold() {
            self.echo_threshold_reached = true;
        }
    }

    async fn count_ready(&mut self, hash: HashBytes, sender: PublicKeyBytes) {
        let num_hashes = self.hash_ready_count.entry(hash).or_insert(0);
        *num_hashes += 1;
        let count = *num_hashes;
        self.sent_ready(sender);

        if count >= self.ready_amp_threshold() {
            self.ready_amp_threshold_reached = true;
        }

        if count >= self.delivery_threshold() {
            self.delivery_threshold_reached = true;
        }
    }
}

/// Protocol-aware wrapper around Interface that handles signing and identity
pub struct ProtocolNode<T> {
    interface: Arc<Interface<BroadcastRound<T>>>,
    private_key: PrivateKey,
    public_key: PublicKeyBytes,
}

impl<T: Data> ProtocolNode<T> {
    pub async fn new(addr: impl tokio::net::ToSocketAddrs, private_key: PrivateKey) -> Arc<Self> {
        let public_key = private_key.public_key();
        let interface = Interface::new(addr).await;

        Arc::new(Self {
            interface,
            private_key,
            public_key,
        })
    }

    pub fn public_key(&self) -> &PublicKeyBytes {
        &self.public_key
    }

    pub fn registry(&self) -> &Registry<BroadcastRound<T>> {
        &self.interface.registry
    }

    pub fn addr(&self) -> std::net::SocketAddr {
        self.interface.addr
    }

    pub async fn add_addr(
        &self,
        pubkey: crate::crypto::PublicKeyBytes,
        addr: std::net::SocketAddr,
    ) {
        self.interface.add_addr(pubkey, addr).await;
    }

    /// Start a reliable broadcast and participate in it
    pub async fn broadcast_init(
        &self,
        recipients: Vec<PublicKeyBytes>,
        data: T,
        msg_link_id: MsgLinkId,
        timeout_secs: u64,
    ) -> Result<T, BroadcastError> {
        let (sig, hash) = self
            .private_key
            .sign_init(&data, *self.public_key(), &recipients, msg_link_id)
            .map_err(|e| BroadcastError::SigningFailed(e.to_string()))?;
        let msg = BroadcastRound::Init(data.clone(), recipients.clone(), sig);

        // Send Init to all other participants
        for participant in recipients.iter() {
            if participant == self.public_key() {
                continue;
            }
            self.interface
                .send_msg(participant, &msg, msg_link_id, self.public_key)
                .await;
        }

        // As initiator, we skip waiting for Init and immediately send Echo
        let mut bcast_instance = BcastInstance::new(data, hash, recipients);
        self.send_echo(&mut bcast_instance, hash, msg_link_id).await;

        let mut rx = self
            .registry()
            .subscribe(msg_link_id)
            .await
            .ok_or(BroadcastError::SubscriptionFailed(msg_link_id))?;

        let res = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            self.participate_in_broadcast_inner(bcast_instance, &mut rx),
        )
        .await
        .map_err(|_| BroadcastError::Timeout(timeout_secs))?;

        drop(rx);

        res
    }

    /// Participate as a recipient of a reliable broadcast
    pub async fn participate_in_broadcast(
        &self,
        msg_link_id: MsgLinkId,
        timeout_secs: u64,
    ) -> Result<T, BroadcastError> {
        let mut rx = self
            .registry()
            .subscribe(msg_link_id)
            .await
            .ok_or(BroadcastError::SubscriptionFailed(msg_link_id))?;

        let result = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
            let bcast_instance = self
                .wait_for_init(msg_link_id, &mut rx)
                .await
                .ok_or(BroadcastError::InitMessageNotReceived)?;

            self.participate_in_broadcast_inner(bcast_instance, &mut rx)
                .await
        })
        .await
        .map_err(|_| BroadcastError::Timeout(timeout_secs))?;

        drop(rx);
        result
    }

    async fn participate_in_broadcast_inner(
        &self,
        bcast_instance: BcastInstance<T>,
        rx: &mut mpsc::Receiver<MsgLink<BroadcastRound<T>>>,
    ) -> Result<T, BroadcastError> {
        let mut bcast_instance = bcast_instance;

        // Process any messages that arrived before Init (they were buffered)
        while let Some(msg) = bcast_instance.msg_queue.pop() {
            self.handle_message(msg, &mut bcast_instance).await;
            if bcast_instance.delivery_threshold_reached {
                return Ok(bcast_instance.payload);
            }
        }

        // Process incoming messages until we reach delivery threshold
        while let Some(msg) = rx.recv().await {
            self.handle_message(msg, &mut bcast_instance).await;
            if bcast_instance.delivery_threshold_reached {
                return Ok(bcast_instance.payload);
            }
        }

        Err(BroadcastError::DeliveryThresholdNotMet)
    }

    async fn wait_for_init(
        &self,
        msg_link_id: MsgLinkId,
        rx: &mut mpsc::Receiver<MsgLink<BroadcastRound<T>>>,
    ) -> Option<BcastInstance<T>> {
        let mut instance_opt: Option<BcastInstance<T>> = None;
        let mut msg_queue = Vec::new();

        // Wait for Init message, buffer any Echo/Ready that arrive early
        while let Some(msg) = rx.recv().await {
            let sender = msg.sender;
            if let BroadcastRound::Init(data, participants, init_sig) = msg.data {
                match verify_init(&init_sig, &data, sender, &participants, msg_link_id) {
                    Ok(hash) => {
                        let mut bcast_instance = BcastInstance::new(data, hash, participants);
                        self.send_echo(&mut bcast_instance, hash, msg_link_id).await;
                        instance_opt = Some(bcast_instance);
                        break;
                    }
                    Err(_) => {
                        tracing::warn!(
                            sender = ?sender,
                            msg_link_id = ?msg_link_id,
                            "invalid init signature, ignoring message"
                        );
                    }
                }
            } else {
                // Buffer messages that arrived before Init
                msg_queue.push(msg);
            }
        }

        if let Some(inst) = instance_opt.as_mut() {
            inst.msg_queue = msg_queue;
        }
        instance_opt
    }

    async fn handle_message(
        &self,
        msg: MsgLink<BroadcastRound<T>>,
        bcast_instance: &mut BcastInstance<T>,
    ) {
        let msg_link_id = msg.get_msg_id().clone();
        let sender = msg.sender;

        match msg.data {
            BroadcastRound::Init(_, _, _) => {
                tracing::warn!(
                    msg_link_id = ?msg_link_id,
                    "received multiple init messages for same msg_link_id, ignoring"
                );
                return;
            }
            BroadcastRound::Echo(init_hash, sender_sig) => {
                if init_hash != bcast_instance.payload_hash {
                    tracing::warn!(
                        sender = ?sender,
                        msg_link_id = ?msg_link_id,
                        "received echo with mismatched hash, ignoring"
                    );
                    return;
                }

                // Skip counting if we already sent Ready (optimization)
                if bcast_instance.is_ready_msg_sent {
                    return;
                }

                if bcast_instance.has_sent_echo(sender) {
                    tracing::warn!(
                        sender = ?sender,
                        msg_link_id = ?msg_link_id,
                        "received duplicate echo from sender, ignoring"
                    );
                    return;
                }

                if let Err(_) = verify_echo(sender, init_hash, msg_link_id, sender_sig) {
                    tracing::warn!(
                        sender = ?sender,
                        msg_link_id = ?msg_link_id,
                        "invalid echo signature, ignoring"
                    );
                    return;
                }

                bcast_instance.count_echo(init_hash.clone(), sender).await;
                if bcast_instance.echo_threshold_reached {
                    self.send_ready(bcast_instance, init_hash, msg_link_id)
                        .await;
                }
            }
            BroadcastRound::Ready(init_hash, signature) => {
                if init_hash != bcast_instance.payload_hash {
                    tracing::warn!(
                        sender = ?sender,
                        msg_link_id = ?msg_link_id,
                        "received ready with mismatched hash, ignoring"
                    );
                    return;
                }

                if bcast_instance.has_sent_ready(sender) {
                    tracing::warn!(
                        sender = ?sender,
                        msg_link_id = ?msg_link_id,
                        "received duplicate ready from sender, ignoring"
                    );
                    return;
                }

                if let Err(_) = verify_ready(sender, init_hash, msg_link_id, signature) {
                    tracing::warn!(
                        sender = ?sender,
                        msg_link_id = ?msg_link_id,
                        "invalid ready signature, ignoring"
                    );
                    return;
                }

                bcast_instance.count_ready(init_hash.clone(), sender).await;

                // Ready amplification: if we see f+1 Readys, we send our own
                if bcast_instance.ready_amp_threshold_reached {
                    if !bcast_instance.is_ready_msg_sent {
                        self.send_ready(bcast_instance, init_hash, msg_link_id)
                            .await;
                    }
                }
            }
        }
    }

    async fn send_echo(
        &self,
        bcast_instance: &mut BcastInstance<T>,
        hash: HashBytes,
        msg_link_id: MsgLinkId,
    ) {
        tracing::debug!(
            node = ?self.public_key,
            msg_link_id = ?msg_link_id,
            "sending echo messages"
        );

        let my_sig = self.private_key.sign_echo(hash, msg_link_id);
        let echo_msg = BroadcastRound::Echo(hash, my_sig);

        for participant in bcast_instance.participants.iter() {
            if participant == self.public_key() {
                continue;
            }
            self.interface
                .send_msg(participant, &echo_msg, msg_link_id, self.public_key)
                .await;
        }
        bcast_instance.count_echo(hash, *self.public_key()).await;
    }

    async fn send_ready(
        &self,
        bcast_instance: &mut BcastInstance<T>,
        hash: HashBytes,
        msg_link_id: MsgLinkId,
    ) {
        tracing::debug!(
            node = ?self.public_key,
            msg_link_id = ?msg_link_id,
            "sending ready messages"
        );

        let sig = self.private_key.sign_ready(hash, msg_link_id);
        let rdy_msg = BroadcastRound::Ready(hash, sig);

        for participant in bcast_instance.participants.iter() {
            if participant == self.public_key() {
                continue;
            }
            self.interface
                .send_msg(participant, &rdy_msg, msg_link_id, self.public_key)
                .await;
        }
        bcast_instance.count_ready(hash, *self.public_key()).await;
        bcast_instance.is_ready_msg_sent = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use std::time::Duration;

    #[tokio::test]
    async fn test_broadcast_four_honest_nodes() {
        const TIMEOUT_SECS: u64 = 5;
        let node0: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node1: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node2: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node3: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;

        let pubkey0 = *node0.public_key();
        let pubkey1 = *node1.public_key();
        let pubkey2 = *node2.public_key();
        let pubkey3 = *node3.public_key();

        for node in [&node0, &node1, &node2, &node3] {
            node.add_addr(node0.public_key, node0.addr()).await;
            node.add_addr(node1.public_key, node1.addr()).await;
            node.add_addr(node2.public_key, node2.addr()).await;
            node.add_addr(node3.public_key, node3.addr()).await;
        }

        let msg_link_id = MsgLinkId::new(100);
        let broadcast_data = "Important broadcast message".to_string();
        let participants = vec![pubkey0, pubkey1, pubkey2, pubkey3];

        let node0_clone = node0.clone();
        let data_clone = broadcast_data.clone();
        let participants_clone = participants.clone();
        let initiator_task = tokio::spawn(async move {
            node0_clone
                .broadcast_init(participants_clone, data_clone, msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node1_clone = node1.clone();
        let participant1_task = tokio::spawn(async move {
            node1_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node2_clone = node2.clone();
        let participant2_task = tokio::spawn(async move {
            node2_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node3_clone = node3.clone();
        let participant3_task = tokio::spawn(async move {
            node3_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let result0 = initiator_task
            .await
            .expect("Node 0 panicked")
            .expect("Node 0 broadcast failed");
        let result1 = participant1_task
            .await
            .expect("Node 1 panicked")
            .expect("Node 1 broadcast failed");
        let result2 = participant2_task
            .await
            .expect("Node 2 panicked")
            .expect("Node 2 broadcast failed");
        let result3 = participant3_task
            .await
            .expect("Node 3 panicked")
            .expect("Node 3 broadcast failed");

        assert_eq!(result0, broadcast_data);
        assert_eq!(result1, broadcast_data);
        assert_eq!(result2, broadcast_data);
        assert_eq!(result3, broadcast_data);
    }

    #[tokio::test]
    async fn test_broadcast_messages_arrive_out_of_order() {
        const TIMEOUT_SECS: u64 = 5;
        let node0: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node1: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node2: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node3: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;

        let pubkey0 = *node0.public_key();
        let pubkey1 = *node1.public_key();
        let pubkey2 = *node2.public_key();
        let pubkey3 = *node3.public_key();

        for node in [&node0, &node1, &node2, &node3] {
            node.add_addr(pubkey0, node0.addr()).await;
            node.add_addr(pubkey1, node1.addr()).await;
            node.add_addr(pubkey2, node2.addr()).await;
            node.add_addr(pubkey3, node3.addr()).await;
        }

        let msg_link_id = MsgLinkId::new(200);
        let broadcast_data = "Out of order test".to_string();
        let participants = vec![pubkey0, pubkey1, pubkey2, pubkey3];

        let node1_clone = node1.clone();
        let participant1_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            node1_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node2_clone = node2.clone();
        let participant2_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            node2_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node3_clone = node3.clone();
        let participant3_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            node3_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let node0_clone = node0.clone();
        let data_clone = broadcast_data.clone();
        let participants_clone = participants.clone();
        let initiator_task = tokio::spawn(async move {
            node0_clone
                .broadcast_init(participants_clone, data_clone, msg_link_id, TIMEOUT_SECS)
                .await
        });

        let result0 = initiator_task
            .await
            .expect("Node 0 panicked")
            .expect("Node 0 failed");
        let result1 = participant1_task
            .await
            .expect("Node 1 panicked")
            .expect("Node 1 failed");
        let result2 = participant2_task
            .await
            .expect("Node 2 panicked")
            .expect("Node 2 failed");
        let result3 = participant3_task
            .await
            .expect("Node 3 panicked")
            .expect("Node 3 failed");

        assert_eq!(result0, broadcast_data);
        assert_eq!(result1, broadcast_data);
        assert_eq!(result2, broadcast_data);
        assert_eq!(result3, broadcast_data);
    }

    #[tokio::test]
    async fn test_broadcast_multiple_concurrent_broadcasts() {
        const NUM_NODES: usize = 10;
        const TIMEOUT_SECS: u64 = 10;

        let mut nodes = Vec::new();
        let mut pubkeys = Vec::new();

        for _ in 0..NUM_NODES {
            let node: Arc<ProtocolNode<String>> =
                ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
            pubkeys.push(*node.public_key());
            nodes.push(node);
        }

        for node in &nodes {
            for (idx, &pubkey) in pubkeys.iter().enumerate() {
                node.add_addr(pubkey, nodes[idx].addr()).await;
            }
        }

        let mut all_tasks = Vec::new();

        for (initiator_idx, initiator_node) in nodes.iter().enumerate() {
            let msg_link_id = MsgLinkId::new(initiator_idx as u128);
            let broadcast_data = format!("Message from node {}", initiator_idx);
            let participants = pubkeys.clone();

            let node_clone = initiator_node.clone();
            let data_clone = broadcast_data.clone();
            let participants_clone = participants.clone();
            let init_task = tokio::spawn(async move {
                node_clone
                    .broadcast_init(
                        participants_clone,
                        data_clone.clone(),
                        msg_link_id,
                        TIMEOUT_SECS,
                    )
                    .await
                    .map(|result| (msg_link_id, result))
            });
            all_tasks.push(init_task);

            for (participant_idx, participant_node) in nodes.iter().enumerate() {
                if participant_idx == initiator_idx {
                    continue;
                }

                let node_clone = participant_node.clone();
                let part_task = tokio::spawn(async move {
                    node_clone
                        .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                        .await
                        .map(|result| (msg_link_id, result))
                });
                all_tasks.push(part_task);
            }
        }

        let mut results_by_msg_id = HashMap::new();

        for task in all_tasks {
            match task.await {
                Ok(Ok((msg_id, data))) => {
                    results_by_msg_id
                        .entry(msg_id)
                        .or_insert_with(Vec::new)
                        .push(data);
                }
                Ok(Err(e)) => panic!("Task failed: {}", e),
                Err(e) => panic!("Task panicked: {:?}", e),
            }
        }

        assert_eq!(results_by_msg_id.len(), NUM_NODES);

        for (msg_id, results) in results_by_msg_id.iter() {
            assert_eq!(results.len(), NUM_NODES);
            let first = &results[0];
            assert!(
                results.iter().all(|r| r == first),
                "All nodes should agree on broadcast {:?}",
                msg_id
            );
        }
    }

    #[tokio::test]
    async fn test_broadcast_with_byzantine_node_sending_invalid_signatures() {
        // Test that nodes reject messages with invalid signatures from a Byzantine node
        // The honest nodes should still complete the broadcast successfully

        const TIMEOUT_SECS: u64 = 5;
        let honest_node0: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let honest_node1: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let honest_node2: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let byzantine_node: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;

        let pubkey0 = *honest_node0.public_key();
        let pubkey1 = *honest_node1.public_key();
        let pubkey2 = *honest_node2.public_key();
        let pubkey_byz = *byzantine_node.public_key();

        // Set up address books
        for node in [&honest_node0, &honest_node1, &honest_node2, &byzantine_node] {
            node.add_addr(pubkey0, honest_node0.addr()).await;
            node.add_addr(pubkey1, honest_node1.addr()).await;
            node.add_addr(pubkey2, honest_node2.addr()).await;
            node.add_addr(pubkey_byz, byzantine_node.addr()).await;
        }

        let msg_link_id = MsgLinkId::new(300);
        let broadcast_data = "Broadcast with Byzantine node".to_string();
        let participants = vec![pubkey0, pubkey1, pubkey2, pubkey_byz];

        // Honest node0 initiates broadcast
        let node0_clone = honest_node0.clone();
        let data_clone = broadcast_data.clone();
        let participants_clone = participants.clone();
        let initiator_task = tokio::spawn(async move {
            node0_clone
                .broadcast_init(participants_clone, data_clone, msg_link_id, TIMEOUT_SECS)
                .await
        });

        // Honest nodes participate normally
        let node1_clone = honest_node1.clone();
        let participant1_task = tokio::spawn(async move {
            node1_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node2_clone = honest_node2.clone();
        let participant2_task = tokio::spawn(async move {
            node2_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        // Byzantine node receives Init and subscribes, but we'll manually send garbage
        let byz_clone = byzantine_node.clone();
        let byzantine_task = tokio::spawn(async move {
            let mut rx = byz_clone
                .registry()
                .subscribe(msg_link_id)
                .await
                .expect("should subscribe");

            // Wait for Init message
            if let Some(msg) = rx.recv().await {
                if let BroadcastRound::Init(data, participants, init_sig) = msg.data {
                    let sender = msg.sender;
                    let hash =
                        verify_init(&init_sig, &data, sender, &participants, msg_link_id).unwrap();
                    // Send Echo with WRONG signature (signed by different key)
                    let wrong_key = PrivateKey::new();
                    let bad_sig = wrong_key.sign_echo(hash, msg_link_id);
                    let bad_echo = BroadcastRound::Echo(hash, bad_sig);

                    // Send bad messages to all honest nodes
                    for participant in participants.iter() {
                        if participant == byz_clone.public_key() {
                            continue;
                        }
                        byz_clone
                            .interface
                            .send_msg(participant, &bad_echo, msg_link_id, *byz_clone.public_key())
                            .await;
                    }
                }
            }

            // Byzantine node just waits - it won't complete the protocol
            tokio::time::sleep(Duration::from_secs(TIMEOUT_SECS)).await;
        });

        // All honest nodes should complete successfully despite Byzantine interference
        let result0 = initiator_task
            .await
            .expect("Node 0 panicked")
            .expect("Node 0 broadcast failed");
        let result1 = participant1_task
            .await
            .expect("Node 1 panicked")
            .expect("Node 1 broadcast failed");
        let result2 = participant2_task
            .await
            .expect("Node 2 panicked")
            .expect("Node 2 broadcast failed");

        // Verify all honest nodes got the correct data
        assert_eq!(result0, broadcast_data);
        assert_eq!(result1, broadcast_data);
        assert_eq!(result2, broadcast_data);

        // Byzantine task should still be running (it won't complete)
        drop(byzantine_task);
    }

    #[tokio::test]
    async fn test_byzantine_initiator_equivocates_to_one_node() {
        // Byzantine initiator equivocates: sends data_a to node1 + node2, data_b to node3.
        // This models a Byzantine node that equivocates on Init but cooperates with one partition.
        const TIMEOUT_SECS: u64 = 3;
        let byz_key = PrivateKey::new();
        let byz_node: Arc<ProtocolNode<String>> = ProtocolNode::new("127.0.0.1:0", byz_key).await;
        let node1: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node2: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node3: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;

        let byz_pubkey = *byz_node.public_key();
        let pubkey1 = *node1.public_key();
        let pubkey2 = *node2.public_key();
        let pubkey3 = *node3.public_key();

        for node in [&byz_node, &node1, &node2, &node3] {
            node.add_addr(byz_pubkey, byz_node.addr()).await;
            node.add_addr(pubkey1, node1.addr()).await;
            node.add_addr(pubkey2, node2.addr()).await;
            node.add_addr(pubkey3, node3.addr()).await;
        }

        let msg_link_id = MsgLinkId::new(500);
        let data_a = "Legitimate message".to_string();
        let data_b = "Equivocating message".to_string();
        let participants = vec![byz_pubkey, pubkey1, pubkey2, pubkey3];

        let (sig_a, hash_a) = byz_node
            .private_key
            .sign_init(&data_a, byz_pubkey, &participants, msg_link_id)
            .unwrap();
        let (sig_b, _) = byz_node
            .private_key
            .sign_init(&data_b, byz_pubkey, &participants, msg_link_id)
            .unwrap();

        let init_a = BroadcastRound::Init(data_a.clone(), participants.clone(), sig_a);
        let init_b = BroadcastRound::Init(data_b.clone(), participants.clone(), sig_b);

        // Send data_a to node1 + node2, data_b to node3
        byz_node
            .interface
            .send_msg(&pubkey1, &init_a, msg_link_id, byz_pubkey)
            .await;
        byz_node
            .interface
            .send_msg(&pubkey2, &init_a, msg_link_id, byz_pubkey)
            .await;
        byz_node
            .interface
            .send_msg(&pubkey3, &init_b, msg_link_id, byz_pubkey)
            .await;

        // The Byzantine node explicitly sends Echo(hash_a) and Ready(hash_a) because
        // it is operating outside the protocol loop
        let echo_sig = byz_node.private_key.sign_echo(hash_a, msg_link_id);
        let echo_msg = BroadcastRound::Echo(hash_a, echo_sig);
        for pk in [&pubkey1, &pubkey2, &pubkey3] {
            byz_node
                .interface
                .send_msg(pk, &echo_msg, msg_link_id, byz_pubkey)
                .await;
        }
        let ready_sig = byz_node.private_key.sign_ready(hash_a, msg_link_id);
        let ready_msg = BroadcastRound::Ready(hash_a, ready_sig);
        for pk in [&pubkey1, &pubkey2] {
            byz_node
                .interface
                .send_msg(pk, &ready_msg, msg_link_id, byz_pubkey)
                .await;
        }

        let node1_clone = node1.clone();
        let t1 = tokio::spawn(async move {
            node1_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node2_clone = node2.clone();
        let t2 = tokio::spawn(async move {
            node2_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node3_clone = node3.clone();
        let t3 = tokio::spawn(async move {
            node3_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        // node1 and node2 deliver data_a successfully
        let result1 = t1.await.unwrap().expect("node1 should deliver");
        let result2 = t2.await.unwrap().expect("node2 should deliver");
        assert_eq!(result1, data_a);
        assert_eq!(result2, data_a);

        // node3 received data_b but never reaches echo threshold — it should time out
        let result3 = t3.await.unwrap();
        assert!(
            matches!(result3, Err(BroadcastError::Timeout(TIMEOUT_SECS))),
            "node3 should time out waiting on stalled hash_b, got {:?}",
            result3
        );
    }

    #[tokio::test]
    async fn test_byzantine_initiator_equivocates_to_majority() {
        // Byzantine initiator equivocates: sends data_a to node1 only, data_b to node2 + node3.
        // No node reaches echo threshold so no Ready messages are ever sent.
        // All honest nodes stall and return Timeout.
        const TIMEOUT_SECS: u64 = 1;
        let byz_key = PrivateKey::new();
        let byz_node: Arc<ProtocolNode<String>> = ProtocolNode::new("127.0.0.1:0", byz_key).await;
        let node1: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node2: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node3: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;

        let byz_pubkey = *byz_node.public_key();
        let pubkey1 = *node1.public_key();
        let pubkey2 = *node2.public_key();
        let pubkey3 = *node3.public_key();

        for node in [&byz_node, &node1, &node2, &node3] {
            node.add_addr(byz_pubkey, byz_node.addr()).await;
            node.add_addr(pubkey1, node1.addr()).await;
            node.add_addr(pubkey2, node2.addr()).await;
            node.add_addr(pubkey3, node3.addr()).await;
        }

        let msg_link_id = MsgLinkId::new(600);
        let data_a = "Message A".to_string();
        let data_b = "Message B".to_string();
        let participants = vec![byz_pubkey, pubkey1, pubkey2, pubkey3];

        let (sig_a, hash_a) = byz_node
            .private_key
            .sign_init(&data_a, byz_pubkey, &participants, msg_link_id)
            .unwrap();
        let (sig_b, _) = byz_node
            .private_key
            .sign_init(&data_b, byz_pubkey, &participants, msg_link_id)
            .unwrap();

        let init_a = BroadcastRound::Init(data_a.clone(), participants.clone(), sig_a);
        let init_b = BroadcastRound::Init(data_b.clone(), participants.clone(), sig_b);

        // Send data_a to node1 only, data_b to node2 and node3
        byz_node
            .interface
            .send_msg(&pubkey1, &init_a, msg_link_id, byz_pubkey)
            .await;
        byz_node
            .interface
            .send_msg(&pubkey2, &init_b, msg_link_id, byz_pubkey)
            .await;
        byz_node
            .interface
            .send_msg(&pubkey3, &init_b, msg_link_id, byz_pubkey)
            .await;

        // Byzantine node echoes hash_a — brings hash_a count to 2, still below threshold of 3
        let echo_sig = byz_node.private_key.sign_echo(hash_a, msg_link_id);
        let echo_msg = BroadcastRound::Echo(hash_a, echo_sig);
        for pk in [&pubkey1, &pubkey2, &pubkey3] {
            byz_node
                .interface
                .send_msg(pk, &echo_msg, msg_link_id, byz_pubkey)
                .await;
        }

        let node1_clone = node1.clone();
        let t1 = tokio::spawn(async move {
            node1_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node2_clone = node2.clone();
        let t2 = tokio::spawn(async move {
            node2_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let node3_clone = node3.clone();
        let t3 = tokio::spawn(async move {
            node3_clone
                .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
                .await
        });

        let result1 = t1.await.unwrap();
        let result2 = t2.await.unwrap();
        let result3 = t3.await.unwrap();

        assert!(
            matches!(result1, Err(BroadcastError::Timeout(TIMEOUT_SECS))),
            "node1 should time out, got {:?}",
            result1
        );
        assert!(
            matches!(result2, Err(BroadcastError::Timeout(TIMEOUT_SECS))),
            "node2 should time out, got {:?}",
            result2
        );
        assert!(
            matches!(result3, Err(BroadcastError::Timeout(TIMEOUT_SECS))),
            "node3 should time out, got {:?}",
            result3
        );
    }

    #[tokio::test]
    async fn test_participant_times_out_waiting_for_init() {
        // Init is never sent. The node subscribes and waits on an empty channel until the timeout fires.

        const TIMEOUT_SECS: u64 = 1;
        let node: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;

        let msg_link_id = MsgLinkId::new(800);

        let result = node
            .participate_in_broadcast(msg_link_id, TIMEOUT_SECS)
            .await;

        assert!(
            matches!(result, Err(BroadcastError::Timeout(TIMEOUT_SECS))),
            "expected Timeout waiting for Init that never arrived, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_initiator_times_out_when_no_echoes_return() {
        // Verifies that broadcast_init times out when recipients never respond.

        const TIMEOUT_SECS: u64 = 1;

        let node0: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node1: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node2: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
        let node3: Arc<ProtocolNode<String>> =
            ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;

        let pubkey0 = *node0.public_key();
        let pubkey1 = *node1.public_key();
        let pubkey2 = *node2.public_key();
        let pubkey3 = *node3.public_key();

        for node in [&node0, &node1, &node2, &node3] {
            node.add_addr(pubkey0, node0.addr()).await;
            node.add_addr(pubkey1, node1.addr()).await;
            node.add_addr(pubkey2, node2.addr()).await;
            node.add_addr(pubkey3, node3.addr()).await;
        }

        let msg_link_id = MsgLinkId::new(900);
        let participants = vec![pubkey0, pubkey1, pubkey2, pubkey3];

        // Only the initiator participates so no echoes are ever sent back
        let result = node0
            .broadcast_init(participants, "hello".to_string(), msg_link_id, TIMEOUT_SECS)
            .await;

        assert!(
            matches!(result, Err(BroadcastError::Timeout(TIMEOUT_SECS))),
            "expected initiator to time out with no echoes returning, got {:?}",
            result
        );
    }
}
