use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::crypto::{
    HashBytes, PrivateKey, PublicKeyBytes, SignatureBytes, verify_echo, verify_init, verify_ready,
};
use crate::network::{Data, Interface, MsgLink, MsgLinkId, Registry};

/// Protocol-aware wrapper around Interface that handles signing and identity
pub struct ProtocolNode<T> {
    interface: Arc<Interface<BroadcastRound<T>>>,
    private_key: PrivateKey,
    public_key: PublicKeyBytes,
}

impl<T: Data> ProtocolNode<T> {
    pub async fn new(addr: impl tokio::net::ToSocketAddrs, private_key: PrivateKey) -> Arc<Self> {
        let public_key = private_key.to_public_key();
        let interface = Interface::new(addr).await;

        Arc::new(Self {
            interface,
            private_key: private_key,
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

    fn get_sig_and_hash<S: serde::Serialize>(
        &self,
        data: &S,
        initiator: PublicKeyBytes,
        participants: &Vec<PublicKeyBytes>,
        msg_link_id: MsgLinkId,
    ) -> (SignatureBytes, HashBytes) {
        self.private_key
            .sig_and_hash(data, initiator, participants, msg_link_id)
    }

    async fn send_msg(
        &self,
        rcvr: &PublicKeyBytes,
        msg: &BroadcastRound<T>,
        msg_link_id: MsgLinkId,
    ) {
        self.interface
            .send_msg(rcvr, msg, msg_link_id, self.public_key)
            .await;
    }

    /// Start a reliable broadcast and participate in it
    pub async fn broadcast_init(
        &self,
        recipients: Vec<PublicKeyBytes>,
        data: T,
        msg_link_id: MsgLinkId,
    ) -> Result<T, String> {
        let (sig, hash) =
            self.get_sig_and_hash(&data, *self.public_key(), &recipients, msg_link_id);
        let msg = BroadcastRound::Init(data.clone(), recipients.clone(), sig);

        for participant in recipients.iter() {
            if participant == self.public_key() {
                continue;
            }
            self.send_msg(participant, &msg, msg_link_id).await;
        }

        // need to set up init state here because initiator wont receive init RPC (from himself)
        let mut bcast_instance = BcastInstance::new();
        bcast_instance.participants = recipients;
        bcast_instance.payload = Some(data);

        // Send out echo and count it
        let my_sig = self.private_key.sign_echo(hash, msg_link_id);
        let echo_msg: BroadcastRound<T> = BroadcastRound::Echo(hash, my_sig);
        for participant in bcast_instance.participants.iter() {
            if participant == self.public_key() {
                continue;
            }
            self.send_msg(participant, &echo_msg, msg_link_id).await;
        }
        Self::count_echo(&mut bcast_instance, hash, *self.public_key()).await;

        let mut rx = self.registry().subscribe(msg_link_id).await.unwrap();
        self.participate_in_broadcast_inner(bcast_instance, &mut rx)
            .await
    }

    pub async fn participate_in_broadcast(&self, msg_link_id: MsgLinkId) -> Result<T, String> {
        let mut rx = self.registry().subscribe(msg_link_id).await.unwrap();
        // wait for init message and place messages received beforehand in bcast_instance.msg_queue
        let bcast_instance = self.wait_for_init(msg_link_id, &mut rx).await;
        if bcast_instance.payload.is_none() {
            return Err("Did not find init message".to_string());
        }
        let value = self
            .participate_in_broadcast_inner(bcast_instance, &mut rx)
            .await;
        drop(rx);
        value
    }
    /// Participate as a recipient of a reliable broadcast
    async fn participate_in_broadcast_inner(
        &self,
        bcast_instance: BcastInstance<T>,
        rx: &mut tokio::sync::mpsc::Receiver<MsgLink<BroadcastRound<T>>>,
    ) -> Result<T, String> {
        let mut bcast_instance = bcast_instance;
        while let Some(msg) = bcast_instance.msg_queue.pop() {
            self.handle_message(msg, &mut bcast_instance).await;
            if bcast_instance.delivery_threshold_reached {
                return bcast_instance
                    .payload
                    .ok_or("Payload not initialized".to_string());
            }
        }
        while let Some(msg) = rx.recv().await {
            self.handle_message(msg, &mut bcast_instance).await;
            if bcast_instance.delivery_threshold_reached {
                return bcast_instance
                    .payload
                    .ok_or("Payload not initialized".to_string());
            }
        }

        Err("no".to_string())
    }

    /// Wait for round one message here and then go into participate_inner() with participants already set
    async fn wait_for_init(
        &self,
        msg_link_id: MsgLinkId,
        rx: &mut tokio::sync::mpsc::Receiver<MsgLink<BroadcastRound<T>>>,
    ) -> BcastInstance<T> {
        let mut bcast_instance: BcastInstance<T> = BcastInstance::new();
        while let Some(msg) = rx.recv().await {
            let sender = msg.sender;
            if let BroadcastRound::Init(data, participants, init_sig) = msg.data {
                // validate Initiator signature
                let Ok(hash) = verify_init(&init_sig, &data, sender, &participants, msg_link_id)
                else {
                    eprintln!("invalid signature");
                    continue;
                };
                bcast_instance.participants = participants;
                bcast_instance.payload = Some(data);

                // Send out echo
                let my_sig = self.private_key.sign_echo(hash, msg_link_id);
                let echo_msg: BroadcastRound<T> = BroadcastRound::Echo(hash.clone(), my_sig);
                for participant in bcast_instance.participants.iter() {
                    if participant == self.public_key() {
                        continue;
                    }
                    self.send_msg(participant, &echo_msg, msg_link_id).await;
                }
                break;
            } else {
                bcast_instance.msg_queue.push(msg);
            }
        }
        bcast_instance
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
                if bcast_instance.payload.is_some() {
                    eprintln!("multiple init message for the same msg id");
                    return;
                }
            }
            BroadcastRound::Echo(init_hash, sender_sig) => {
                // Skip all counting logic if we've already sent out Ready
                if bcast_instance.is_ready_msg_sent {
                    return;
                }
                // Ignore echo message if we've received an echo message from that pubkey
                if bcast_instance.has_sent_echo(sender) {
                    eprintln!("Multiple echo messages from {sender:?}");
                    return;
                }
                // Validate sender signature
                if verify_echo(sender, init_hash, msg_link_id, sender_sig).is_err() {
                    return;
                }
                Self::count_echo(bcast_instance, init_hash.clone(), sender).await;
                if bcast_instance.echo_threshold_reached {
                    self.send_ready(bcast_instance, init_hash, msg_link_id)
                        .await;
                }
            }
            BroadcastRound::Ready(init_hash, signature) => {
                if bcast_instance.has_sent_ready(sender) {
                    eprintln!("Multiple ready messages from {sender:?}");
                    return;
                }
                if verify_ready(sender, init_hash, msg_link_id, signature).is_err() {
                    eprintln!("Invalid signature from {sender:?}");
                    return;
                }
                Self::count_ready(bcast_instance, init_hash.clone(), sender).await;
                // Check to see if I should send out Ready amplification
                if bcast_instance.ready_amp_threshold_reached {
                    // Dont send Ready message if already sent
                    if !bcast_instance.is_ready_msg_sent {
                        self.send_ready(bcast_instance, init_hash, msg_link_id)
                            .await;
                    }
                }
            }
        }
    }
    async fn send_ready(
        &self,
        bcast_instance: &mut BcastInstance<T>,
        hash: HashBytes,
        msg_link_id: MsgLinkId,
    ) {
        let sig = self.private_key.sign_ready(hash, msg_link_id);
        let rdy_msg = BroadcastRound::Ready(hash, sig);
        let participants = bcast_instance.participants.clone();
        let public_key = *self.public_key();
        let interface = self.interface.clone();

        tokio::task::spawn(async move {
            for participant in participants {
                if participant == public_key {
                    continue;
                }
                let rdy_msg_clone = rdy_msg.clone();
                interface
                    .send_msg(&participant, &rdy_msg_clone, msg_link_id, public_key)
                    .await;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        bcast_instance.is_ready_msg_sent = true;
    }

    async fn count_echo(
        bcast_instance: &mut BcastInstance<T>,
        hash: HashBytes,
        sender: PublicKeyBytes,
    ) {
        let num_hashes = bcast_instance.hash_echo_count.entry(hash).or_insert(0);
        *num_hashes += 1;
        let count = *num_hashes;
        bcast_instance.sent_echo(sender);
        // Can't check quorum if Init message hasnt been processed
        if bcast_instance.payload.is_none() {
            return;
        }

        // Send Ready out and mark flag to not send multiple Ready(s) out
        if count >= bcast_instance.echo_to_ready_threshold() {
            bcast_instance.echo_threshold_reached = true;
        }
    }

    async fn count_ready(
        bcast_instance: &mut BcastInstance<T>,
        hash: HashBytes,
        sender: PublicKeyBytes,
    ) {
        let num_hashes = bcast_instance.hash_ready_count.entry(hash).or_insert(0);
        *num_hashes += 1;
        let count = *num_hashes;
        bcast_instance.sent_ready(sender);

        // Can't check quorum if Init message hasnt been processed
        if bcast_instance.payload.is_none() {
            return;
        }

        // Have I reached threshold of Readys to send my own Ready
        if count >= bcast_instance.ready_amp_threshold() {
            bcast_instance.ready_amp_threshold_reached = true;
        }

        // Check for delivery threshold
        if count >= bcast_instance.delivery_threshold() {
            bcast_instance.delivery_threshold_reached = true;
        }
    }
}

struct BcastInstance<T> {
    /// How many Echo received for a specific hash
    hash_echo_count: HashMap<HashBytes, usize>,
    /// How may Ready messages received for a specific hash
    hash_ready_count: HashMap<HashBytes, usize>,
    /// Has identity sent Echos or Readys for this `MsgLinkId`
    senders: HashMap<PublicKeyBytes, (bool, bool)>,
    is_ready_msg_sent: bool,
    echo_threshold_reached: bool,
    // have I received enough Readys to send out my own Ready to all of the protocol (Ready amplification)
    ready_amp_threshold_reached: bool,
    /// Did the broadcast finalize a value
    delivery_threshold_reached: bool,
    /// includes the initiator
    participants: Vec<PublicKeyBytes>,
    msg_queue: Vec<MsgLink<BroadcastRound<T>>>,
    payload: Option<T>,
}

impl<T> BcastInstance<T> {
    fn new() -> Self {
        Self {
            hash_echo_count: HashMap::new(),
            hash_ready_count: HashMap::new(),
            senders: HashMap::new(),
            is_ready_msg_sent: false,
            echo_threshold_reached: false,
            ready_amp_threshold_reached: false,
            delivery_threshold_reached: false,
            participants: Vec::new(),
            payload: None,
            msg_queue: Vec::new(),
        }
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
    fn echo_to_ready_threshold(&self) -> usize {
        let n = self.participants.len();
        (n + ((n - 1) / 3) + 1).div_ceil(2)
    }

    fn ready_amp_threshold(&self) -> usize {
        let n = self.participants.len();
        ((n - 1) / 3) + 1
    }

    fn delivery_threshold(&self) -> usize {
        let n = self.participants.len();
        (((n - 1) / 3) * 2) + 1
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize, Debug)]
pub enum BroadcastRound<T> {
    /// (Initiator, Data, Participants, InitiatorSignature)
    Init(T, Vec<PublicKeyBytes>, SignatureBytes),
    /// Sender, Hash
    Echo(HashBytes, SignatureBytes),
    /// Sender, Hash
    Ready(HashBytes, SignatureBytes),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use std::time::Duration;

    #[tokio::test]
    async fn test_broadcast_four_honest_nodes() {
        // Basic happy path: 4 honest nodes complete a broadcast successfully
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

        // Set up address books so everyone knows everyone
        for node in [&node0, &node1, &node2, &node3] {
            node.add_addr(node0.public_key, node0.addr()).await;
            node.add_addr(node1.public_key, node1.addr()).await;
            node.add_addr(node2.public_key, node2.addr()).await;
            node.add_addr(node3.public_key, node3.addr()).await;
        }

        let msg_link_id = MsgLinkId::new(100);
        let broadcast_data = "Important broadcast message".to_string();
        let participants = vec![pubkey0, pubkey1, pubkey2, pubkey3];

        // Node 0 initiates the broadcast
        let node0_clone = node0.clone();
        let data_clone = broadcast_data.clone();
        let participants_clone = participants.clone();
        let initiator_task = tokio::spawn(async move {
            node0_clone
                .broadcast_init(participants_clone, data_clone, msg_link_id)
                .await
        });

        // Other nodes participate
        let node1_clone = node1.clone();
        let participant1_task =
            tokio::spawn(async move { node1_clone.participate_in_broadcast(msg_link_id).await });

        let node2_clone = node2.clone();
        let participant2_task =
            tokio::spawn(async move { node2_clone.participate_in_broadcast(msg_link_id).await });

        let node3_clone = node3.clone();
        let participant3_task =
            tokio::spawn(async move { node3_clone.participate_in_broadcast(msg_link_id).await });

        // Wait for all to complete
        let timeout_duration = Duration::from_secs(3);

        let result0 = tokio::time::timeout(timeout_duration, initiator_task)
            .await
            .expect("Node 0 timed out")
            .expect("Node 0 task panicked")
            .expect("Node 0 broadcast failed");

        let result1 = tokio::time::timeout(timeout_duration, participant1_task)
            .await
            .expect("Node 1 timed out")
            .expect("Node 1 task panicked")
            .expect("Node 1 broadcast failed");

        let result2 = tokio::time::timeout(timeout_duration, participant2_task)
            .await
            .expect("Node 2 timed out")
            .expect("Node 2 task panicked")
            .expect("Node 2 broadcast failed");

        let result3 = tokio::time::timeout(timeout_duration, participant3_task)
            .await
            .expect("Node 3 timed out")
            .expect("Node 3 task panicked")
            .expect("Node 3 broadcast failed");

        // Verify all nodes received the same data
        assert_eq!(result0, broadcast_data);
        assert_eq!(result1, broadcast_data);
        assert_eq!(result2, broadcast_data);
        assert_eq!(result3, broadcast_data);
    }

    #[tokio::test]
    async fn test_broadcast_messages_arrive_out_of_order() {
        // Test that the protocol handles out-of-order message delivery
        // The registry buffers messages, so even if Echo arrives before Init,
        // the protocol should still complete successfully
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

        // Set up address books
        for node in [&node0, &node1, &node2, &node3] {
            node.add_addr(pubkey0, node0.addr()).await;
            node.add_addr(pubkey1, node1.addr()).await;
            node.add_addr(pubkey2, node2.addr()).await;
            node.add_addr(pubkey3, node3.addr()).await;
        }

        let msg_link_id = MsgLinkId::new(200);
        let broadcast_data = "Out of order test".to_string();
        let participants = vec![pubkey0, pubkey1, pubkey2, pubkey3];

        // Start participant tasks first - they will wait for messages
        let node1_clone = node1.clone();
        let participant1_task = tokio::spawn(async move {
            // Small delay to ensure subscribe happens first
            tokio::time::sleep(Duration::from_millis(10)).await;
            node1_clone.participate_in_broadcast(msg_link_id).await
        });

        let node2_clone = node2.clone();
        let participant2_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            node2_clone.participate_in_broadcast(msg_link_id).await
        });

        let node3_clone = node3.clone();
        let participant3_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            node3_clone.participate_in_broadcast(msg_link_id).await
        });

        // Small delay to let participants start listening
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now start the broadcast
        let node0_clone = node0.clone();
        let data_clone = broadcast_data.clone();
        let participants_clone = participants.clone();
        let initiator_task = tokio::spawn(async move {
            node0_clone
                .broadcast_init(participants_clone, data_clone, msg_link_id)
                .await
        });

        let timeout_duration = Duration::from_secs(5);

        let result0 = tokio::time::timeout(timeout_duration, initiator_task)
            .await
            .expect("Node 0 timed out")
            .expect("Node 0 panicked")
            .expect("Node 0 failed");

        let result1 = tokio::time::timeout(timeout_duration, participant1_task)
            .await
            .expect("Node 1 timed out")
            .expect("Node 1 panicked")
            .expect("Node 1 failed");

        let result2 = tokio::time::timeout(timeout_duration, participant2_task)
            .await
            .expect("Node 2 timed out")
            .expect("Node 2 panicked")
            .expect("Node 2 failed");

        let result3 = tokio::time::timeout(timeout_duration, participant3_task)
            .await
            .expect("Node 3 timed out")
            .expect("Node 3 panicked")
            .expect("Node 3 failed");

        assert_eq!(result0, broadcast_data);
        assert_eq!(result1, broadcast_data);
        assert_eq!(result2, broadcast_data);
        assert_eq!(result3, broadcast_data);
    }

    #[tokio::test]
    async fn test_broadcast_multiple_concurrent_broadcasts() {
        // Test multiple broadcasts happening concurrently on the same nodes
        // Each node initiates its own broadcast simultaneously
        const NUM_NODES: usize = 5;

        let mut nodes = Vec::new();
        let mut pubkeys = Vec::new();

        for _ in 0..NUM_NODES {
            let node: Arc<ProtocolNode<String>> =
                ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
            pubkeys.push(*node.public_key());
            nodes.push(node);
        }

        // Set up address books
        for node in &nodes {
            for (idx, &pubkey) in pubkeys.iter().enumerate() {
                node.add_addr(pubkey, nodes[idx].addr()).await;
            }
        }

        let mut all_tasks = Vec::new();

        // Each node initiates its own broadcast
        for (initiator_idx, initiator_node) in nodes.iter().enumerate() {
            let msg_link_id = MsgLinkId::new(initiator_idx as u128);
            let broadcast_data = format!("Message from node {}", initiator_idx);
            let participants = pubkeys.clone();

            // Initiator task
            let node_clone = initiator_node.clone();
            let data_clone = broadcast_data.clone();
            let participants_clone = participants.clone();
            let init_task = tokio::spawn(async move {
                node_clone
                    .broadcast_init(participants_clone, data_clone.clone(), msg_link_id)
                    .await
                    .map(|result| (msg_link_id, result))
            });
            all_tasks.push(init_task);

            // Participant tasks for other nodes
            for (participant_idx, participant_node) in nodes.iter().enumerate() {
                if participant_idx == initiator_idx {
                    continue;
                }

                let node_clone = participant_node.clone();
                let part_task = tokio::spawn(async move {
                    node_clone
                        .participate_in_broadcast(msg_link_id)
                        .await
                        .map(|result| (msg_link_id, result))
                });
                all_tasks.push(part_task);
            }
        }

        // Wait for all tasks
        let timeout_duration = Duration::from_secs(10);
        let mut results_by_msg_id = HashMap::new();

        for task in all_tasks {
            match tokio::time::timeout(timeout_duration, task).await {
                Ok(Ok(Ok((msg_id, data)))) => {
                    results_by_msg_id
                        .entry(msg_id)
                        .or_insert_with(Vec::new)
                        .push(data);
                }
                Ok(Ok(Err(e))) => panic!("Task failed: {}", e),
                Ok(Err(e)) => panic!("Task panicked: {:?}", e),
                Err(_) => panic!("Task timed out"),
            }
        }

        // Verify each broadcast was delivered to all nodes with consensus
        assert_eq!(
            results_by_msg_id.len(),
            NUM_NODES,
            "Should have results for all broadcasts"
        );

        for (msg_id, results) in results_by_msg_id.iter() {
            assert_eq!(
                results.len(),
                NUM_NODES,
                "Each broadcast should reach all {} nodes",
                NUM_NODES
            );

            // All results for this msg_id should be identical
            let first = &results[0];
            assert!(
                results.iter().all(|r| r == first),
                "All nodes should agree on broadcast {:?}",
                msg_id
            );
        }
    }
}
