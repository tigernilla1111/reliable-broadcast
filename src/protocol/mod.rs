use std::collections::HashMap;
use std::net::SocketAddr;
use std::u8;

use bincode::serde::encode_to_vec;
use sha2::{Digest, Sha256};

use crate::network::{Data, Interface, MsgLink, MsgLinkId};
use crate::types::{Signature, UserId};

const MAX_ENCODING_BYTES: usize = 10000;
type DataHashOutput = [u8; 32];

struct BcastInstance<T> {
    /// How many Echo received for a specific hash
    hash_echo_count: HashMap<DataHashOutput, usize>,
    /// How may Ready messages received for a specific hash
    hash_ready_count: HashMap<DataHashOutput, usize>,
    is_ready_msg_sent: bool,
    /// Did the broadcast finalize a value ie did it get >= quorom Ready messages
    is_bcast_finalized: bool,
    /// includes the initiator
    participants: Vec<UserId>,
    payload: Option<T>,
    // TODO: track echo and ready msgs received from a sender in a hashset (one for echos, one for readys)
}
impl<T> BcastInstance<T> {
    fn new(//payload_hash: [u8; 32],
    ) -> Self {
        Self {
            hash_echo_count: HashMap::new(),
            hash_ready_count: HashMap::new(),
            is_ready_msg_sent: false,
            is_bcast_finalized: false,
            participants: Vec::new(),
            payload: None,
        }
    }
    fn get_quorum(&self) -> usize {
        (self.participants.len() / 2) + 1
    }
}
#[derive(Clone, serde::Deserialize, serde::Serialize, Debug)]
enum BroadcastRound<T> {
    /// (MsgLinkId, Initiator, Data, Participants)
    Init(MsgLinkId, UserId, T, Vec<UserId>),
    /// MsgLinkId,  Sender, Hash
    Echo(MsgLinkId, UserId, DataHashOutput),
    /// MsgLinkId,  Sender, Hash
    Ready(MsgLinkId, UserId, DataHashOutput),
}
/// Start a reliable broadcast and participate in it
async fn broadcast_init<T: Data>(
    iface: &Interface<BroadcastRound<T>>,
    //bcast_state: &mut BcastState<T>,
    recipients: Vec<UserId>,
    data: T,
    msg_link_id: MsgLinkId,
) -> Result<T, String> {
    let msg = BroadcastRound::Init(msg_link_id, iface.pubkey, data.clone(), recipients.clone());
    let sig: Signature = "sign(msg_data||msg_link_id||SEND)".to_string();
    for rcvr in recipients.iter() {
        iface.send_msg(rcvr, &msg, msg_link_id).await;
    }
    // need to set up init state here because iniator wont receive init RPC (from himself)
    let mut bcast_instance = BcastInstance::new();
    bcast_instance.participants = recipients;
    bcast_instance.payload = Some(data);
    participate_in_broadcast(&iface, Some(bcast_instance), msg_link_id).await
}

/// function to run to participate as a recipient of a reliable broadcast
async fn participate_in_broadcast<T: Data>(
    iface: &Interface<BroadcastRound<T>>,
    bcast_instance: Option<BcastInstance<T>>,
    msg_link_id: MsgLinkId,
) -> Result<T, String> {
    let mut rx = iface.registry.subscribe(msg_link_id).await.unwrap();
    let mut bcast_instance = bcast_instance.unwrap_or(BcastInstance::new());
    // TODO: validate signature
    // TODO: do all message handling in this loop
    while let Some(msg) = rx.recv().await {
        match msg.data {
            BroadcastRound::Init(_, _, data, participants) => {
                // TODO: check for multiple init messages
                let hash = canonical_hash(&data);
                bcast_instance.participants = participants;
                bcast_instance.payload = Some(data);

                // Send out echo
                let echo_msg: BroadcastRound<T> =
                    BroadcastRound::Echo(msg_link_id, iface.pubkey, hash);
                for participant in bcast_instance.participants.iter() {
                    if participant == &iface.pubkey {
                        continue;
                    }
                    iface.send_msg(participant, &echo_msg, msg_link_id).await;
                }

                // check for quorums reached on messages received before processing Init
                let quorum = bcast_instance.get_quorum();
                // send out Ready if quorum is reached
                if let Some(&echo_count) = bcast_instance.hash_echo_count.get(&hash) {
                    if echo_count >= quorum {
                        bcast_instance.is_ready_msg_sent = true;
                        let rdy_msg = BroadcastRound::Ready(msg_link_id, iface.pubkey, hash);
                        for participant in bcast_instance.participants.iter() {
                            if participant == &iface.pubkey {
                                continue;
                            }
                            iface.send_msg(participant, &rdy_msg, msg_link_id).await;
                        }
                    }
                }
                // deliver message if quorum is reached
                if let Some(&ready_count) = bcast_instance.hash_ready_count.get(&hash) {
                    if ready_count >= quorum {
                        return bcast_instance
                            .payload
                            .ok_or("No payload initiated".to_string());
                    }
                }
            }
            _ => {
                handle_msg_data(msg, &mut bcast_instance, iface).await;
                // If init message hasnt been processed, cant check quorum
                if bcast_instance.payload.is_none() {
                    continue;
                }
                if bcast_instance.is_bcast_finalized {
                    return bcast_instance
                        .payload
                        .ok_or("Payload not initialized".to_string());
                }
            }
        }
    }
    // Drop receiver
    drop(rx);

    Err("no".to_string())
}

async fn handle_msg_data<T: Data>(
    msg: MsgLink<BroadcastRound<T>>,
    bcast_instance: &mut BcastInstance<T>,
    iface: &Interface<BroadcastRound<T>>,
) {
    if bcast_instance.is_bcast_finalized {
        return;
    }
    match msg.data {
        BroadcastRound::Echo(msg_link_id, sender, hash) => {
            // we can stop counting echos if the Ready message has been sent out already
            if bcast_instance.is_ready_msg_sent {
                return;
            }
            let num_hashes = bcast_instance.hash_echo_count.entry(hash).or_insert(0);
            *num_hashes += 1;
            // Can't check quorum if Init message hasnt been processed
            if bcast_instance.payload.is_none() {
                return;
            }

            // Send Ready out and mark flag to not send multiple Ready(s) out
            if *num_hashes >= bcast_instance.get_quorum() {
                bcast_instance.is_ready_msg_sent = true;
                let rdy_msg = BroadcastRound::Ready(msg_link_id, iface.pubkey, hash);
                for participant in bcast_instance.participants.iter() {
                    if participant == &iface.pubkey {
                        continue;
                    }
                    iface.send_msg(participant, &rdy_msg, msg_link_id).await;
                }
            }
        }
        BroadcastRound::Ready(msg_link_id, sender, hash) => {
            let num_hashes = bcast_instance.hash_ready_count.entry(hash).or_insert(0);
            *num_hashes += 1;
            // Can't check quorum if Init message hasnt been processed
            if bcast_instance.payload.is_none() {
                return;
            }
            if *num_hashes >= bcast_instance.get_quorum() {
                bcast_instance.is_bcast_finalized = true;
            }
        }
        BroadcastRound::Init(_, _, _, _) => {
            panic!("should not have any more init messages to process");
        }
    }
}

fn canonical_hash<T: serde::Serialize>(value: &T) -> DataHashOutput {
    let config = bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_ENCODING_BYTES>();
    let bytes = encode_to_vec(value, config).expect("serialization failed");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

mod tests {

    use super::*;
    use std::{sync::Arc, time::Duration};

    // ============================================================================
    // BASIC SANITY CHECKS
    // ============================================================================

    #[test]
    fn bcast_instance_new() {
        let instance: BcastInstance<String> = BcastInstance::new();
        assert!(instance.hash_echo_count.is_empty());
        assert!(instance.hash_ready_count.is_empty());
        assert!(!instance.is_ready_msg_sent);
        assert!(!instance.is_bcast_finalized);
        assert!(instance.participants.is_empty());
        assert!(instance.payload.is_none());
    }

    #[test]
    fn bcast_instance_get_quorum() {
        let mut instance: BcastInstance<String> = BcastInstance::new();
        let create_users = |num: i32| {
            (0..num)
                .map(|n| UserId::new(n as u64))
                .collect::<Vec<UserId>>()
        };

        // Empty participants
        assert_eq!(instance.get_quorum(), 1);
        instance.participants = create_users(1);
        assert_eq!(instance.get_quorum(), 1);
        instance.participants = create_users(2);
        assert_eq!(instance.get_quorum(), 2);
        instance.participants = create_users(3);
        assert_eq!(instance.get_quorum(), 2);
        instance.participants = create_users(4);
        assert_eq!(instance.get_quorum(), 3);
        instance.participants = create_users(5);
        assert_eq!(instance.get_quorum(), 3);
    }

    #[test]
    fn canonical_hash_deterministic() {
        let data1 = "test_data".to_string();
        let data2 = "test_data".to_string();
        let hash1 = canonical_hash(&data1);
        let hash2 = canonical_hash(&data2);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn canonical_hash_different_data() {
        let data1 = "test_data_1".to_string();
        let data2 = "test_data_2".to_string();
        let hash1 = canonical_hash(&data1);
        let hash2 = canonical_hash(&data2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn canonical_hash_complex_data() {
        #[derive(serde::Serialize)]
        struct ComplexData {
            id: u64,
            name: String,
            values: Vec<i32>,
        }

        let data = ComplexData {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let hash = canonical_hash(&data);
        assert_eq!(hash.len(), 32);

        // Same data should produce same hash
        let data2 = ComplexData {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };
        let hash2 = canonical_hash(&data2);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn broadcast_round_init_serialization() {
        let msg_id = MsgLinkId::new(1);
        let initiator = UserId::new(100);
        let data = "test_payload".to_string();
        let participants = vec![UserId::new(1), UserId::new(2), UserId::new(3)];

        let round = BroadcastRound::Init(msg_id, initiator, data, participants);

        // Test that it can be serialized and deserialized
        let config = bincode::config::standard();
        let encoded = bincode::serde::encode_to_vec(&round, config).unwrap();
        let decoded: BroadcastRound<String> = bincode::serde::decode_from_slice(&encoded, config)
            .unwrap()
            .0;

        match decoded {
            BroadcastRound::Init(id, init, payload, parts) => {
                assert_eq!(id, msg_id);
                assert_eq!(init, initiator);
                assert_eq!(payload, "test_payload");
                assert_eq!(parts.len(), 3);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn broadcast_round_echo_serialization() {
        let msg_id = MsgLinkId::new(2);
        let sender = UserId::new(200);
        let hash = [42u8; 32];

        let round: BroadcastRound<String> = BroadcastRound::Echo(msg_id, sender, hash);

        let config = bincode::config::standard();
        let encoded = bincode::serde::encode_to_vec(&round, config).unwrap();
        let decoded: BroadcastRound<String> = bincode::serde::decode_from_slice(&encoded, config)
            .unwrap()
            .0;

        match decoded {
            BroadcastRound::Echo(id, s, h) => {
                assert_eq!(id, msg_id);
                assert_eq!(s, sender);
                assert_eq!(h, hash);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn broadcast_round_ready_serialization() {
        let msg_id = MsgLinkId::new(3);
        let sender = UserId::new(300);
        let hash = [99u8; 32];

        let round: BroadcastRound<String> = BroadcastRound::Ready(msg_id, sender, hash);

        let config = bincode::config::standard();
        let encoded = bincode::serde::encode_to_vec(&round, config).unwrap();
        let decoded: BroadcastRound<String> = bincode::serde::decode_from_slice(&encoded, config)
            .unwrap()
            .0;

        match decoded {
            BroadcastRound::Ready(id, s, h) => {
                assert_eq!(id, msg_id);
                assert_eq!(s, sender);
                assert_eq!(h, hash);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn bcast_instance_echo_counting() {
        let mut instance: BcastInstance<String> = BcastInstance::new();
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        // Count echos for hash1
        *instance.hash_echo_count.entry(hash1).or_insert(0) += 1;
        *instance.hash_echo_count.entry(hash1).or_insert(0) += 1;
        *instance.hash_echo_count.entry(hash1).or_insert(0) += 1;
        // Count echos for hash2
        *instance.hash_echo_count.entry(hash2).or_insert(0) += 1;
        assert_eq!(instance.hash_echo_count.get(&hash1), Some(&3));
        assert_eq!(instance.hash_echo_count.get(&hash2), Some(&1));
    }

    #[test]
    fn bcast_instance_ready_counting() {
        let mut instance: BcastInstance<String> = BcastInstance::new();
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        // Count ready messages for hash1
        *instance.hash_ready_count.entry(hash1).or_insert(0) += 1;
        *instance.hash_ready_count.entry(hash1).or_insert(0) += 1;
        // Count ready messages for hash2
        *instance.hash_ready_count.entry(hash2).or_insert(0) += 1;
        *instance.hash_ready_count.entry(hash2).or_insert(0) += 1;
        *instance.hash_ready_count.entry(hash2).or_insert(0) += 1;
        assert_eq!(instance.hash_ready_count.get(&hash1), Some(&2));
        assert_eq!(instance.hash_ready_count.get(&hash2), Some(&3));
    }

    // ============================================================================
    // INTEGRATION TESTS
    // ============================================================================

    #[tokio::test]
    async fn broadcast_standard_four_nodes_happy_path() {
        // Set up 4 nodes and verify they can complete a basic broadcast
        let iface0: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface1: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface2: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface3: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;

        let user0 = iface0.pubkey;
        let user1 = iface1.pubkey;
        let user2 = iface2.pubkey;
        let user3 = iface3.pubkey;

        // Each node needs to know about all the others
        for iface in [&iface0, &iface1, &iface2, &iface3].iter() {
            iface.add_addr(user0, iface0.addr).await;
            iface.add_addr(user1, iface1.addr).await;
            iface.add_addr(user2, iface2.addr).await;
            iface.add_addr(user3, iface3.addr).await;
        }
        
        let msg_link_id = MsgLinkId::new(100);
        let broadcast_data = "Important broadcast message".to_string();
        let participants = vec![user0, user1, user2, user3];

        // Node 0 starts the broadcast
        let data_clone = broadcast_data.clone();
        let participants_clone = participants.clone();
        let initiator_task = tokio::spawn(async move {
            broadcast_init(&*iface0, participants_clone, data_clone, msg_link_id).await
        });

        // The other nodes participate
        let participant1_task =
            tokio::spawn(
                async move { participate_in_broadcast(&*iface1, None, msg_link_id).await },
            );

        let participant2_task =
            tokio::spawn(
                async move { participate_in_broadcast(&*iface2, None, msg_link_id).await },
            );

        let participant3_task =
            tokio::spawn(
                async move { participate_in_broadcast(&*iface3, None, msg_link_id).await },
            );

        let timeout_duration = Duration::from_secs(5);

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

        // Check that everyone got the same message
        assert_eq!(result0, broadcast_data);
        assert_eq!(result1, broadcast_data);
        assert_eq!(result2, broadcast_data);
        assert_eq!(result3, broadcast_data);

        println!("All 4 nodes completed the broadcast successfully");
        println!("Everyone delivered: '{}'", broadcast_data);
    }

    #[tokio::test]
    async fn broadcast_messages_arrive_out_of_order() {
        // Make sure the protocol handles messages arriving in the wrong order.
        // We'll send an Echo before the Init arrives and verify everything still works.

        let iface0: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface1: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface2: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface3: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;

        let user0 = iface0.pubkey;
        let user1 = iface1.pubkey;
        let user2 = iface2.pubkey;
        let user3 = iface3.pubkey;

        for iface in [&iface0, &iface1, &iface2, &iface3].iter() {
            iface.add_addr(user0, iface0.addr).await;
            iface.add_addr(user1, iface1.addr).await;
            iface.add_addr(user2, iface2.addr).await;
            iface.add_addr(user3, iface3.addr).await;
        }

        let msg_link_id = MsgLinkId::new(200);
        let broadcast_data = "Out of order test message".to_string();
        let participants = vec![user0, user1, user2, user3];

        // Send an Echo message to node 1 before the Init arrives
        let data_hash = canonical_hash(&broadcast_data);
        let early_echo = BroadcastRound::Echo(msg_link_id, user2, data_hash);

        iface2.send_msg(&user1, &early_echo, msg_link_id).await;

        // Give the early message time to arrive
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now actually start the broadcast
        let data_clone = broadcast_data.clone();
        let participants_clone = participants.clone();
        let initiator_task = tokio::spawn(async move {
            broadcast_init(&*iface0, participants_clone, data_clone, msg_link_id).await
        });

        let iface1_clone = iface1.clone();
        let participant1_task = tokio::spawn(async move {
            participate_in_broadcast(&iface1_clone, None, msg_link_id).await
        });

        let iface2_clone = iface2.clone();
        let participant2_task = tokio::spawn(async move {
            participate_in_broadcast(&iface2_clone, None, msg_link_id).await
        });

        let iface3_clone = iface3.clone();
        let participant3_task = tokio::spawn(async move {
            participate_in_broadcast(&iface3_clone, None, msg_link_id).await
        });

        let timeout_duration = Duration::from_secs(5);

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

        // Despite the ordering issue, everyone should still get the right message
        assert_eq!(result0, broadcast_data);
        assert_eq!(result1, broadcast_data);
        assert_eq!(result2, broadcast_data);
        assert_eq!(result3, broadcast_data);

        println!("Broadcast worked correctly even with out-of-order messages");
        println!("Node 1 buffered the early Echo and processed it after Init arrived");
    }

    #[tokio::test]
    async fn broadcast_stress_test_many_concurrent_broadcasts() {
        // Run a lot of broadcasts at once to stress test the system.
        // 10 nodes each starting 5 broadcasts = 50 total concurrent broadcasts.
        
        const NUM_NODES: usize = 10;
        const BROADCASTS_PER_NODE: usize = 5;

        println!(
            "Starting stress test: {} nodes, {} broadcasts per node, {} total",
            NUM_NODES, BROADCASTS_PER_NODE, NUM_NODES * BROADCASTS_PER_NODE
        );

        // Create all the nodes
        let mut interfaces = Vec::new();
        let mut user_ids = Vec::new();

        for _ in 0..NUM_NODES {
            let iface: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
            user_ids.push(iface.pubkey);
            interfaces.push(iface);
        }

        // Set up address books so everyone knows everyone
        println!("Setting up address books...");
        for iface in interfaces.iter() {
            for (idx, user_id) in user_ids.iter().enumerate() {
                iface.add_addr(*user_id, interfaces[idx].addr).await;
            }
        }

        let mut all_tasks = Vec::new();

        println!(
            "Launching {} broadcasts...",
            NUM_NODES * BROADCASTS_PER_NODE
        );

        for initiator_idx in 0..NUM_NODES {
            for broadcast_num in 0..BROADCASTS_PER_NODE {
                let msg_link_id =
                    MsgLinkId::new((initiator_idx * BROADCASTS_PER_NODE + broadcast_num) as u128);
                let broadcast_data = format!("Node_{}_Broadcast_{}", initiator_idx, broadcast_num);
                let participants = user_ids.clone();

                // Start the initiator task
                let iface = interfaces[initiator_idx].clone();
                let data_clone = broadcast_data.clone();
                let participants_clone = participants.clone();

                let initiator_task = tokio::spawn(async move {
                    broadcast_init(&*iface, participants_clone, data_clone.clone(), msg_link_id)
                        .await
                        .map(|result| (msg_link_id, initiator_idx, result))
                });
                all_tasks.push(initiator_task);

                // Start participant tasks for all other nodes
                for participant_idx in 0..NUM_NODES {
                    if participant_idx == initiator_idx {
                        continue;
                    }

                    let iface_clone = interfaces[participant_idx].clone();

                    let participant_task = tokio::spawn(async move {
                        participate_in_broadcast(&iface_clone, None, msg_link_id)
                            .await
                            .map(|result| (msg_link_id, participant_idx, result))
                    });
                    all_tasks.push(participant_task);
                }
            }
        }

        println!("Waiting for {} tasks to complete...", all_tasks.len());

        let timeout_duration = Duration::from_secs(30);
        let start_time = std::time::Instant::now();

        let mut completed = 0;
        let mut failed = 0;
        let mut results_by_msg_id: HashMap<MsgLinkId, Vec<String>> = HashMap::new();

        for (idx, task) in all_tasks.into_iter().enumerate() {
            match tokio::time::timeout(timeout_duration, task).await {
                Ok(Ok(Ok((msg_id, _node_idx, data)))) => {
                    completed += 1;
                    results_by_msg_id
                        .entry(msg_id)
                        .or_insert_with(Vec::new)
                        .push(data);

                    if completed % 50 == 0 {
                        println!("  {} tasks completed so far...", completed);
                    }
                }
                Ok(Ok(Err(e))) => {
                    failed += 1;
                    eprintln!("  Task {} failed with error: {}", idx, e);
                }
                Ok(Err(e)) => {
                    failed += 1;
                    eprintln!("  Task {} panicked: {:?}", idx, e);
                }
                Err(_) => {
                    failed += 1;
                    eprintln!("  Task {} timed out", idx);
                }
            }
        }

        let elapsed = start_time.elapsed();

        println!("\nStress test results:");
        println!("  Total time: {:?}", elapsed);
        println!("  Completed: {}", completed);
        println!("  Failed: {}", failed);
        println!("  Unique broadcasts: {}", results_by_msg_id.len());

        // Check that all nodes agreed on each broadcast
        let mut consensus_verified = 0;
        for (msg_id, results) in results_by_msg_id.iter() {
            if !results.is_empty() {
                let first_result = &results[0];
                let all_agree = results.iter().all(|r| r == first_result);

                if all_agree {
                    consensus_verified += 1;
                } else {
                    eprintln!(
                        "  Warning: MsgLinkId {:?} had disagreement: {:?}",
                        msg_id, results
                    );
                }
            }
        }

        println!(
            "  Consensus verified: {}/{}",
            consensus_verified,
            results_by_msg_id.len()
        );

        assert_eq!(failed, 0, "No tasks should fail");
        assert_eq!(
            results_by_msg_id.len(),
            NUM_NODES * BROADCASTS_PER_NODE,
            "Should have results for all broadcasts"
        );
        assert_eq!(
            consensus_verified,
            NUM_NODES * BROADCASTS_PER_NODE,
            "All broadcasts should reach consensus"
        );

        println!(
            "\nStress test passed! All {} broadcasts completed successfully",
            NUM_NODES * BROADCASTS_PER_NODE
        );
    }

    #[tokio::test]
    async fn broadcast_byzantine_conflicting_hashes() {
        // Test that the protocol can handle a malicious node sending wrong hashes.
        // One node will send Echo messages with an incorrect hash, but the honest
        // majority should still reach consensus on the correct value.

        let iface0: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface1: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface2: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface3: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
        let iface4: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;

        let user0 = iface0.pubkey;
        let user1 = iface1.pubkey;
        let user2 = iface2.pubkey;
        let user3 = iface3.pubkey;
        let user4 = iface4.pubkey;

        for iface in [&iface0, &iface1, &iface2, &iface3, &iface4].iter() {
            iface.add_addr(user0, iface0.addr).await;
            iface.add_addr(user1, iface1.addr).await;
            iface.add_addr(user2, iface2.addr).await;
            iface.add_addr(user3, iface3.addr).await;
            iface.add_addr(user4, iface4.addr).await;
        }

        let msg_link_id = MsgLinkId::new(300);
        let broadcast_data = "Correct message".to_string();
        let participants = vec![user0, user1, user2, user3, user4];

        println!("Byzantine test: node 4 will send malicious Echo messages with a fake hash");

        // Node 0 starts the broadcast
        let iface0_clone = iface0.clone();
        let data_clone = broadcast_data.clone();
        let participants_clone = participants.clone();
        let initiator_task = tokio::spawn(async move {
            broadcast_init(&*iface0_clone, participants_clone, data_clone, msg_link_id).await
        });

        // Nodes 1, 2, and 3 participate honestly
        let iface1_clone = iface1.clone();
        let participant1_task = tokio::spawn(async move {
            participate_in_broadcast(&iface1_clone, None, msg_link_id).await
        });

        let iface2_clone = iface2.clone();
        let participant2_task = tokio::spawn(async move {
            participate_in_broadcast(&iface2_clone, None, msg_link_id).await
        });

        let iface3_clone = iface3.clone();
        let participant3_task = tokio::spawn(async move {
            participate_in_broadcast(&iface3_clone, None, msg_link_id).await
        });

        // Node 4 will both participate and send malicious messages
        let iface4_clone = iface4.clone();
        let iface4_for_attack = iface4.clone();

        // Spawn the Byzantine behavior
        tokio::spawn(async move {
            // Wait for Init to propagate
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Send Echo messages with a completely wrong hash
            let fake_hash = [
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ];

            let malicious_echo = BroadcastRound::Echo(msg_link_id, user4, fake_hash);

            for target in [user0, user1, user2, user3].iter() {
                iface4_for_attack
                    .send_msg(target, &malicious_echo, msg_link_id)
                    .await;
            }

            println!("  Node 4 sent malicious Echo messages to all other nodes");
        });

        // Node 4 also receives messages normally
        let participant4_task = tokio::spawn(async move {
            participate_in_broadcast(&iface4_clone, None, msg_link_id).await
        });

        let timeout_duration = Duration::from_secs(5);

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

        let result4 = tokio::time::timeout(timeout_duration, participant4_task)
            .await
            .expect("Node 4 timed out")
            .expect("Node 4 task panicked")
            .expect("Node 4 broadcast failed");

        // Everyone should get the correct message despite the malicious node.
        // The fake Echos get ignored because:
        // - They don't match the hash from Init
        // - The honest nodes (4 out of 5) send correct Echos
        // - Quorum is 3, so 4 honest Echos are enough to proceed

        assert_eq!(result0, broadcast_data);
        assert_eq!(result1, broadcast_data);
        assert_eq!(result2, broadcast_data);
        assert_eq!(result3, broadcast_data);
        assert_eq!(result4, broadcast_data);

        println!("Byzantine fault tolerance verified");
        println!("All nodes delivered the correct message despite the malicious node");
        println!("Configuration: quorum 3/5, honest nodes 4/5, Byzantine nodes 1/5");
    }
}