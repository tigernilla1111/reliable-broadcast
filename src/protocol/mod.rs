use std::collections::HashMap;
use std::net::SocketAddr;
use std::u8;

use crate::crypto::{PrivateKey, PublicKeyBytes, Sha512HashBytes, canonical_bytes};
use crate::network::{Data, Interface, MsgLink, MsgLinkId};

struct BcastInstance<T> {
    /// How many Echo received for a specific hash
    hash_echo_count: HashMap<Sha512HashBytes, usize>,
    /// How may Ready messages received for a specific hash
    hash_ready_count: HashMap<Sha512HashBytes, usize>,
    is_ready_msg_sent: bool,
    echo_threshold_reached: bool,
    // have I received enough Readys to send out my own Ready to all of the protocol (Ready amplification)
    ready_amp_threshold_reached: bool,
    /// Did the broadcast finalize a value
    delivery_threshold_reached: bool,
    /// includes the initiator
    participants: Vec<PublicKeyBytes>,
    payload: Option<T>,
}
impl<T> BcastInstance<T> {
    fn new() -> Self {
        Self {
            hash_echo_count: HashMap::new(),
            hash_ready_count: HashMap::new(),
            is_ready_msg_sent: false,
            echo_threshold_reached: false,
            ready_amp_threshold_reached: false,
            delivery_threshold_reached: false,
            participants: Vec::new(),
            payload: None,
        }
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
enum BroadcastRound<T> {
    /// (Initiator, Data, Participants)
    Init(PublicKeyBytes, T, Vec<PublicKeyBytes>),
    /// Sender, Hash
    Echo(PublicKeyBytes, Sha512HashBytes),
    /// Sender, Hash
    Ready(PublicKeyBytes, Sha512HashBytes),
}
/// Start a reliable broadcast and participate in it
async fn broadcast_init<T: Data>(
    iface: &Interface<BroadcastRound<T>>,
    recipients: Vec<PublicKeyBytes>,
    data: T,
    msg_link_id: MsgLinkId,
) -> Result<T, String> {
    let msg = BroadcastRound::Init(*iface.public_key(), data.clone(), recipients.clone());
    let (sig, hash) = iface.get_sig_and_hash(&data, *iface.public_key(), &recipients, msg_link_id);
    for rcvr in recipients.iter() {
        iface
            .send_msg(
                rcvr,
                &msg,
                msg_link_id,
                //signature
            )
            .await;
    }
    // need to set up init state here because iniator wont receive init RPC (from himself)
    let mut bcast_instance = BcastInstance::new();
    bcast_instance.participants = recipients;
    bcast_instance.payload = Some(data);
    // Send out echo
    let echo_msg: BroadcastRound<T> = BroadcastRound::Echo(*iface.public_key(), hash);
    for participant in bcast_instance.participants.iter() {
        if participant == iface.public_key() {
            continue;
        }
        iface.send_msg(participant, &echo_msg, msg_link_id).await;
    }
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
    while let Some(msg) = rx.recv().await {
        match msg.data {
            BroadcastRound::Init(_, data, participants) => {
                let hash = canonical_bytes(&data);
                bcast_instance.participants = participants;
                bcast_instance.payload = Some(data);

                // Send out echo
                let echo_msg: BroadcastRound<T> =
                    BroadcastRound::Echo(*iface.public_key(), hash.clone());
                for participant in bcast_instance.participants.iter() {
                    if participant == iface.public_key() {
                        continue;
                    }
                    iface.send_msg(participant, &echo_msg, msg_link_id).await;
                }

                // check for quorums reached on messages received before processing Init
                // send out Ready if quorum is reached
                if let Some(&echo_count) = bcast_instance.hash_echo_count.get(&hash) {
                    if echo_count >= bcast_instance.echo_to_ready_threshold() {
                        bcast_instance.echo_threshold_reached = true;
                        send_ready(&mut bcast_instance, iface, hash.clone(), msg_link_id).await;
                    }
                }
                // Send Ready amp and deliver message if quorum is reached
                if let Some(&ready_count) = bcast_instance.hash_ready_count.get(&hash) {
                    if ready_count >= bcast_instance.ready_amp_threshold() {
                        send_ready(&mut bcast_instance, iface, hash, msg_link_id).await;
                    }

                    if ready_count >= bcast_instance.delivery_threshold() {
                        return bcast_instance
                            .payload
                            .ok_or("No payload initiated".to_string());
                    }
                }
            }
            BroadcastRound::Echo(_sender, init_hash) => {
                // Skip all counting logic if we've already sent out Ready
                if bcast_instance.is_ready_msg_sent {
                    continue;
                }
                count_echo(&mut bcast_instance, iface, init_hash.clone(), msg_link_id).await;
                if bcast_instance.echo_threshold_reached {
                    send_ready(&mut bcast_instance, iface, init_hash, msg_link_id).await;
                }
            }
            BroadcastRound::Ready(_sender, hash) => {
                count_ready(&mut bcast_instance, hash.clone()).await;
                // Check to see if I should send out Ready amplification
                if bcast_instance.ready_amp_threshold_reached {
                    // Dont send Ready message if already sent
                    if !bcast_instance.is_ready_msg_sent {
                        send_ready(&mut bcast_instance, iface, hash, msg_link_id).await;
                    }
                }
                if bcast_instance.delivery_threshold_reached {
                    drop(rx);
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
async fn send_ready<T: Data>(
    bcast_instance: &mut BcastInstance<T>,
    iface: &Interface<BroadcastRound<T>>,
    hash: Sha512HashBytes,
    msg_link_id: MsgLinkId,
) {
    let rdy_msg = BroadcastRound::Ready(*iface.public_key(), hash);
    let participants = bcast_instance.participants.clone();
    let iface_clone = iface.clone();
    tokio::task::spawn(async move {
        for participant in participants {
            if participant == *iface_clone.public_key() {
                continue;
            }
            let rdy_msg_clone = rdy_msg.clone();
            iface_clone
                .send_msg(&participant, &rdy_msg_clone, msg_link_id)
                .await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
    bcast_instance.is_ready_msg_sent = true;
}
async fn count_echo<T: Data>(
    bcast_instance: &mut BcastInstance<T>,
    iface: &Interface<BroadcastRound<T>>,
    hash: Sha512HashBytes,
    msg_link_id: MsgLinkId,
) {
    let num_hashes = bcast_instance.hash_echo_count.entry(hash).or_insert(0);
    *num_hashes += 1;
    // Can't check quorum if Init message hasnt been processed
    if bcast_instance.payload.is_none() {
        return;
    }

    // Send Ready out and mark flag to not send multiple Ready(s) out
    if *num_hashes >= bcast_instance.echo_to_ready_threshold() {
        bcast_instance.echo_threshold_reached = true;
    }
}
async fn count_ready<T: Data>(bcast_instance: &mut BcastInstance<T>, hash: Sha512HashBytes) {
    let num_hashes = bcast_instance.hash_ready_count.entry(hash).or_insert(0);
    *num_hashes += 1;
    // Can't check quorum if Init message hasnt been processed
    if bcast_instance.payload.is_none() {
        return;
    }
    let count = *num_hashes;
    // Have I reached threshold of Readys to send my own Ready
    if count >= bcast_instance.ready_amp_threshold() {
        bcast_instance.ready_amp_threshold_reached = true;
    }
    // Check to
    if count >= bcast_instance.delivery_threshold() {
        bcast_instance.delivery_threshold_reached = true;
    }
}

// mod tests {
//     use super::*;
//     use std::{sync::Arc, time::Duration};

//     #[test]
//     fn bcast_instance_new() {
//         let instance: BcastInstance<String> = BcastInstance::new();
//         assert!(instance.hash_echo_count.is_empty());
//         assert!(instance.hash_ready_count.is_empty());
//         assert!(!instance.is_ready_msg_sent);
//         assert!(!instance.delivery_threshold_reached);
//         assert!(instance.participants.is_empty());
//         assert!(instance.payload.is_none());
//     }
//     #[test]
//     fn canonical_hash_different_data() {
//         let data1 = "test_data_1".to_string();
//         let data2 = "test_data_2".to_string();
//         let hash1 = canonical_bytes(&data1);
//         let hash2 = canonical_bytes(&data2);
//         assert_ne!(hash1, hash2);
//     }
//     #[test]
//     fn broadcast_round_init_serialization() {
//         let initiator = UserId::new(100);
//         let data = "test_payload".to_string();
//         let participants = vec![UserId::new(1), UserId::new(2), UserId::new(3)];

//         let round = BroadcastRound::Init(initiator, data, participants);

//         // Test that it can be serialized and deserialized
//         let config = bincode::config::standard();
//         let encoded = bincode::serde::encode_to_vec(&round, config).unwrap();
//         let decoded: BroadcastRound<String> = bincode::serde::decode_from_slice(&encoded, config)
//             .unwrap()
//             .0;

//         match decoded {
//             BroadcastRound::Init(init, payload, parts) => {
//                 assert_eq!(init, initiator);
//                 assert_eq!(payload, "test_payload");
//                 assert_eq!(parts.len(), 3);
//             }
//             _ => panic!("Wrong variant"),
//         }
//     }

//     #[tokio::test]
//     async fn broadcast_standard_four_nodes_happy_path() {
//         // Set up 4 nodes and verify they can complete a basic broadcast
//         let iface0: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
//         let iface1: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
//         let iface2: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
//         let iface3: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;

//         let user0 = iface0.pubkey;
//         let user1 = iface1.pubkey;
//         let user2 = iface2.pubkey;
//         let user3 = iface3.pubkey;

//         // Each node needs to know about all the others
//         for iface in [&iface0, &iface1, &iface2, &iface3].iter() {
//             iface.add_addr(user0, iface0.addr).await;
//             iface.add_addr(user1, iface1.addr).await;
//             iface.add_addr(user2, iface2.addr).await;
//             iface.add_addr(user3, iface3.addr).await;
//         }

//         let msg_link_id = MsgLinkId::new(100);
//         let broadcast_data = "Important broadcast message".to_string();
//         let participants = vec![user0, user1, user2, user3];

//         // Node 0 starts the broadcast
//         let data_clone = broadcast_data.clone();
//         let participants_clone = participants.clone();
//         let iface0_clone = iface0.clone();
//         let initiator_task = tokio::spawn(async move {
//             broadcast_init(&*iface0, participants_clone, data_clone, msg_link_id).await
//         });
//         println!("{:?} sent init", iface0_clone.pubkey);

//         // The other nodes participate
//         let participant1_task =
//             tokio::spawn(
//                 async move { participate_in_broadcast(&*iface1, None, msg_link_id).await },
//             );

//         let participant2_task =
//             tokio::spawn(
//                 async move { participate_in_broadcast(&*iface2, None, msg_link_id).await },
//             );

//         let participant3_task =
//             tokio::spawn(
//                 async move { participate_in_broadcast(&*iface3, None, msg_link_id).await },
//             );

//         let timeout_duration = Duration::from_secs(5);

//         let result0 = tokio::time::timeout(timeout_duration, initiator_task)
//             .await
//             .expect("Node 0 timed out")
//             .expect("Node 0 task panicked")
//             .expect("Node 0 broadcast failed");

//         let result1 = tokio::time::timeout(timeout_duration, participant1_task)
//             .await
//             .expect("Node 1 timed out")
//             .expect("Node 1 task panicked")
//             .expect("Node 1 broadcast failed");

//         let result2 = tokio::time::timeout(timeout_duration, participant2_task)
//             .await
//             .expect("Node 2 timed out")
//             .expect("Node 2 task panicked")
//             .expect("Node 2 broadcast failed");

//         let result3 = tokio::time::timeout(timeout_duration, participant3_task)
//             .await
//             .expect("Node 3 timed out")
//             .expect("Node 3 task panicked")
//             .expect("Node 3 broadcast failed");

//         // Check that everyone got the same message
//         assert_eq!(result0, broadcast_data);
//         assert_eq!(result1, broadcast_data);
//         assert_eq!(result2, broadcast_data);
//         assert_eq!(result3, broadcast_data);

//         println!("All 4 nodes completed the broadcast successfully");
//         println!("Everyone delivered: '{}'", broadcast_data);
//     }

//     #[tokio::test]
//     async fn broadcast_messages_arrive_out_of_order() {
//         // Make sure the protocol handles messages arriving in the wrong order.
//         // We'll send an Echo before the Init arrives and verify everything still works.

//         let iface0: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
//         let iface1: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
//         let iface2: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
//         let iface3: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;

//         let user0 = iface0.pubkey;
//         let user1 = iface1.pubkey;
//         let user2 = iface2.pubkey;
//         let user3 = iface3.pubkey;

//         for iface in [&iface0, &iface1, &iface2, &iface3].iter() {
//             iface.add_addr(user0, iface0.addr).await;
//             iface.add_addr(user1, iface1.addr).await;
//             iface.add_addr(user2, iface2.addr).await;
//             iface.add_addr(user3, iface3.addr).await;
//         }

//         let msg_link_id = MsgLinkId::new(200);
//         let broadcast_data = "Out of order test message".to_string();
//         let participants = vec![user0, user1, user2, user3];

//         // Send an Echo message to node 1 before the Init arrives
//         let data_hash = canonical_bytes(&broadcast_data);
//         let early_echo = BroadcastRound::Echo(user2, data_hash);

//         iface2.send_msg(&user1, &early_echo, msg_link_id).await;

//         // Give the early message time to arrive
//         tokio::time::sleep(Duration::from_millis(50)).await;

//         // Now actually start the broadcast
//         let data_clone = broadcast_data.clone();
//         let participants_clone = participants.clone();
//         let initiator_task = tokio::spawn(async move {
//             broadcast_init(&*iface0, participants_clone, data_clone, msg_link_id).await
//         });

//         let iface1_clone = iface1.clone();
//         let participant1_task = tokio::spawn(async move {
//             participate_in_broadcast(&iface1_clone, None, msg_link_id).await
//         });

//         let iface2_clone = iface2.clone();
//         let participant2_task = tokio::spawn(async move {
//             participate_in_broadcast(&iface2_clone, None, msg_link_id).await
//         });

//         let iface3_clone = iface3.clone();
//         let participant3_task = tokio::spawn(async move {
//             participate_in_broadcast(&iface3_clone, None, msg_link_id).await
//         });

//         let timeout_duration = Duration::from_secs(5);

//         let result0 = tokio::time::timeout(timeout_duration, initiator_task)
//             .await
//             .expect("Node 0 timed out")
//             .expect("Node 0 task panicked")
//             .expect("Node 0 broadcast failed");

//         let result1 = tokio::time::timeout(timeout_duration, participant1_task)
//             .await
//             .expect("Node 1 timed out")
//             .expect("Node 1 task panicked")
//             .expect("Node 1 broadcast failed");

//         let result2 = tokio::time::timeout(timeout_duration, participant2_task)
//             .await
//             .expect("Node 2 timed out")
//             .expect("Node 2 task panicked")
//             .expect("Node 2 broadcast failed");

//         let result3 = tokio::time::timeout(timeout_duration, participant3_task)
//             .await
//             .expect("Node 3 timed out")
//             .expect("Node 3 task panicked")
//             .expect("Node 3 broadcast failed");

//         // Despite the ordering issue, everyone should still get the right message
//         assert_eq!(result0, broadcast_data);
//         assert_eq!(result1, broadcast_data);
//         assert_eq!(result2, broadcast_data);
//         assert_eq!(result3, broadcast_data);

//         println!("Broadcast worked correctly even with out-of-order messages");
//         println!("Node 1 buffered the early Echo and processed it after Init arrived");
//     }

//     #[tokio::test]
//     async fn broadcast_stress_test_many_concurrent_broadcasts() {
//         // Run a lot of broadcasts at once to stress test the system.
//         // 10 nodes each starting 5 broadcasts = 50 total concurrent broadcasts.

//         const NUM_NODES: usize = 10;
//         const BROADCASTS_PER_NODE: usize = 4;

//         println!(
//             "Starting stress test: {} nodes, {} broadcasts per node, {} total",
//             NUM_NODES,
//             BROADCASTS_PER_NODE,
//             NUM_NODES * BROADCASTS_PER_NODE
//         );

//         // Create all the nodes
//         let mut interfaces = Vec::new();
//         let mut user_ids = Vec::new();

//         for _ in 0..NUM_NODES {
//             let iface: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
//             user_ids.push(iface.pubkey);
//             interfaces.push(iface);
//         }

//         // Set up address books so everyone knows everyone
//         println!("Setting up address books...");
//         for iface in interfaces.iter() {
//             for (idx, user_id) in user_ids.iter().enumerate() {
//                 iface.add_addr(*user_id, interfaces[idx].addr).await;
//             }
//         }

//         let mut all_tasks = Vec::new();

//         println!(
//             "Launching {} broadcasts...",
//             NUM_NODES * BROADCASTS_PER_NODE
//         );

//         for initiator_idx in 0..NUM_NODES {
//             for broadcast_num in 0..BROADCASTS_PER_NODE {
//                 let msg_link_id =
//                     MsgLinkId::new((initiator_idx * BROADCASTS_PER_NODE + broadcast_num) as u128);
//                 let broadcast_data = format!("Node_{}_Broadcast_{}", initiator_idx, broadcast_num);
//                 let participants = user_ids.clone();

//                 // Start the initiator task
//                 let iface = interfaces[initiator_idx].clone();
//                 let data_clone = broadcast_data.clone();
//                 let participants_clone = participants.clone();

//                 let initiator_task = tokio::spawn(async move {
//                     broadcast_init(&*iface, participants_clone, data_clone.clone(), msg_link_id)
//                         .await
//                         .map(|result| (msg_link_id, initiator_idx, result))
//                 });
//                 all_tasks.push(initiator_task);

//                 // Start participant tasks for all other nodes
//                 for participant_idx in 0..NUM_NODES {
//                     if participant_idx == initiator_idx {
//                         continue;
//                     }

//                     let iface_clone = interfaces[participant_idx].clone();

//                     let participant_task = tokio::spawn(async move {
//                         participate_in_broadcast(&iface_clone, None, msg_link_id)
//                             .await
//                             .map(|result| (msg_link_id, participant_idx, result))
//                     });
//                     all_tasks.push(participant_task);
//                 }
//             }
//         }

//         println!("Waiting for {} tasks to complete...", all_tasks.len());

//         let timeout_duration = Duration::from_secs(30);
//         let start_time = std::time::Instant::now();

//         let mut completed = 0;
//         let mut failed = 0;
//         let mut results_by_msg_id: HashMap<MsgLinkId, Vec<String>> = HashMap::new();

//         for (idx, task) in all_tasks.into_iter().enumerate() {
//             match tokio::time::timeout(timeout_duration, task).await {
//                 Ok(Ok(Ok((msg_id, _node_idx, data)))) => {
//                     completed += 1;
//                     results_by_msg_id
//                         .entry(msg_id)
//                         .or_insert_with(Vec::new)
//                         .push(data);

//                     if completed % 50 == 0 {
//                         println!("  {} tasks completed so far...", completed);
//                     }
//                 }
//                 Ok(Ok(Err(e))) => {
//                     failed += 1;
//                     eprintln!("  Task {} failed with error: {}", idx, e);
//                 }
//                 Ok(Err(e)) => {
//                     failed += 1;
//                     eprintln!("  Task {} panicked: {:?}", idx, e);
//                 }
//                 Err(_) => {
//                     failed += 1;
//                     eprintln!("  Task {} timed out", idx);
//                 }
//             }
//         }

//         let elapsed = start_time.elapsed();

//         println!("\nStress test results:");
//         println!("  Total time: {:?}", elapsed);
//         println!("  Completed: {}", completed);
//         println!("  Failed: {}", failed);
//         println!("  Unique broadcasts: {}", results_by_msg_id.len());

//         // Check that all nodes agreed on each broadcast
//         let mut consensus_verified = 0;
//         for (msg_id, results) in results_by_msg_id.iter() {
//             if !results.is_empty() {
//                 let first_result = &results[0];
//                 let all_agree = results.iter().all(|r| r == first_result);

//                 if all_agree {
//                     consensus_verified += 1;
//                 } else {
//                     eprintln!(
//                         "  Warning: MsgLinkId {:?} had disagreement: {:?}",
//                         msg_id, results
//                     );
//                 }
//             }
//         }

//         println!(
//             "  Consensus verified: {}/{}",
//             consensus_verified,
//             results_by_msg_id.len()
//         );

//         assert_eq!(failed, 0, "No tasks should fail");
//         assert_eq!(
//             results_by_msg_id.len(),
//             NUM_NODES * BROADCASTS_PER_NODE,
//             "Should have results for all broadcasts"
//         );
//         assert_eq!(
//             consensus_verified,
//             NUM_NODES * BROADCASTS_PER_NODE,
//             "All broadcasts should reach consensus"
//         );

//         println!(
//             "\nStress test passed! All {} broadcasts completed successfully",
//             NUM_NODES * BROADCASTS_PER_NODE
//         );
//     }

//     #[tokio::test]
//     async fn broadcast_large_number_of_honest_recipients() {
//         // Test a single broadcast with many honest recipients to verify
//         // the protocol scales correctly with participant count

//         const NUM_NODES: usize = 10;

//         println!("Testing broadcast with {} honest nodes", NUM_NODES);

//         // Create all the nodes
//         let mut interfaces = Vec::new();
//         let mut user_ids = Vec::new();

//         for _ in 0..NUM_NODES {
//             let iface: Arc<Interface<BroadcastRound<String>>> = Interface::new("127.0.0.1:0").await;
//             user_ids.push(iface.pubkey);
//             interfaces.push(iface);
//         }

//         // Set up address books
//         println!("Setting up address books for {} nodes...", NUM_NODES);
//         for iface in interfaces.iter() {
//             for (idx, user_id) in user_ids.iter().enumerate() {
//                 iface.add_addr(*user_id, interfaces[idx].addr).await;
//             }
//         }

//         let msg_link_id = MsgLinkId::new(500);
//         let broadcast_data = "msg".to_string();
//         let participants = user_ids.clone();

//         println!("Starting broadcast from node 0 to {} recipients", NUM_NODES);

//         // Node 0 initiates
//         let iface0 = interfaces[0].clone();
//         let data_clone = broadcast_data.clone();
//         let participants_clone = participants.clone();
//         let initiator_task = tokio::spawn(async move {
//             broadcast_init(&*iface0, participants_clone, data_clone, msg_link_id).await
//         });

//         // All other nodes participate
//         let mut participant_tasks = Vec::new();
//         for i in 1..NUM_NODES {
//             let iface = interfaces[i].clone();
//             let task =
//                 tokio::spawn(
//                     async move { participate_in_broadcast(&iface, None, msg_link_id).await },
//                 );
//             participant_tasks.push(task);
//         }

//         println!("Waiting for all {} nodes to complete...", NUM_NODES);

//         let timeout_duration = Duration::from_secs(10);

//         // Check initiator
//         let result0 = tokio::time::timeout(timeout_duration, initiator_task)
//             .await
//             .expect("Node 0 timed out")
//             .expect("Node 0 task panicked")
//             .expect("Node 0 broadcast failed");

//         assert_eq!(result0, broadcast_data);
//         println!("initiator checked");

//         // Check all participants
//         let mut successful = 1; // Count initiator
//         for (idx, task) in participant_tasks.into_iter().enumerate() {
//             let pubkey = interfaces[idx + 1].pubkey;
//             println!("checking node {pubkey:?}");
//             match tokio::time::timeout(timeout_duration, task).await {
//                 Ok(Ok(Ok(result))) => {
//                     assert_eq!(result, broadcast_data);
//                     successful += 1;
//                 }
//                 Ok(Ok(Err(e))) => {
//                     eprintln!("Node {:?} failed: {}", pubkey, e);
//                 }
//                 Ok(Err(e)) => {
//                     eprintln!("Node {:?} panicked: {:?}", pubkey, e);
//                 }
//                 Err(_) => {
//                     eprintln!("Node {:?} timed out", pubkey);
//                 }
//             }
//         }

//         println!(
//             "Successfully delivered to {}/{} nodes",
//             successful, NUM_NODES
//         );
//         println!("Quorum was: {}", (NUM_NODES / 2) + 1);

//         assert_eq!(
//             successful, NUM_NODES,
//             "All nodes should successfully deliver"
//         );

//         println!("Large scale broadcast test passed");
//     }
// }
