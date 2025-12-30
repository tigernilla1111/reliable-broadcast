// Basic example demonstrating Byzantine Reliable Broadcast
// Run with: cargo run --example basic_broadcast

use reliable_broadcast::{crypto::PrivateKey, network::MsgLinkId, protocol::ProtocolNode};
use std::sync::Arc;
use tokio::time::Duration;

#[tokio::main]
async fn main() {
    // Initialize tracing for logs
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== Byzantine Reliable Broadcast Example ===\n");

    // Create 4 nodes with unique identities
    println!("Creating 4 nodes...");
    let node0: Arc<ProtocolNode<String>> =
        ProtocolNode::new("127.0.0.1:8000", PrivateKey::new()).await;
    let node1: Arc<ProtocolNode<String>> =
        ProtocolNode::new("127.0.0.1:8001", PrivateKey::new()).await;
    let node2: Arc<ProtocolNode<String>> =
        ProtocolNode::new("127.0.0.1:8002", PrivateKey::new()).await;
    let node3: Arc<ProtocolNode<String>> =
        ProtocolNode::new("127.0.0.1:8003", PrivateKey::new()).await;

    let pubkey0 = *node0.public_key();
    let pubkey1 = *node1.public_key();
    let pubkey2 = *node2.public_key();
    let pubkey3 = *node3.public_key();

    println!("Node 0: {:?}", pubkey0);
    println!("Node 1: {:?}", pubkey1);
    println!("Node 2: {:?}", pubkey2);
    println!("Node 3: {:?}", pubkey3);

    // Set up address books so all nodes know each other
    println!("\nSetting up address books...");
    for node in [&node0, &node1, &node2, &node3] {
        node.add_addr(pubkey0, node0.addr()).await;
        node.add_addr(pubkey1, node1.addr()).await;
        node.add_addr(pubkey2, node2.addr()).await;
        node.add_addr(pubkey3, node3.addr()).await;
    }

    let msg_link_id = MsgLinkId::new(1);
    let broadcast_data =
        "Hello from Node 0! This message will be reliably broadcast to all nodes.".to_string();
    let participants = vec![pubkey0, pubkey1, pubkey2, pubkey3];

    println!("\n=== Starting Broadcast ===");
    println!("Initiator: Node 0");
    println!("Message: \"{}\"", broadcast_data);
    println!("Participants: 4 nodes");
    println!("\nPhase 1: Node 0 sends Init message...");

    // Node 0 initiates the broadcast
    let node0_clone = node0.clone();
    let data_clone = broadcast_data.clone();
    let participants_clone = participants.clone();
    let initiator_task = tokio::spawn(async move {
        let result = node0_clone
            .broadcast_init(participants_clone, data_clone, msg_link_id)
            .await;
        println!("Node 0: ✓ Delivered!");
        result
    });

    // Give initiator a head start
    tokio::time::sleep(Duration::from_millis(50)).await;

    println!("Phase 2: Participants send Echo messages...");

    // Other nodes participate
    let node1_clone = node1.clone();
    let participant1_task = tokio::spawn(async move {
        let result = node1_clone.participate_in_broadcast(msg_link_id).await;
        println!("Node 1: ✓ Delivered!");
        result
    });

    let node2_clone = node2.clone();
    let participant2_task = tokio::spawn(async move {
        let result = node2_clone.participate_in_broadcast(msg_link_id).await;
        println!("Node 2: ✓ Delivered!");
        result
    });

    let node3_clone = node3.clone();
    let participant3_task = tokio::spawn(async move {
        let result = node3_clone.participate_in_broadcast(msg_link_id).await;
        println!("Node 3: ✓ Delivered!");
        result
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    println!("Phase 3: Nodes send Ready messages...");
    println!("Phase 4: Waiting for delivery threshold...\n");

    // Wait for all nodes to complete
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
    println!("=== Results ===");
    println!("Node 0 received: \"{}\"", result0);
    println!("Node 1 received: \"{}\"", result1);
    println!("Node 2 received: \"{}\"", result2);
    println!("Node 3 received: \"{}\"", result3);

    assert_eq!(result0, broadcast_data);
    assert_eq!(result1, broadcast_data);
    assert_eq!(result2, broadcast_data);
    assert_eq!(result3, broadcast_data);

    println!("\n✓ SUCCESS: All nodes delivered the same message!");
    println!("Byzantine Reliable Broadcast completed successfully.");
}
