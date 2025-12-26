# Bracha's Reliable Broadcast

A Rust implementation of Bracha's Byzantine fault-tolerant broadcast protocol for distributed systems.

## What it does

This library lets nodes in a distributed network reliably broadcast messages to each other, even when some nodes might be malicious or faulty. When one node broadcasts a message, all honest nodes are guaranteed to either deliver the same message or deliver nothing at all.

## Protocol overview

The broadcast works in three phases:
1. **Init** - The initiator sends the message to all participants
2. **Echo** - Recipients echo the message hash after verifying the initiator's signature
3. **Ready** - Once enough echoes are collected, nodes broadcast ready messages and deliver when enough readys arrive

The protocol tolerates up to `t = (n-1)/3` Byzantine faults, where `n` is the total number of participants.

## Key components

- **ProtocolNode** - Main interface for participating in broadcasts
- **BroadcastRound** - Message types (Init, Echo, Ready) with cryptographic signatures
- **Interface/Registry** - Network layer handling message routing and delivery
- **Crypto** - Ed25519 signatures with SHA-512 hashing for message integrity

## Important constraints

- **Data types must be ordered** - Use `Vec` or `BTreeMap` instead of `HashMap`/`HashSet` for broadcast payloads. The signing/verification requires deterministic serialization.
- **SHA-512 requirement** - When using `ed25519_dalek` for prehashed signatures, the digest must be SHA-512 (per the Ed25519 specification).

## Example usage
```rust
// Create nodes
let node0 = ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;
let node1 = ProtocolNode::new("127.0.0.1:0", PrivateKey::new()).await;

// Set up address books
node0.add_addr(*node1.public_key(), node1.addr()).await;
node1.add_addr(*node0.public_key(), node0.addr()).await;

// Node 0 initiates broadcast
let msg_id = MsgLinkId::new(100);
let data = "Hello, world!".to_string();
let participants = vec![*node0.public_key(), *node1.public_key()];

let result = node0.broadcast_init(participants, data, msg_id).await;

// Node 1 participates
let result = node1.participate_in_broadcast(msg_id).await;
```

## Safety guarantees

- **Validity** - If an honest node broadcasts a message, all honest nodes eventually deliver it
- **Agreement** - If one honest node delivers a message, all honest nodes deliver the same message
- **Integrity** - Messages are cryptographically signed and verified at each step