use std::collections::HashMap;
use std::net::SocketAddr;
use std::u8;

use bincode::serde::encode_to_vec;
use sha2::{Digest, Sha256};

use crate::network::{Data, Interface, MsgLink, MsgLinkId};
use crate::types::{LedgerDiff, Signature, UserId};

const MAX_ENCODING_BYTES: usize = 10000;
type DataHashOutput = [u8; 32];

struct BcastState<T> {
    instances: HashMap<MsgLinkId, BcastInstance<T>>,
}
struct BcastInstance<T> {
    intiator: UserId,
    /// includes the initiator
    participants: Vec<UserId>,
    payload: T,
    /// How many Echo received for a specific hash
    hash_echo_count: HashMap<DataHashOutput, usize>,
    /// How may Ready messages received for a specific hash
    hash_ready_count: HashMap<DataHashOutput, usize>,
    is_ready_msg_sent: bool,
}
impl<T> BcastInstance<T> {
    fn new(
        intiator: UserId,
        participants: Vec<UserId>,
        payload: T,
        //payload_hash: [u8; 32],
    ) -> Self {
        Self {
            intiator,
            participants,
            payload,
            hash_echo_count: HashMap::new(),
            hash_ready_count: HashMap::new(),
            is_ready_msg_sent: false,
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
    Echo(MsgLinkId, UserId, [u8; 32]),
    /// MsgLinkId,  Sender, Hash
    Ready(MsgLinkId, UserId, [u8; 32]),
}
/// Start a reliable broadcast
// async fn broadcast_init<T: Data>(
//     iface: Interface<BroadcastRound<T>>,
//     bcast_state: BcastState<T>,
//     recipients: Vec<SocketAddr>,
//     data: T,
//     msg_link_id: MsgLinkId,
// ) {
//     let data = BroadcastRound::Init(msg_link_id, data);
//     let sig: Signature = "sign(msg_data||msg_link_id||SEND)".to_string();
//     for rcvr in recipients.iter() {
//         iface.send_msg(rcvr, data.clone(), msg_link_id).await;
//     }
//     let mut rx = iface.registry.subscribe(msg_link_id).await.unwrap();
//     while let Some(msg) = rx.recv().await {
//         match msg.data {
//             BroadcastRound::Init(_, _) => {
//                 // do nothing here and maybe even report user because we should be
//                 panic!("should not have received an Init message if I am the intiator");
//             }
//             BroadcastRound::Echo(_, _) => {}
//             BroadcastRound::Ready(_, _) => {}
//         }
//     }
// }
/// function to run to participate as a recipient of a reliable broadcast
async fn participate_in_broadcast<T: Data>(
    iface: Interface<BroadcastRound<T>>,
    bcast_state: &mut BcastState<T>,
    msg_link_id: MsgLinkId,
) -> Result<T, String> {
    let mut rx = iface.registry.subscribe(msg_link_id).await.unwrap();
    let mut msg_queue = Vec::new();
    let mut bcast_instance: Option<BcastInstance<T>> = None;
    // To prevent double processing the init message from a malicious initiator
    // iterate through all messages until we find the init, then we can process the others
    // TODO: validate signature
    while let Some(msg) = rx.recv().await {
        if let BroadcastRound::Init(_, initiator, data, rcvd_participants) = msg.data {
            let hash = canonical_hash(&data);
            bcast_instance = Some(BcastInstance::new(initiator, rcvd_participants, data));
            // send out echo
            let echo_msg: BroadcastRound<T> = BroadcastRound::Echo(msg_link_id, iface.pubkey, hash);
            for participant in bcast_instance
                .as_ref()
                .expect("should not fail, above line sets value to Some")
                .participants
                .iter()
            {
                if participant == &iface.pubkey {
                    continue;
                }
                iface.send_msg(participant, &echo_msg, msg_link_id).await;
            }
            break;
        } else {
            msg_queue.push(msg);
        }
    }
    let Some(mut bcast_instance) = bcast_instance else {
        panic!("channel closed without receiving init");
    };
    // iterate through the queued messages
    for msg in msg_queue.iter() {
        match msg.data {
            BroadcastRound::Echo(msg_link_id, sender, hash) => {
                let num_hashes = bcast_instance.hash_echo_count.entry(hash).or_insert(0);
                *num_hashes += 1;

                // mark flag to not send multiple readies out and send Ready out
                if *num_hashes >= bcast_instance.get_quorum() && !bcast_instance.is_ready_msg_sent {
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

                if *num_hashes >= bcast_instance.get_quorum() {
                    // drop receiver
                    return Ok(bcast_instance.payload);
                }
            }
            _ => {
                panic!("should not have any more init messages to process for {msg_link_id:?}")
            }
        }
    }
    // drop receiver
    Err("no".to_string())
}

fn handle_msg_data<T>(msg: &MsgLink<BroadcastRound<T>>) {}

fn canonical_hash<T: serde::Serialize>(value: &T) -> [u8; 32] {
    let config = bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_ENCODING_BYTES>();
    let bytes = encode_to_vec(value, config).expect("serialization failed");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

// TODO: turn this into a reliable broadcast crate
// - instead of Vec of LedgerDiff, allow it to be generic over some value T
// - do the same with DirectMessage
// - use msglinkid instead of RoundNum.  A reliable broadcast instance
//   does not need to be tied to any notion of the blockchain.  It could be used that way
//   but this makes usage of it in the future more generic
