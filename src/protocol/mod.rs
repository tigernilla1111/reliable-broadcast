use std::net::SocketAddr;

use bincode::serde::encode_to_vec;
use sha2::{Digest, Sha256};

use crate::network::{Data, Interface, MsgLinkId};
use crate::types::{LedgerDiff, Signature, UserId};

const MAX_ENCODING_BYTES: usize = 10000;

#[derive(Clone, serde::Deserialize, serde::Serialize, Debug)]
enum BroadcastRound<T> {
    Init(MsgLinkId, T),
    Echo(MsgLinkId, [u8; 32]),
    Ready(MsgLinkId, [u8; 32]),
}
/// Start a reliable broadcast
async fn broadcast_init<T: Data>(
    iface: Interface<BroadcastRound<T>>,
    recipients: Vec<SocketAddr>,
    data: T,
    msg_link_id: MsgLinkId,
) {
    let data = BroadcastRound::Init(msg_link_id, data);
    let sig: Signature = "sign(msg_data||msg_link_id||SEND)".to_string();
    for rcvr in recipients.iter() {
        iface.send_msg(rcvr, data.clone(), msg_link_id).await;
    }
    let mut rx = iface.registry.subscribe(msg_link_id).await.unwrap();
    while let Some(msg) = rx.recv().await {
        match msg.data {
            BroadcastRound::Init(_, _) => {}
            BroadcastRound::Echo(_, _) => {}
            BroadcastRound::Ready(_, _) => {}
        }
    }
}

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
