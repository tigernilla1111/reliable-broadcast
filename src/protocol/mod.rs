use crate::network::{Interface, MsgLinkData, RoundNum};
use crate::types::{LedgerDiff, Signature, UserId};
/// Start a reliable broadcast
async fn broadcast_init(
    iface: Interface,
    recipients: Vec<UserId>,
    msg_data: Vec<LedgerDiff>,
    round_num: RoundNum,
) {
    let sig: Signature = "sign(msg_data||msg_link_id||SEND)".to_string();
    let data = MsgLinkData::Send(sig, msg_data);
    for rcvr in recipients.iter() {
        iface.send_msg(rcvr, data.clone(), round_num).await;
    }
}

async fn broadcast(
    iface: Interface,
    recipients: Vec<UserId>,
    msg_data: MsgLinkData,
    round_num: RoundNum,
) {
    for rcvr in recipients.iter() {
        iface.send_msg(rcvr, msg_data.clone(), round_num).await;
    }
}

// TODO: turn this into a reliable broadcast crate
// - instead of LedgerDiff, allow it to be generic over some value T
// - do the same with DirectMessage
// - use msglinkid instead of RoundNum.  A reliable broadcast instance
//   does not need to be tied to any notion of the blockchain.  It could be used that way
//   but this makes usage of it in the future more generic
