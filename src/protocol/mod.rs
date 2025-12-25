use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::{PrivateKey, PublicKeyBytes, Sha512HashBytes, Signature, canonical_bytes};
use crate::network::{Data, Interface, MsgLink, MsgLinkId, Registry};

/// Protocol-aware wrapper around Interface that handles signing and identity
pub struct ProtocolNode<T> {
    interface: Arc<Interface<BroadcastRound<T>>>,
    private_key: Arc<PrivateKey>,
    public_key: PublicKeyBytes,
}

impl<T: Data> ProtocolNode<T> {
    pub async fn new(addr: impl tokio::net::ToSocketAddrs, private_key: PrivateKey) -> Arc<Self> {
        let public_key = private_key.to_public_key().to_bytes();
        let interface = Interface::new(addr).await;

        Arc::new(Self {
            interface,
            private_key: Arc::new(private_key),
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

    pub async fn add_addr(&self, pubkey: crate::crypto::PublicKey, addr: std::net::SocketAddr) {
        self.interface.add_addr(pubkey, addr).await;
    }

    fn get_sig_and_hash<S: serde::Serialize>(
        &self,
        data: &S,
        initiator: PublicKeyBytes,
        participants: &Vec<PublicKeyBytes>,
        msg_link_id: MsgLinkId,
    ) -> (Signature, Sha512HashBytes) {
        self.private_key
            .get_sig_and_hash(data, initiator, participants, msg_link_id)
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
        let msg = BroadcastRound::Init(*self.public_key(), data.clone(), recipients.clone());
        let (_sig, hash) =
            self.get_sig_and_hash(&data, *self.public_key(), &recipients, msg_link_id);

        for rcvr in recipients.iter() {
            self.send_msg(rcvr, &msg, msg_link_id).await;
        }

        // need to set up init state here because initiator wont receive init RPC (from himself)
        let mut bcast_instance = BcastInstance::new();
        bcast_instance.participants = recipients;
        bcast_instance.payload = Some(data);

        // Send out echo
        let echo_msg: BroadcastRound<T> = BroadcastRound::Echo(*self.public_key(), hash);
        for participant in bcast_instance.participants.iter() {
            if participant == self.public_key() {
                continue;
            }
            self.send_msg(participant, &echo_msg, msg_link_id).await;
        }

        self.participate_in_broadcast(Some(bcast_instance), msg_link_id)
            .await
    }

    /// Participate as a recipient of a reliable broadcast
    pub async fn participate_in_broadcast(
        &self,
        bcast_instance: Option<BcastInstance<T>>,
        msg_link_id: MsgLinkId,
    ) -> Result<T, String> {
        let mut rx = self.registry().subscribe(msg_link_id).await.unwrap();
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
                        BroadcastRound::Echo(*self.public_key(), hash.clone());
                    for participant in bcast_instance.participants.iter() {
                        if participant == self.public_key() {
                            continue;
                        }
                        self.send_msg(participant, &echo_msg, msg_link_id).await;
                    }

                    // check for quorums reached on messages received before processing Init
                    // send out Ready if quorum is reached
                    if let Some(&echo_count) = bcast_instance.hash_echo_count.get(&hash) {
                        if echo_count >= bcast_instance.echo_to_ready_threshold() {
                            bcast_instance.echo_threshold_reached = true;
                            self.send_ready(&mut bcast_instance, hash.clone(), msg_link_id)
                                .await;
                        }
                    }

                    // Send Ready amp and deliver message if quorum is reached
                    if let Some(&ready_count) = bcast_instance.hash_ready_count.get(&hash) {
                        if ready_count >= bcast_instance.ready_amp_threshold() {
                            self.send_ready(&mut bcast_instance, hash, msg_link_id)
                                .await;
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
                    self.count_echo(&mut bcast_instance, init_hash.clone(), msg_link_id)
                        .await;
                    if bcast_instance.echo_threshold_reached {
                        self.send_ready(&mut bcast_instance, init_hash, msg_link_id)
                            .await;
                    }
                }
                BroadcastRound::Ready(_sender, hash) => {
                    Self::count_ready(&mut bcast_instance, hash.clone()).await;
                    // Check to see if I should send out Ready amplification
                    if bcast_instance.ready_amp_threshold_reached {
                        // Dont send Ready message if already sent
                        if !bcast_instance.is_ready_msg_sent {
                            self.send_ready(&mut bcast_instance, hash, msg_link_id)
                                .await;
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

        drop(rx);
        Err("no".to_string())
    }

    async fn send_ready(
        &self,
        bcast_instance: &mut BcastInstance<T>,
        hash: Sha512HashBytes,
        msg_link_id: MsgLinkId,
    ) {
        let rdy_msg = BroadcastRound::Ready(*self.public_key(), hash);
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
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        bcast_instance.is_ready_msg_sent = true;
    }

    async fn count_echo(
        &self,
        bcast_instance: &mut BcastInstance<T>,
        hash: Sha512HashBytes,
        _msg_link_id: MsgLinkId,
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

    async fn count_ready(bcast_instance: &mut BcastInstance<T>, hash: Sha512HashBytes) {
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
}

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
pub enum BroadcastRound<T> {
    /// (Initiator, Data, Participants)
    Init(PublicKeyBytes, T, Vec<PublicKeyBytes>),
    /// Sender, Hash
    Echo(PublicKeyBytes, Sha512HashBytes),
    /// Sender, Hash
    Ready(PublicKeyBytes, Sha512HashBytes),
}
