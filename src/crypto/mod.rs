use crate::network::MsgLinkId;
use bincode::serde::encode_to_vec;
use ed25519_dalek::Verifier;
use ed25519_dalek::ed25519::signature::Signer;
use rand_core::OsRng;
use serde_bytes;
use sha2::{Digest, Sha512, digest::OutputSizeUser};
use thiserror;

const MAX_ENCODING_BYTES: usize = 10000;
const SHA512_OUTPUT_BYTES: usize = 64;
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid signature from {0:?}")]
    InvalidSignature(PublicKeyBytes),

    #[error("unconstructable public key {0:?}")]
    InvalidPublicKey(PublicKeyBytes),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Hash)]
pub struct HashBytes(#[serde(with = "serde_bytes")] [u8; SHA512_OUTPUT_BYTES]);

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct SignatureBytes(#[serde(with = "serde_bytes")] [u8; ed25519_dalek::SIGNATURE_LENGTH]);
impl SignatureBytes {
    fn to_signature(&self) -> ed25519_dalek::Signature {
        ed25519_dalek::Signature::from_bytes(&self.0)
    }
}
#[derive(serde::Deserialize, serde::Serialize, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct PublicKeyBytes([u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);
impl PublicKeyBytes {
    fn to_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0).unwrap()
    }
}

pub fn verify_init<T: serde::Serialize>(
    sig: &SignatureBytes,
    data: &T,
    initiator_bytes: PublicKeyBytes,
    participants: &Vec<PublicKeyBytes>,
    msg_link_id: MsgLinkId,
) -> Result<HashBytes, ()> {
    let hasher = init_msg_hasher(&data, initiator_bytes, participants, msg_link_id);
    let sig = sig.to_signature();
    let pubkey = initiator_bytes.to_verifying_key();
    pubkey
        .verify_prehashed(hasher.clone(), None, &sig)
        .map(|_| HashBytes(hasher.finalize().into()))
        .map_err(|_| ())
}

pub fn verify_echo(
    sender: PublicKeyBytes,
    init_msg_hash: HashBytes,
    msg_link_id: MsgLinkId,
    signature: SignatureBytes,
) -> Result<(), ()> {
    let bytes = canonical_echo_bytes(sender, init_msg_hash, msg_link_id);
    let signature = signature.to_signature();
    sender
        .to_verifying_key()
        .verify(&bytes, &signature)
        .map_err(|_| ())
}

pub fn verify_ready(
    sender: PublicKeyBytes,
    init_msg_hash: HashBytes,
    msg_link_id: MsgLinkId,
    signature: SignatureBytes,
) -> Result<(), ()> {
    let bytes = canonical_ready_bytes(sender, init_msg_hash, msg_link_id);
    let signature = signature.to_signature();
    sender
        .to_verifying_key()
        .verify(&bytes, &signature)
        .map_err(|_| ())
}

pub struct PrivateKey(ed25519_dalek::SigningKey);
impl PrivateKey {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        Self(ed25519_dalek::SigningKey::generate(&mut csprng))
    }
    pub fn to_public_key(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.0.verifying_key().to_bytes())
    }
    pub fn sig_and_hash<T: serde::Serialize>(
        &self,
        data: &T,
        initiator: PublicKeyBytes,
        participants: &Vec<PublicKeyBytes>,
        msg_link_id: MsgLinkId,
    ) -> (SignatureBytes, HashBytes) {
        let hasher = init_msg_hasher(&data, initiator, participants, msg_link_id);
        let signature = SignatureBytes(
            self.0
                .sign_prehashed(hasher.clone(), None)
                .unwrap()
                .to_bytes(),
        );
        (signature, HashBytes(hasher.finalize().into()))
    }
    pub fn sign_echo(&self, init_msg_hash: HashBytes, msg_link_id: MsgLinkId) -> SignatureBytes {
        let echo_bytes = canonical_echo_bytes(self.to_public_key(), init_msg_hash, msg_link_id);
        SignatureBytes(self.0.sign(&echo_bytes).to_bytes())
    }
    pub fn sign_ready(&self, init_msg_hash: HashBytes, msg_link_id: MsgLinkId) -> SignatureBytes {
        let ready_bytes = canonical_ready_bytes(self.to_public_key(), init_msg_hash, msg_link_id);
        SignatureBytes(self.0.sign(&ready_bytes).to_bytes())
    }
}

fn canonical_echo_bytes(
    sender: PublicKeyBytes,
    init_msg_hash: HashBytes,
    msg_link_id: MsgLinkId,
) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.append(&mut sender.0.into());
    bytes.append(&mut init_msg_hash.0.into());
    bytes.append(&mut msg_link_id.to_be_bytes().into());
    bytes.append(&mut "ECHO".as_bytes().into());
    bytes
}
fn canonical_ready_bytes(
    sender: PublicKeyBytes,
    init_msg_hash: HashBytes,
    msg_link_id: MsgLinkId,
) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.append(&mut sender.0.into());
    bytes.append(&mut init_msg_hash.0.into());
    bytes.append(&mut msg_link_id.to_be_bytes().into());
    bytes.append(&mut "READY".as_bytes().into());
    bytes
}
/// Data types that contain a HashMap or HashSet cannot be used in this function
/// They must be converted into an ordered set eg Vec or BTreeSet
fn canonical_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let config = bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_ENCODING_BYTES>();
    encode_to_vec(value, config).expect("serialization failed")
}

/// Can't use the ed25519_dalek::SigningKey.sign on the init message because we need to expose the
/// hash it produces to be signed, which can't be done with that crate.
/// So manually create the a Sha512 hash which can be fed into the sign_prehashed
fn init_msg_hasher<D: serde::Serialize>(
    data: &D,
    initiator: PublicKeyBytes,
    participants: &Vec<PublicKeyBytes>,
    msg_link_id: MsgLinkId,
) -> Sha512 {
    let mut hasher = Sha512::new();
    hasher.update(canonical_bytes(&data));
    hasher.update(initiator.0);
    for participant in participants {
        hasher.update(participant.0);
    }
    hasher.update(msg_link_id.to_be_bytes());
    hasher
}

pub fn init_msg_hash<D: serde::Serialize>(
    data: &D,
    initiator: PublicKeyBytes,
    participants: &Vec<PublicKeyBytes>,
    msg_link_id: MsgLinkId,
) -> HashBytes {
    HashBytes(
        init_msg_hasher(data, initiator, participants, msg_link_id)
            .finalize()
            .into(),
    )
}
