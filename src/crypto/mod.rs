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
pub enum CryptoError {
    #[error("invalid signature from {0:?}")]
    InvalidSignature(PublicKeyBytes),

    #[error("invalid public key bytes {0:?}")]
    InvalidPublicKey(PublicKeyBytes),

    #[error("serialization failed")]
    Serialization,
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
    fn to_verifying_key(self) -> Result<ed25519_dalek::VerifyingKey, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|_| CryptoError::InvalidPublicKey(self))
    }
}

pub fn verify_init<T: serde::Serialize>(
    sig: &SignatureBytes,
    data: &T,
    initiator: PublicKeyBytes,
    participants: &[PublicKeyBytes],
    msg_link_id: MsgLinkId,
) -> Result<HashBytes, CryptoError> {
    let hasher = init_msg_hasher(data, initiator, participants, msg_link_id)?;

    let pubkey = initiator.to_verifying_key()?;
    pubkey
        .verify_prehashed(hasher.clone(), None, &sig.to_signature())
        .map_err(|_| CryptoError::InvalidSignature(initiator))?;

    Ok(HashBytes(hasher.finalize().into()))
}

pub fn verify_echo(
    sender: PublicKeyBytes,
    init_hash: HashBytes,
    msg_link_id: MsgLinkId,
    sig: SignatureBytes,
) -> Result<(), CryptoError> {
    let bytes = canonical_echo_bytes(sender, init_hash, msg_link_id);

    sender
        .to_verifying_key()?
        .verify(&bytes, &sig.to_signature())
        .map_err(|_| CryptoError::InvalidSignature(sender))
}

pub fn verify_ready(
    sender: PublicKeyBytes,
    init_hash: HashBytes,
    msg_link_id: MsgLinkId,
    sig: SignatureBytes,
) -> Result<(), CryptoError> {
    let bytes = canonical_ready_bytes(sender, init_hash, msg_link_id);

    sender
        .to_verifying_key()?
        .verify(&bytes, &sig.to_signature())
        .map_err(|_| CryptoError::InvalidSignature(sender))
}

pub struct PrivateKey(ed25519_dalek::SigningKey);
impl PrivateKey {
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self(ed25519_dalek::SigningKey::generate(&mut rng))
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.0.verifying_key().to_bytes())
    }

    pub fn sign_init<T: serde::Serialize>(
        &self,
        data: &T,
        initiator: PublicKeyBytes,
        participants: &[PublicKeyBytes],
        msg_link_id: MsgLinkId,
    ) -> Result<(SignatureBytes, HashBytes), CryptoError> {
        let hasher = init_msg_hasher(data, initiator, participants, msg_link_id)?;

        let sig = self
            .0
            .sign_prehashed(hasher.clone(), None)
            .map_err(|_| CryptoError::Serialization)?;

        Ok((
            SignatureBytes(sig.to_bytes()),
            HashBytes(hasher.finalize().into()),
        ))
    }

    pub fn sign_echo(&self, hash: HashBytes, msg_link_id: MsgLinkId) -> SignatureBytes {
        let bytes = canonical_echo_bytes(self.public_key(), hash, msg_link_id);
        SignatureBytes(self.0.sign(&bytes).to_bytes())
    }

    pub fn sign_ready(&self, hash: HashBytes, msg_link_id: MsgLinkId) -> SignatureBytes {
        let bytes = canonical_ready_bytes(self.public_key(), hash, msg_link_id);
        SignatureBytes(self.0.sign(&bytes).to_bytes())
    }
}

fn canonical_echo_bytes(
    sender: PublicKeyBytes,
    hash: HashBytes,
    msg_link_id: MsgLinkId,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + 32);
    v.extend_from_slice(&sender.0);
    v.extend_from_slice(&hash.0);
    v.extend_from_slice(&msg_link_id.to_be_bytes());
    v.extend_from_slice(b"ECHO");
    v
}

fn canonical_ready_bytes(
    sender: PublicKeyBytes,
    hash: HashBytes,
    msg_link_id: MsgLinkId,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + 32);
    v.extend_from_slice(&sender.0);
    v.extend_from_slice(&hash.0);
    v.extend_from_slice(&msg_link_id.to_be_bytes());
    v.extend_from_slice(b"READY");
    v
}

fn canonical_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    let cfg = bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_ENCODING_BYTES>();

    encode_to_vec(value, cfg).map_err(|_| CryptoError::Serialization)
}

fn init_msg_hasher<T: serde::Serialize>(
    data: &T,
    initiator: PublicKeyBytes,
    participants: &[PublicKeyBytes],
    msg_link_id: MsgLinkId,
) -> Result<Sha512, CryptoError> {
    let mut h = Sha512::new();
    h.update(canonical_bytes(data)?);
    h.update(initiator.0);
    for p in participants {
        h.update(p.0);
    }
    h.update(msg_link_id.to_be_bytes());
    Ok(h)
}
