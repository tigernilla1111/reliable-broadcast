use crate::network::MsgLinkId;
use bincode::serde::encode_to_vec;
use ed25519_dalek::Verifier;
use ed25519_dalek::ed25519::signature::Signer;
use rand_core::OsRng;
use serde_bytes;
use sha2::{Digest, Sha512};
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
pub struct PublicKeyBytes(pub [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);

impl PublicKeyBytes {
    fn to_verifying_key(self) -> Result<ed25519_dalek::VerifyingKey, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|_| CryptoError::InvalidPublicKey(self))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_init_roundtrip() {
        // Test the complete sign/verify cycle for init messages
        let private_key = PrivateKey::new();
        let initiator = private_key.public_key();
        let participant1 = PrivateKey::new().public_key();
        let participant2 = PrivateKey::new().public_key();
        let participants = vec![participant1, participant2];
        let msg_link_id = MsgLinkId::new(12345);

        let test_data = "test message data";

        // Sign the init message
        let (signature, hash) = private_key
            .sign_init(&test_data, initiator, &participants, msg_link_id)
            .expect("signing should succeed");

        // Verify the init message
        let verified_hash = verify_init(
            &signature,
            &test_data,
            initiator,
            &participants,
            msg_link_id,
        )
        .expect("verification should succeed");

        // Hash from signing and verification should match
        assert_eq!(hash, verified_hash);
    }

    #[test]
    fn test_echo_and_ready_signature_verification() {
        // Test that echo and ready messages are signed/verified correctly
        let private_key = PrivateKey::new();
        let sender = private_key.public_key();
        let msg_link_id = MsgLinkId::new(67890);

        // Create a mock hash
        let init_hash = HashBytes([42u8; SHA512_OUTPUT_BYTES]);

        // Test ECHO
        let echo_sig = private_key.sign_echo(init_hash, msg_link_id);
        verify_echo(sender, init_hash, msg_link_id, echo_sig)
            .expect("echo verification should succeed");

        // Test READY
        let ready_sig = private_key.sign_ready(init_hash, msg_link_id);
        verify_ready(sender, init_hash, msg_link_id, ready_sig)
            .expect("ready verification should succeed");
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_key() {
        // Test that signatures fail verification when wrong public key is used
        let signer = PrivateKey::new();
        let wrong_key = PrivateKey::new().public_key();
        let correct_key = signer.public_key();
        let msg_link_id = MsgLinkId::new(11111);

        let test_data = "important data";
        let participants = vec![correct_key];

        // Sign with one key
        let (signature, _) = signer
            .sign_init(&test_data, correct_key, &participants, msg_link_id)
            .expect("signing should succeed");

        // Try to verify with wrong initiator key - should fail
        let result = verify_init(
            &signature,
            &test_data,
            wrong_key,
            &participants,
            msg_link_id,
        );
        assert!(matches!(result, Err(CryptoError::InvalidSignature(_))));

        // Verify with correct key should succeed
        let result = verify_init(
            &signature,
            &test_data,
            correct_key,
            &participants,
            msg_link_id,
        );
        assert!(result.is_ok());
    }
}
