use bincode::serde::encode_to_vec;
use ed25519_dalek::ed25519::signature::SignerMut;
use rand_core::OsRng;
use sha2::{Digest, Sha512};

use crate::network::MsgLinkId;

const MAX_ENCODING_BYTES: usize = 10000;

pub type Sha512HashBytes = Vec<u8>;

#[derive(serde::Deserialize, serde::Serialize, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct PublicKeyBytes([u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);

#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);
impl PublicKey {
    pub fn from_bytes(
        bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    ) -> Result<Self, ed25519_dalek::SignatureError> {
        Ok(PublicKey(ed25519_dalek::VerifyingKey::from_bytes(bytes)?))
    }
    pub fn to_bytes(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.0.to_bytes())
    }
    pub fn as_bytes(&self) -> &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }
    // For the init message, participants will generate the hash and then validate the included signature
    pub fn verify_ph(&self, hash: Sha512, sig: &Signature) -> Result<(), ()> {
        self.0.verify_prehashed(hash, None, &sig.0).map_err(|_| ())
    }
}
pub struct Signature(ed25519_dalek::Signature);
pub struct PrivateKey(ed25519_dalek::SigningKey);
impl PrivateKey {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        Self(ed25519_dalek::SigningKey::generate(&mut csprng))
    }
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }
    pub fn sign<T: serde::Serialize>(&mut self, data: T) -> Signature {
        let bytes = canonical_bytes(&data);
        Signature(self.0.sign(&bytes))
    }
    pub fn get_sig_and_hash<T: serde::Serialize>(
        &self,
        data: &T,
        initiator: PublicKeyBytes,
        participants: &Vec<PublicKeyBytes>,
        msg_link_id: MsgLinkId,
    ) -> (Signature, Sha512HashBytes) {
        let hasher = sha512_init_msg_hasher(&data, initiator, participants, msg_link_id);
        let signature = Signature(self.0.sign_prehashed(hasher.clone(), None).unwrap());
        (signature, hasher.finalize().to_vec())
    }
}

/// Data types that contain a HashMap or HashSet cannot be used in this function
/// They must be converted into an ordered set eg Vec or BTreeSet
pub fn canonical_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let config = bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_ENCODING_BYTES>();
    encode_to_vec(value, config).expect("serialization failed")
}

/// Can't use the ed25519_dalek::SigningKey.sign on the init message because we need to expose the
/// hash it produces to be signed, which can't be done with that crate.
/// So manually create the a Sha512 hash which can be fed into the sign_prehashed
fn sha512_init_msg_hasher<D: serde::Serialize>(
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
) -> Sha512HashBytes {
    sha512_init_msg_hasher(data, initiator, participants, msg_link_id)
        .finalize()
        .to_vec()
}
