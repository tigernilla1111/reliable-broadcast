use bincode::serde::encode_to_vec;
use ed25519_dalek::ed25519::signature::SignerMut;
use rand_core::OsRng;
use sha2::{Digest, Sha512, digest::Output};

use crate::network::MsgLinkId;

const MAX_ENCODING_BYTES: usize = 10000;

pub type Sha512HashOutput = Output<Sha512>;
pub type Sha512HashBytes = Vec<u8>;
#[derive(serde::Deserialize, serde::Serialize)]
pub struct PublicKeyBytes([u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);

pub struct PublicKey(ed25519_dalek::VerifyingKey);
impl PublicKey {
    pub fn from_bytes(
        bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    ) -> Result<Self, ed25519_dalek::SignatureError> {
        Ok(PublicKey(ed25519_dalek::VerifyingKey::from_bytes(bytes)?))
    }
    pub fn validate_ph(&self, hash: Sha512HashOutput) -> Result<(), ()> {
        todo!()
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
        data: T,
        intiator: PublicKey,
        participants: Vec<PublicKey>,
        msg_link_id: MsgLinkId,
    ) -> (Signature, Sha512HashOutput) {
        let hasher = sha512_init_msg(data, intiator, participants, msg_link_id);
        let signature = Signature(self.0.sign_prehashed(hasher.clone(), None).unwrap());
        (signature, hasher.finalize())
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
fn sha512_init_msg<D: serde::Serialize>(
    data: D,
    intiator: PublicKey,
    participants: Vec<PublicKey>,
    msg_link_id: MsgLinkId,
) -> Sha512 {
    let mut hasher = Sha512::new();
    hasher.update(canonical_bytes(&data));
    hasher.update(intiator.0.as_bytes());
    for participant in participants {
        hasher.update(participant.0.as_bytes());
    }
    hasher.update(msg_link_id.to_be_bytes());
    hasher
}
