use rand::Rng;
use std::ops::Deref;
type PubId = u64;

pub type DataHashOutput = [u8; 32];

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct UserId(PubId);
impl UserId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn random() -> Self {
        Self(rand::rng().random())
    }
}
impl Deref for UserId {
    type Target = PubId;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub type Signature = String;
