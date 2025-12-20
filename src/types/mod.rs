use std::ops::Deref;

use rand::Rng;
type PubId = u64;
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

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CreatePost {
    poster: UserId,
    msg: String,
    sig: Signature,
}

/// LedgerDiffs are different state changes that can be applied to the ledger
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum LedgerDiff {
    CreatePost(CreatePost),
}
