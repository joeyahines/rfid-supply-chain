use serde::{Serialize, Deserialize};
use crate::models::key::PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRequest {
    pub key_ids: Vec<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyResponse {
    pub keys: Vec<PublicKey>
}
