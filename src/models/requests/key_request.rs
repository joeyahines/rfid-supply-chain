use serde::{Deserialize, Serialize};

use crate::models::key::PublicKey;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRequest {
    pub key_ids: Vec<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyResponse {
    pub keys: HashMap<u32, PublicKey>,
}
