use serde::{Deserialize, Serialize};

use crate::models::rfid::RfidData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateBlockChainRequest {
    pub rfid_data: RfidData,
    pub next_distributor: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateBlockChainResponse {
    pub rfid_data: RfidData,
}
