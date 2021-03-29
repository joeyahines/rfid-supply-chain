use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::{Cursor, Read};

use crate::error::RFIDDataParseError;
use crate::models::{deserialize_base64, serialize_base64, BlockChainEntry};
use crate::SIGNATURE_SIZE;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SupplyChainEntry {
    pub pub_key: u32,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub signature: Vec<u8>,
}

impl Into<Vec<u8>> for SupplyChainEntry {
    fn into(self) -> Vec<u8> {
        let mut buffer = Vec::new();
        let pub_key = self.pub_key;
        let mut signature = self.signature;

        buffer.write_u32::<LittleEndian>(pub_key).unwrap();
        buffer.append(&mut signature);

        buffer
    }
}

impl TryFrom<Vec<u8>> for SupplyChainEntry {
    type Error = RFIDDataParseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytes);

        let pub_key = cursor.read_u32::<LittleEndian>()?;

        let mut signature = vec![0u8; SIGNATURE_SIZE];
        cursor.read_exact(&mut signature)?;

        Ok(Self { pub_key, signature })
    }
}

impl SupplyChainEntry {
    pub fn new(
        private_key: Vec<u8>,
        next_public_key: Vec<u8>,
        rfid_data: Vec<u8>,
        public_key_id: u32,
    ) -> SupplyChainEntry {
        let signature = Self::create_signature(private_key, vec![rfid_data, next_public_key]);

        Self {
            pub_key: public_key_id,
            signature,
        }
    }
}

impl BlockChainEntry for SupplyChainEntry {
    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}
