use crate::DatabaseModel;
use crate::{deserialize_base64, serialize_base64};
use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub id: u32,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub key: Vec<u8>,
    pub distributor_name: String,
}

impl PublicKey {
    pub fn new(id: u32, key: Vec<u8>, distributor_name: String) -> Self {
        Self {
            id,
            key,
            distributor_name,
        }
    }
}

impl DatabaseModel for PublicKey {
    type ID = u32;

    fn id(&self) -> Self::ID {
        self.id
    }

    fn set_id(&mut self, id: Self::ID) {
        self.id = id;
    }

    fn id_type_to_bytes(id: Self::ID) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_u32::<LittleEndian>(id).unwrap();
        bytes
    }

    fn tree() -> String {
        "public_keys".to_string()
    }
}
