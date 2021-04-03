use crate::DatabaseModel;
use crate::key::PublicKey;
use crate::rfid::RfidData;
use crate::{deserialize_base64, serialize_base64, BlockChainEntry};
use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CentralEntry {
    pub dist_id: u32,
    pub next_dist_id: u32,
    pub rfid_data: RfidData,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub signature: Vec<u8>,
}

impl CentralEntry {
    pub fn new(
        private_key: Vec<u8>,
        dist_id: u32,
        next_dist_id: u32,
        next_dist_pk: Vec<u8>,
        rfid_data: RfidData,
        record_data: Vec<u8>,
    ) -> Self {
        let data = if record_data.is_empty() {
            vec![serde_json::to_vec(&rfid_data).unwrap(), next_dist_pk]
        } else {
            vec![
                record_data,
                serde_json::to_vec(&rfid_data).unwrap(),
                next_dist_pk,
            ]
        };

        let signature = Self::create_signature(private_key, data);

        Self {
            dist_id,
            next_dist_id,
            rfid_data,
            signature,
        }
    }
}

impl BlockChainEntry for CentralEntry {
    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CentralRecord {
    pub chip_id: u128,
    pub entries: Vec<CentralEntry>,
}

impl DatabaseModel for CentralRecord {
    type ID = u128;

    fn id(&self) -> Self::ID {
        self.chip_id
    }

    fn set_id(&mut self, id: Self::ID) {
        self.chip_id = id
    }

    fn id_type_to_bytes(id: Self::ID) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_u128::<LittleEndian>(id).unwrap();
        bytes
    }

    fn tree() -> String {
        "central_record".to_string()
    }
}

impl CentralRecord {
    pub fn new(chip_id: u128) -> Self {
        Self {
            chip_id,
            entries: vec![],
        }
    }

    pub fn add_entry(
        &mut self,
        private_key: Vec<u8>,
        dist_id: u32,
        next_dist_id: u32,
        next_dist_pk: Vec<u8>,
        rfid_data: RfidData,
    ) {
        let record_data: Vec<u8> = if self.entries.is_empty() {
            Vec::new()
        } else {
            serde_json::to_vec(&self).unwrap()
        };

        let entry = CentralEntry::new(
            private_key,
            dist_id,
            next_dist_id,
            next_dist_pk,
            rfid_data,
            record_data,
        );
        self.entries.push(entry)
    }

    pub fn validate_chain(
        &self,
        keys: &HashMap<u32, PublicKey>,
        public_key: PublicKey,
    ) -> Result<(), usize> {
        let mut data_buff = Vec::new();

        for (ndx, entry) in self.entries.iter().enumerate() {
            data_buff.clear();
            let next_public_key = if let Some(pub_key) = keys.get(&entry.next_dist_id) {
                pub_key
            } else {
                return Err(ndx);
            };

            if ndx == 0 {
                data_buff.extend_from_slice(&serde_json::to_vec(&entry.rfid_data).unwrap());
                data_buff.extend_from_slice(&next_public_key.key);
            } else {
                let last_entry = &self.entries[ndx - 1];
                let last_pub_key = keys.get(&last_entry.next_dist_id).unwrap();
                data_buff.extend_from_slice(&crate::utility::hash_from_signature(
                    &last_pub_key.key,
                    &last_entry.signature,
                ));
                data_buff.extend_from_slice(&serde_json::to_vec(&entry.rfid_data).unwrap());
                data_buff.extend_from_slice(&next_public_key.key);
            }

            if !entry.verify_signature(&data_buff, &public_key.key) {
                return Err(ndx);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::models::central_record::CentralRecord;
    use crate::models::key::PublicKey;
    use crate::models::rfid::RfidBuilder;
    use openssl::rsa::Rsa;
    use std::collections::HashMap;

    #[test]
    fn test_central_record() {
        let keypair1 = Rsa::generate(2048).unwrap();
        let keypair2 = Rsa::generate(2048).unwrap();
        let keypair3 = Rsa::generate(2048).unwrap();
        let keypair4 = Rsa::generate(2048).unwrap();

        let key_id1: u32 = 0;
        let key_id2: u32 = 1;
        let key_id3: u32 = 2;
        let key_id4: u32 = 3;

        let mut key_map: HashMap<u32, PublicKey> = HashMap::new();
        key_map.insert(
            key_id1,
            PublicKey::new(
                key_id1,
                keypair1.public_key_to_pem().unwrap(),
                "1".to_string(),
            ),
        );
        key_map.insert(
            key_id2,
            PublicKey::new(
                key_id2,
                keypair2.public_key_to_pem().unwrap(),
                "2".to_string(),
            ),
        );
        key_map.insert(
            key_id3,
            PublicKey::new(
                key_id3,
                keypair3.public_key_to_pem().unwrap(),
                "3".to_string(),
            ),
        );

        key_map.insert(
            key_id4,
            PublicKey::new(
                key_id4,
                keypair4.public_key_to_pem().unwrap(),
                "4".to_string(),
            ),
        );

        let data = RfidBuilder::default()
            .chip_data(42, 5.0, 5.0, 5.0, 5.0)
            .add_entry(
                keypair1.private_key_to_pem().unwrap(),
                key_id1,
                key_id2,
                &key_map,
            )
            .add_entry(
                keypair2.private_key_to_pem().unwrap(),
                key_id2,
                key_id3,
                &key_map,
            )
            .build();

        let mut record = CentralRecord::default();
        record.add_entry(
            keypair4.private_key_to_pem().unwrap().to_vec(),
            key_id2,
            key_id3,
            key_map.get(&key_id3).unwrap().key.clone(),
            data,
        );

        assert!(record
            .validate_chain(&key_map, key_map.get(&key_id4).unwrap().clone())
            .is_ok());
    }
}
