use serde::{Deserialize, Serialize};

use crate::models::central_record::CentralRecord;
use crate::models::rfid::RfidData;
use crate::models::BlockChainEntry;
use crate::models::{deserialize_base64, serialize_base64};
use byteorder::{BigEndian, WriteBytesExt};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Signer;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdateRecordRequest {
    pub dist_id: u32,
    pub next_dist_id: u32,
    pub rfid_data: RfidData,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub signature: Vec<u8>,
}

impl UpdateRecordRequest {
    pub(crate) fn new(
        dist_id: u32,
        next_dist_id: u32,
        rfid_data: RfidData,
        private_key: &Rsa<Private>,
    ) -> Self {
        let mut req = Self {
            dist_id,
            next_dist_id,
            rfid_data,
            signature: vec![],
        };

        let bytes: Vec<u8> = req.clone().into();

        let hasher = MessageDigest::sha3_256();
        let pkey = PKey::from_rsa(private_key.clone()).unwrap();

        let mut signer = Signer::new(hasher, &pkey).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();

        signer.update(&bytes).unwrap();

        req.signature = signer.sign_to_vec().unwrap();

        req
    }
}

impl BlockChainEntry for UpdateRecordRequest {
    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl Into<Vec<u8>> for UpdateRecordRequest {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.write_u32::<BigEndian>(self.dist_id).unwrap();
        bytes.write_u32::<BigEndian>(self.next_dist_id).unwrap();
        let mut rfid_bytes: Vec<u8> = self.rfid_data.into();
        bytes.append(&mut rfid_bytes);

        bytes
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdateRecordResponse {
    pub success: bool,
    pub record: Option<CentralRecord>,
}
