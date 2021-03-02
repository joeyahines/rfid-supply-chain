use std::convert::TryFrom;
use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};

use crate::error::RFIDDataParseError;
use crate::{KEY_SIZE, SIGNATURE_SIZE};

#[derive(Debug, Clone)]
pub struct SupplyChainEntry {
    pub pub_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Into<Vec<u8>> for SupplyChainEntry {
    fn into(self) -> Vec<u8> {
        let mut pub_key = self.pub_key;
        let mut signature = self.signature;

        pub_key.append(&mut signature);

        pub_key
    }
}

impl TryFrom<Vec<u8>> for SupplyChainEntry {
    type Error = RFIDDataParseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytes);

        let mut pub_key = vec![0u8; KEY_SIZE];
        let mut signature = vec![0u8; SIGNATURE_SIZE];

        cursor.read_exact(&mut pub_key)?;
        cursor.read_exact(&mut signature)?;

        Ok(Self { pub_key, signature })
    }
}

impl SupplyChainEntry {
    pub fn new(
        private_key: Vec<u8>,
        next_public_key: Vec<u8>,
        rfid_data: Vec<u8>,
    ) -> SupplyChainEntry {
        let keypair = Rsa::private_key_from_pem(&private_key).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();
        let hasher = MessageDigest::sha3_256();

        let pub_key: Vec<u8> = hash(hasher, &keypair.public_key_to_pem().unwrap())
            .unwrap()
            .to_vec();

        let mut signer = Signer::new(hasher, &keypair).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();

        signer.update(&rfid_data).unwrap();
        signer.update(&next_public_key).unwrap();

        let signature = signer.sign_to_vec().unwrap();

        Self { pub_key, signature }
    }

    pub fn verify_signature(&self, expected_data: &[u8], public_key: &[u8]) -> bool {
        let pkey = PKey::public_key_from_pem(&public_key).unwrap();
        let hasher = MessageDigest::sha3_256();
        let mut verifier = Verifier::new(hasher, &pkey).unwrap();

        verifier.update(expected_data).unwrap();

        verifier.verify(&*self.signature).unwrap()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChipData {
    pub chip_id: u128,
    pub freq: f32,
    pub voltage: f32,
    pub temp: f32,
    pub time: f32,
}

impl Into<Vec<u8>> for ChipData {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.write_u128::<BigEndian>(self.chip_id).unwrap();
        bytes.write_f32::<BigEndian>(self.freq).unwrap();
        bytes.write_f32::<BigEndian>(self.voltage).unwrap();
        bytes.write_f32::<BigEndian>(self.temp).unwrap();
        bytes.write_f32::<BigEndian>(self.time).unwrap();
        bytes
    }
}

impl TryFrom<Vec<u8>> for ChipData {
    type Error = RFIDDataParseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytes);

        let chip_id = cursor.read_u128::<BigEndian>()?;
        let freq = cursor.read_f32::<BigEndian>()?;
        let voltage = cursor.read_f32::<BigEndian>()?;
        let temp = cursor.read_f32::<BigEndian>()?;
        let time = cursor.read_f32::<BigEndian>()?;

        Ok(Self {
            chip_id,
            freq,
            voltage,
            temp,
            time,
        })
    }
}
