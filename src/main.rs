#![allow(dead_code)]

mod error;
mod models;
mod utility;
mod args;

const KEY_SIZE: usize = 2;
const SIGNATURE_SIZE: usize = 256;


fn main() {
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryFrom;

    use openssl::hash::{hash, MessageDigest};
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;

    use crate::models::rfid::{RFIDBuilder, RFIDData};
    use crate::utility::hash_from_signature;

    #[test]
    fn test_signature_decrypt() {
        let rsa = Rsa::generate(2048).unwrap();
        let keypair = PKey::from_rsa(rsa.clone()).unwrap();
        let hasher = MessageDigest::sha3_256();
        let test_value = b"\xDE\xAD\xBE\xEF\xff";
        let test_hash = hash(hasher, test_value).unwrap().to_vec();

        let mut signer = Signer::new(hasher, &keypair).unwrap();

        signer.update(test_value).unwrap();

        let signature = signer.sign_to_vec().unwrap();

        let sign_hash = hash_from_signature(&keypair.public_key_to_pem().unwrap(), &signature);

        assert_eq!(sign_hash, test_hash)
    }

    #[test]
    fn test_rfid_data_build() {
        let keypair1 = Rsa::generate(2048).unwrap();
        let keypair2 = Rsa::generate(2048).unwrap();
        let keypair3 = Rsa::generate(2048).unwrap();

        let key_id1: Vec<u8> = vec![0, 0];
        let key_id2: Vec<u8> = vec![0, 1];
        let key_id3: Vec<u8> = vec![0, 2];

        let mut key_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        key_map.insert(key_id1.clone(), keypair1.public_key_to_pem().unwrap());
        key_map.insert(key_id2.clone(), keypair2.public_key_to_pem().unwrap());
        key_map.insert(key_id3.clone(), keypair3.public_key_to_pem().unwrap());

        let data = RFIDBuilder::default()
            .chip_data(42, 5.0, 5.0, 5.0, 5.0)
            .add_entry(
                keypair1.private_key_to_pem().unwrap(),
                keypair2.public_key_to_pem().unwrap(),
                key_id1.clone(),
                &key_map,
            )
            .add_entry(
                keypair2.private_key_to_pem().unwrap(),
                keypair3.public_key_to_pem().unwrap(),
                key_id2.clone(),
                &key_map,
            )
            .build();

        assert!(data.valid_crc());
        assert!(data
            .validate_chain(&key_map, keypair3.public_key_to_pem().unwrap().to_vec())
            .is_ok());
        let data2: Vec<u8> = data.clone().into();
        let data2 = RFIDData::try_from(data2).unwrap();
        assert!(data2.valid_crc());
        assert!(data2
            .validate_chain(&key_map, keypair3.public_key_to_pem().unwrap().to_vec())
            .is_ok());

        assert_eq!(data.calc_crc(), data2.calc_crc())
    }
}
