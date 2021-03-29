#![allow(dead_code)]

mod args;
mod central_server;
mod config;
mod database;
mod distributor_server;
mod error;
mod models;
mod utility;

use crate::args::{Args, Mode};
use structopt::StructOpt;

const SIGNATURE_SIZE: usize = 256;

#[tokio::main]
async fn main() {
    let args: Args = Args::from_args();

    match &args.mode {
        Mode::DistributorServer(dist_args) => {
            distributor_server::distributor_server(&args, dist_args)
                .await
                .unwrap()
        }
        Mode::CentralServer(cent_args) => central_server::central_server(&args, cent_args)
            .await
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::path::PathBuf;

    use openssl::hash::{hash, MessageDigest};
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;

    use crate::models::key::PublicKey;
    use crate::models::rfid::{RFIDBuilder, RFIDData};
    use crate::utility::{hash_from_signature, open_private_key};

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

        let key_id1: u32 = 0;
        let key_id2: u32 = 1;
        let key_id3: u32 = 2;

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

        let data = RFIDBuilder::default()
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

        assert!(data.valid_crc());
        assert!(data
            .validate_chain(&key_map, key_map.get(&key_id3).unwrap().clone())
            .is_ok());
        let data2: Vec<u8> = data.clone().into();
        let data2 = RFIDData::try_from(data2).unwrap();
        assert!(data2.valid_crc());
        assert!(data2
            .validate_chain(&key_map, key_map.get(&key_id3).unwrap().clone())
            .is_ok());

        assert_eq!(data.calc_crc(), data2.calc_crc())
    }

    #[test]
    fn test_to_json() {
        let keypair1 = open_private_key(PathBuf::from("test_keys/sauce_rsa"));
        let keypair2 = open_private_key(PathBuf::from("test_keys/cool_chip_rsa"));

        let key_id1: u32 = 55;
        let key_id2: u32 = 0;

        let mut key_map: HashMap<u32, PublicKey> = HashMap::new();
        key_map.insert(
            key_id1,
            PublicKey::new(
                key_id1,
                keypair1.public_key_to_pem().unwrap(),
                "Sauce Firm".to_string(),
            ),
        );
        key_map.insert(
            key_id2,
            PublicKey::new(
                key_id2,
                keypair2.public_key_to_pem().unwrap(),
                "Cool Chip 123".to_string(),
            ),
        );
        let data = RFIDBuilder::default()
            .chip_data(42, 5.0, 5.0, 5.0, 5.0)
            .add_entry(
                keypair1.private_key_to_pem().unwrap(),
                key_id1,
                key_id2,
                &key_map,
            )
            .build();

        data.validate_chain(&key_map, key_map.get(&key_id2).unwrap().clone())
            .unwrap();

        println!("{}", serde_json::to_string(&data).unwrap())
    }
}
