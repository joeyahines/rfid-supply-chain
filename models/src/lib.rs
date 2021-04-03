pub mod central_record;
pub mod chip_data;
pub mod key;
pub mod rfid;
pub mod supply_chain;
pub mod requests;
pub mod error;
pub mod utility;

use base64::{decode, encode};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};
use serde::{Deserialize, Deserializer, Serializer, Serialize};
use serde::de::DeserializeOwned;

const SIGNATURE_SIZE: usize = 256;

pub fn serialize_base64<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
{
    serializer.serialize_str(&encode(&buffer))
}

pub fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| decode(string).map_err(|err| Error::custom(err.to_string())))
}

pub trait BlockChainEntry {
    fn signature(&self) -> Vec<u8>;

    fn create_signature(private_key: Vec<u8>, members: Vec<Vec<u8>>) -> Vec<u8> {
        let keypair = Rsa::private_key_from_pem(&private_key).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();
        let hasher = MessageDigest::sha3_256();

        let mut signer = Signer::new(hasher, &keypair).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();

        for member in members {
            signer.update(&member).unwrap();
        }

        signer.sign_to_vec().unwrap()
    }

    fn verify_signature(&self, expected_data: &[u8], public_key: &[u8]) -> bool {
        let pkey = PKey::public_key_from_pem(&public_key).unwrap();
        let hasher = MessageDigest::sha3_256();
        let mut verifier = Verifier::new(hasher, &pkey).unwrap();

        verifier.update(expected_data).unwrap();

        verifier.verify(&self.signature()).unwrap()
    }
}

pub trait DatabaseModel: Serialize + DeserializeOwned {
    type ID;

    fn id(&self) -> Self::ID;
    fn set_id(&mut self, id: Self::ID);

    fn id_to_bytes(self) -> Vec<u8> {
        Self::id_type_to_bytes(self.id())
    }

    fn id_type_to_bytes(id: Self::ID) -> Vec<u8>;
    fn tree() -> String;
}

