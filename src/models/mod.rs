pub mod chip_data;
pub mod key;
pub mod requests;
pub mod rfid;
pub mod supply_chain;

use base64::{decode, encode};
use serde::{Deserialize, Deserializer, Serializer};

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
