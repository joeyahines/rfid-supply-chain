use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crc::crc16;
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Rsa, Padding};
use openssl::sign::{Signer, Verifier};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read};
use std::collections::HashMap;

const KEY_SIZE: usize = 32; // 256 bits
const SIGNATURE_SIZE: usize = 256;

#[derive(Debug)]
enum RFIDDataParseError {
    ByteParseError(std::io::Error),
}

impl From<std::io::Error> for RFIDDataParseError {
    fn from(e: std::io::Error) -> Self {
        Self::ByteParseError(e)
    }
}

impl Error for RFIDDataParseError {}

impl Display for RFIDDataParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RFIDDataParseError::ByteParseError(e) => write!(f, "Failed to parse struct: {}", e),
        }
    }
}

#[derive(Debug, Clone)]
struct SupplyChainEntry {
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
    fn new(private_key: Vec<u8>, next_public_key: Vec<u8>, rfid_data: Vec<u8>) -> SupplyChainEntry {
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

    fn verify_signature(&self, expected_data: &Vec<u8>, public_key: &Vec<u8>) -> bool {
        let pkey = PKey::public_key_from_pem(&public_key).unwrap();
        let hasher = MessageDigest::sha3_256();
        let mut verifier = Verifier::new(hasher, &pkey).unwrap();

        verifier.update(expected_data).unwrap();

        verifier.verify(&*self.signature).unwrap()
    }
}

#[derive(Debug, Clone, Default)]
struct ChipData {
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

#[derive(Debug, Clone, Default)]
struct RFIDData {
    pub crc: u16,
    pub chip_data: ChipData,
    pub entries: Vec<SupplyChainEntry>,
}

impl RFIDData {
    pub fn calc_crc(&self) -> u16 {
        let bytes: Vec<u8> = self.clone().into();
        ((bytes[0] as u16) << 8) | bytes[1] as u16
    }

    pub fn validate_chain(&self, keys: &HashMap<Vec<u8>, Vec<u8>>, public_key: Vec<u8>) -> Result<(), usize> {
        let mut data_buff = Vec::with_capacity(KEY_SIZE+SIGNATURE_SIZE);

        for (ndx, entry) in self.entries.iter().enumerate() {
            data_buff.clear();
            let next_public_key = if ndx == self.entries.len()-1 {
                &public_key
            }
            else {
                if let Some(pub_key) = keys.get(&self.entries[ndx+1].pub_key) {
                    pub_key
                }
                else {
                    return Err(ndx);
                }
            };

            if ndx == 0 {
                let chip_data: Vec<u8> = self.chip_data.clone().into();
                data_buff.extend_from_slice(&chip_data);
                data_buff.extend_from_slice(next_public_key);
            }
            else {
                let last_entry = &self.entries[ndx-1];
                let last_pub_key = keys.get(&last_entry.pub_key).unwrap();
                data_buff.extend_from_slice(&hash_from_signature(last_pub_key, &last_entry.signature));
                data_buff.extend_from_slice(&last_entry.signature);
                data_buff.extend_from_slice(next_public_key);
            }

            if !entry.verify_signature(&data_buff, keys.get(&entry.pub_key).unwrap())  {
                return Err(ndx);
            }

        }

        Ok(())

    }

    pub fn valid_crc(&self) -> bool {
        self.crc == self.calc_crc()
    }
}

impl Into<Vec<u8>> for RFIDData {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let entry_len = self.entries.len() as u16;

        bytes.push((entry_len >> 8) as u8);
        bytes.push((entry_len as u8) & 0xff);
        bytes.append(&mut self.chip_data.into());

        let mut entry_bytes: Vec<u8> = self
            .entries
            .into_iter()
            .map::<Vec<u8>, _>(|e| e.into())
            .flatten()
            .collect();

        bytes.append(&mut entry_bytes);
        let crc = crc16::checksum_x25(&bytes);

        bytes.insert(0, (crc >> 8) as u8);
        bytes.insert(0, (crc & 0xff) as u8);

        bytes
    }
}

impl TryFrom<Vec<u8>> for RFIDData {
    type Error = RFIDDataParseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytes);
        let crc = cursor.read_u16::<BigEndian>()?;
        let entry_count = cursor.read_u16::<BigEndian>()?;

        let mut chip_data_bytes = vec![0u8; 32];
        cursor.read_exact(&mut chip_data_bytes)?;

        let chip_data = ChipData::try_from(chip_data_bytes)?;

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let mut entry_bytes = vec![0u8; KEY_SIZE + SIGNATURE_SIZE];
            cursor.read_exact(&mut entry_bytes)?;
            let entry = SupplyChainEntry::try_from(entry_bytes)?;
            entries.push(entry)
        }

        Ok(Self {
            crc,
            chip_data,
            entries,
        })
    }
}

#[derive(Default)]
struct RFIDBuilder {
    rfid_data: RFIDData,
}

impl RFIDBuilder {
    pub fn add_entry(mut self, private_key: Vec<u8>, next_public_key: Vec<u8>, keys: &HashMap<Vec<u8>, Vec<u8>>) -> Self {
        let data = if let Some(last_entry) = self.rfid_data.entries.last() {
            let last_public_key = keys.get(&last_entry.pub_key).unwrap();
            let mut buf = hash_from_signature(last_public_key, &last_entry.signature);
            buf.extend_from_slice(&last_entry.signature);
            buf
        }
        else {
            self.rfid_data.chip_data.clone().into()
        };

        self.rfid_data
            .entries
            .push(SupplyChainEntry::new(private_key, next_public_key, data));
        self
    }

    pub fn chip_data(
        mut self,
        chip_id: u128,
        freq: f32,
        voltage: f32,
        temp: f32,
        time: f32,
    ) -> Self {
        self.rfid_data.chip_data.chip_id = chip_id;
        self.rfid_data.chip_data.freq = freq;
        self.rfid_data.chip_data.voltage = voltage;
        self.rfid_data.chip_data.temp = temp;
        self.rfid_data.chip_data.time = time;

        self
    }

    pub fn build(mut self) -> RFIDData {
        let crc = self.rfid_data.calc_crc();
        self.rfid_data.crc = crc;

        self.rfid_data
    }
}

pub fn hash_from_signature(pub_key: &Vec<u8>, signature: &Vec<u8>) -> Vec<u8>{
    let rsa= Rsa::public_key_from_pem(pub_key).unwrap();
    let mut output = vec![0u8; signature.len()];
    rsa.public_decrypt(&signature, &mut output, Padding::PKCS1).unwrap();

    output.drain(0..19);

    output.truncate(KEY_SIZE);

    output
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use crate::{RFIDBuilder, hash_from_signature, RFIDData};
    use openssl::rsa::Rsa;
    use std::collections::HashMap;
    use openssl::hash::{MessageDigest, hash};
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use std::convert::TryFrom;

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
        let hasher = MessageDigest::sha3_256();

        let pub_key1: Vec<u8> = hash(hasher, &keypair1.public_key_to_pem().unwrap())
            .unwrap()
            .to_vec();

        let pub_key2: Vec<u8> = hash(hasher, &keypair2.public_key_to_pem().unwrap())
            .unwrap()
            .to_vec();

        let pub_key3: Vec<u8> = hash(hasher, &keypair3.public_key_to_pem().unwrap())
            .unwrap()
            .to_vec();

        let mut key_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        key_map.insert(pub_key1, keypair1.public_key_to_pem().unwrap());
        key_map.insert(pub_key2, keypair2.public_key_to_pem().unwrap());
        key_map.insert(pub_key3, keypair3.public_key_to_pem().unwrap());

        let data = RFIDBuilder::default()
            .chip_data(42, 5.0, 5.0, 5.0, 5.0)
            .add_entry(
                keypair1.private_key_to_pem().unwrap(),
                keypair2.public_key_to_pem().unwrap(),
                &key_map
            )
            .add_entry(
                keypair2.private_key_to_pem().unwrap(),
                keypair3.public_key_to_pem().unwrap(),
                &key_map
            )
            .build();

        assert!(data.valid_crc());
        assert!(data.validate_chain(&key_map, keypair3.public_key_to_pem().unwrap().to_vec()).is_ok());
        let data2: Vec<u8> = data.clone().into();
        let data2 = RFIDData::try_from(data2).unwrap();
        assert!(data2.valid_crc());
        assert!(data2.validate_chain(&key_map, keypair3.public_key_to_pem().unwrap().to_vec()).is_ok());

        assert_eq!(data.calc_crc(), data2.calc_crc())
    }
}
