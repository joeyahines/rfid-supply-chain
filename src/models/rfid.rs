use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt};
use crc::crc16;

se crate::{KEY_SIZE, SIGNATURE_SIZE};
use crate::error::RFIDDataParseError;
use crate::models::chip_data::ChipData;
use crate::models::supply_chain::SupplyChainEntry;

#[derive(Debug, Clone, Default)]
pub struct RFIDData {
    pub crc: u16,
    pub chip_data: ChipData,
    pub entries: Vec<SupplyChainEntry>,
}

impl RFIDData {
    pub fn calc_crc(&self) -> u16 {
        let bytes: Vec<u8> = self.clone().into();
        ((bytes[0] as u16) << 8) | bytes[1] as u16
    }

    pub fn validate_chain(
        &self,
        keys: &HashMap<Vec<u8>, Vec<u8>>,
        public_key: Vec<u8>,
    ) -> Result<(), usize> {
        let mut data_buff = Vec::with_capacity(KEY_SIZE + SIGNATURE_SIZE);

        for (ndx, entry) in self.entries.iter().enumerate() {
            data_buff.clear();
            let next_public_key = if ndx == self.entries.len() - 1 {
                &public_key
            } else if let Some(pub_key) = keys.get(&self.entries[ndx + 1].pub_key) {
                pub_key
            } else {
                return Err(ndx);
            };

            if ndx == 0 {
                let chip_data: Vec<u8> = self.chip_data.clone().into();
                data_buff.extend_from_slice(&chip_data);
                data_buff.extend_from_slice(next_public_key);
            } else {
                let last_entry = &self.entries[ndx - 1];
                let last_pub_key = keys.get(&last_entry.pub_key).unwrap();
                data_buff.extend_from_slice(&crate::utility::hash_from_signature(
                    last_pub_key,
                    &last_entry.signature,
                ));
                data_buff.extend_from_slice(&last_entry.signature);
                data_buff.extend_from_slice(next_public_key);
            }

            if !entry.verify_signature(&data_buff, keys.get(&entry.pub_key).unwrap()) {
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
        bytes.push(entry_len as u8);
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
pub struct RFIDBuilder {
    rfid_data: RFIDData,
}

impl RFIDBuilder {
    pub fn add_entry(
        mut self,
        private_key: Vec<u8>,
        next_public_key: Vec<u8>,
        public_key_id: Vec<u8>,
        keys: &HashMap<Vec<u8>, Vec<u8>>,
    ) -> Self {
        let data = if let Some(last_entry) = self.rfid_data.entries.last() {
            let last_public_key = keys.get(&last_entry.pub_key).unwrap();
            let mut buf =
                crate::utility::hash_from_signature(last_public_key, &last_entry.signature);
            buf.extend_from_slice(&last_entry.signature);
            buf
        } else {
            self.rfid_data.chip_data.clone().into()
        };

        self.rfid_data
            .entries
            .push(SupplyChainEntry::new(private_key, next_public_key, data, public_key_id));
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
