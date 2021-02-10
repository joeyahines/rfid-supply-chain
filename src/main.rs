use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read};
use crc::crc16;

const KEY_SIZE: usize = 32; // 256 bits
const SIGNATURE_SIZE: usize = 32; // 256 bits

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
            RFIDDataParseError::ByteParseError(e) => write!(f, "Failed to parse struct: {}", e)
        }
    }
}

#[derive(Debug, Clone)]
struct SupplyChainEntry {
    pub pub_key: Vec<u8>,
    pub signature: Vec<u8>
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

        let mut pub_key = Vec::new();
        let mut signature = Vec::new();

        cursor.read_exact(&mut pub_key)?;
        cursor.read_exact(&mut signature)?;

        Ok(Self {
            pub_key,
            signature
        })
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
            time
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
        ((bytes[0] as u16) << 8) & bytes[1] as u16
    }

    pub fn valid(&self) -> bool {
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

        let mut entry_bytes: Vec<u8> = self.entries.into_iter().map::<Vec<u8>, _>(|e| {
            e.into()
        }).flatten().collect();

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
        let entry_count= cursor.read_u16::<BigEndian>()?;

        let mut chip_data_bytes= vec![0u8; 32];
        cursor.read_exact(&mut chip_data_bytes)?;

        let chip_data = ChipData::try_from(chip_data_bytes)?;

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let mut entry_bytes= vec![0u8; KEY_SIZE + SIGNATURE_SIZE];
            cursor.read_exact(&mut entry_bytes)?;
            let entry = SupplyChainEntry::try_from(entry_bytes)?;
            entries.push(entry)
        }

        Ok(Self {
            crc,
            chip_data,
            entries
        })
    }
}

#[derive(Default)]
struct RFIDBuilder {
    rfid_data: RFIDData,
}

impl RFIDBuilder {
    pub fn add_entry(mut self, entry: SupplyChainEntry) -> Self {
        self.rfid_data.entries.push(entry);
        self
    }

    pub fn chip_data(mut self, chip_id: u128, freq: f32, voltage: f32, temp: f32, time: f32) -> Self {
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

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use crate::{RFIDBuilder, SupplyChainEntry, KEY_SIZE, SIGNATURE_SIZE};

    #[test]
    fn test_rfid_data_build() {
        let data = RFIDBuilder::default()
            .chip_data(42, 5.0, 5.0, 5.0, 5.0)
            .add_entry(SupplyChainEntry {
                pub_key: vec![0u8; KEY_SIZE],
                signature: vec![0u8; SIGNATURE_SIZE]
            })
            .build();

        assert!(data.valid())
    }
}