use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::error::RfidDataParseError;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
    type Error = RfidDataParseError;

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
