// src/drivers/meter_x.rs

use serde_json::json;
use crate::security::{EncryptionMode, SecurityEngine};
use crate::traits::{
    parse_wmbus_records, DllHeader, DllHeaderInfo, MeterDriver, ParseError, ProcessResult,
};

pub struct MeterXDriver;

impl MeterXDriver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MeterXDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MeterDriver for MeterXDriver {
    fn supports(&self, header: &DllHeader) -> bool {
        header.manufacturer_code() == "MTX"
    }

    fn parse(
        &self,
        raw_payload: &[u8],
        oms_mode: Option<u8>,
        key: Option<&[u8]>,
    ) -> Result<ProcessResult, ParseError> {
        let header = DllHeader::from_bytes(raw_payload)?;

        let mode = EncryptionMode::from(oms_mode);

        let payload_to_parse =
            SecurityEngine::decrypt_payload(mode, raw_payload, 10, key)?;

        let parsed_measurements = parse_wmbus_records(&payload_to_parse);

        let dll_info = DllHeaderInfo {
            manufacturer_code: header.manufacturer_code(),
            device_type_raw: header.device_type,
            version: header.version,
        };

        Ok(ProcessResult {
            driver_name: "MeterXDriver".to_string(),
            manufacturer: header.manufacturer_code(),
            device_type: header.device_type,
            dll: dll_info,
            parsed_measurements,
            payload_fields: json!({}),
        })
    }
}