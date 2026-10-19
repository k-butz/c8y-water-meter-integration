// src/drivers/axioma.rs

use serde_json::json;
use crate::security::{EncryptionMode, SecurityEngine};
use crate::traits::{
    parse_wmbus_records, DllHeader, DllHeaderInfo, MeterDriver, ParseError, ProcessResult,
};

pub struct AxiomaDriver;

impl AxiomaDriver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AxiomaDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MeterDriver for AxiomaDriver {
    fn supports(&self, header: &DllHeader) -> bool {
        let code = header.manufacturer_code();
        code == "AXI" || code == "ASI" || header.manufacturer_hex() == "0907"
    }

    fn parse(
        &self,
        raw_payload: &[u8],
        oms_mode: Option<u8>,
        key: Option<&[u8]>,
    ) -> Result<ProcessResult, ParseError> {
        let header = DllHeader::from_bytes(raw_payload)?;

        // If no key is provided, parse unencrypted (encrypted frames are rejected)
        let mode = if key.is_none() {
            EncryptionMode::None
        } else {
            EncryptionMode::from(oms_mode)
        };

        let decrypted_payload =
            SecurityEngine::decrypt_payload(mode, raw_payload, 10, key)?;

        let parsed_measurements = parse_wmbus_records(&decrypted_payload);

        let dll_info = DllHeaderInfo {
            manufacturer_code: header.manufacturer_code(),
            device_type_raw: header.device_type,
            version: header.version,
        };

        Ok(ProcessResult {
            driver_name: "AxiomaDriver".to_string(),
            manufacturer: header.manufacturer_code(),
            device_type: header.device_type,
            dll: dll_info,
            parsed_measurements,
            payload_fields: json!({
                "decrypted_length": decrypted_payload.len(),
            }),
        })
    }
}