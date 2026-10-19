// src/drivers/diehl.rs

use serde_json::json;
use crate::security::{EncryptionMode, SecurityEngine};
use crate::traits::{
    parse_wmbus_records, DllHeader, DllHeaderInfo, MeterDriver, ParseError, ProcessResult,
};

pub struct DiehlDriver;

impl DiehlDriver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DiehlDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MeterDriver for DiehlDriver {
    fn supports(&self, header: &DllHeader) -> bool {
        // Match both Diehl Metering (DME) and legacy Hydrometer (HYD) manufacturer codes
        matches!(header.manufacturer_code().as_str(), "DME" | "HYD")
    }

    fn parse(
        &self,
        raw_payload: &[u8],
        oms_mode: Option<u8>,
        key: Option<&[u8]>,
    ) -> Result<ProcessResult, ParseError> {
        let header = DllHeader::from_bytes(raw_payload)?;

        // Standard DLL Header length is 10 bytes
        const HEADER_OFFSET: usize = 10;

        if raw_payload.len() < HEADER_OFFSET {
            return Err(ParseError::HeaderTooShort);
        }

        // Determine effective mode and decrypt if key is supplied or mode demands it
        let effective_mode = oms_mode.unwrap_or_else(|| if key.is_some() { 7 } else { 0 });

        let mode = EncryptionMode::from(Some(effective_mode));
        let decrypted_payload =
            SecurityEngine::decrypt_payload(mode, raw_payload, HEADER_OFFSET, key)?;

        // Debug log decrypted byte stream
        tracing::info!("Decrypted Payload Hex: {}", hex::encode(&decrypted_payload).to_uppercase());

        // Parse wM-Bus data records from payload
        let mut parsed_measurements = parse_wmbus_records(&decrypted_payload);

        // Diehl-specific record post-processing
        for rec in &mut parsed_measurements {
            // 1. Target Billing Volume (0x4C13 / 0x4C933C with sentinel 0xAAAAAAAA)
            if rec.header_raw.starts_with("4C13") || rec.header_raw.starts_with("4C933C") {
                if rec.value == "0" {
                    rec.description = "Target Volume (Unset)".to_string();
                    rec.value = "Unset".to_string();
                    rec.unit = "".to_string();
                } else {
                    rec.description = "Target Volume".to_string();
                }
            }

            // 2. Target Billing Date (0x426C)
            if rec.header_raw.starts_with("426C") {
                if rec.value == "Unset" || rec.value == "-1" {
                    rec.description = "Target Billing Date (Unset)".to_string();
                    rec.value = "Unset".to_string();
                    rec.unit = "".to_string();
                }
            }
        }

        let dll_info = DllHeaderInfo {
            manufacturer_code: header.manufacturer_code(),
            device_type_raw: header.device_type,
            version: header.version,
        };

        Ok(ProcessResult {
            driver_name: "DiehlDriver".to_string(),
            manufacturer: header.manufacturer_code(),
            device_type: header.device_type,
            dll: dll_info,
            parsed_measurements,
            payload_fields: json!({
                "mode": effective_mode,
            }),
        })
    }
}