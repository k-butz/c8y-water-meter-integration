// Defines core data structures, error types, and the driver interface (MeterDriver).
//
// src/traits.rs

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Header too short (minimum 10 bytes required)")]
    HeaderTooShort,

    #[error("Header error: {0}")]
    HeaderError(String),

    #[error("No matching driver found for M-Field: {manufacturer}, Device Type: {device_type:#04x}, Version: {version:#04x}")]
    NoMatchingDriver {
        manufacturer: String,
        device_type: u8,
        version: u8,
    },

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid frame structure: {0}")]
    InvalidFrame(String),

    #[error("Invalid header offset")]
    InvalidHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeterIdentifier {
    pub manufacturer: String,
    pub device_type: Option<u8>,
    pub version: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedMeasurements {
    pub header_raw: String,
    pub storage_no: u32,
    pub tariff: u32,
    pub device: u32,
    pub dib: String,
    pub vib: String,
    pub value: String,
    pub unit: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllHeaderInfo {
    pub manufacturer_code: String,
    pub device_type_raw: u8,
    pub version: u8,
}

#[derive(Debug, Clone)]
pub struct DllHeader {
    pub length: u8,
    pub c_field: u8,
    pub m_field: [u8; 2],
    pub a_field: [u8; 6],
    pub version: u8,
    pub device_type: u8,
}

impl DllHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 10 {
            return Err(ParseError::HeaderTooShort);
        }

        let mut m_field = [0u8; 2];
        m_field.copy_from_slice(&bytes[2..4]);

        let mut a_field = [0u8; 6];
        a_field.copy_from_slice(&bytes[4..10]);

        Ok(Self {
            length: bytes[0],
            c_field: bytes[1],
            m_field,
            a_field,
            version: bytes[8],
            device_type: bytes[9],
        })
    }

    pub fn manufacturer_code(&self) -> String {
        let m = u16::from_le_bytes(self.m_field);
        let c1 = (((m >> 10) & 0x1F) as u8 + 64) as char;
        let c2 = (((m >> 5) & 0x1F) as u8 + 64) as char;
        let c3 = ((m & 0x1F) as u8 + 64) as char;
        format!("{}{}{}", c1, c2, c3)
    }

    pub fn manufacturer_hex(&self) -> String {
        format!("{:02X}{:02X}", self.m_field[1], self.m_field[0])
    }
}

// ============================================================================
// MBUS DECODING HELPERS
// ============================================================================

/// Helper to parse Little-Endian BCD bytes into a floating-point number.
/// Decodes 2-digit (1B), 4-digit (2B), 6-digit (3B), 8-digit (4B), and 12-digit (6B) BCD fields.
pub fn parse_bcd_bytes(data: &[u8]) -> f64 {
    let mut val: u64 = 0;
    let mut mult: u64 = 1;

    for &byte in data {
        let low = (byte & 0x0F) as u64;
        let high = ((byte >> 4) & 0x0F) as u64;

        // Fallback for non-standard BCD hex filler (e.g. 0xF)
        let low = if low > 9 { 0 } else { low };
        let high = if high > 9 { 0 } else { high };

        val += (low + high * 10) * mult;
        mult *= 100;
    }

    val as f64
}

fn parse_mbus_date(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let raw_u16 = u16::from_le_bytes([bytes[0], bytes[1]]);

    // 0xFFFF is the standard M-Bus sentinel for "Date Not Set"
    if raw_u16 == 0xFFFF {
        return Some("Unset".to_string());
    }

    let day = (raw_u16 & 0x1F) as u32;
    let month = ((raw_u16 >> 8) & 0x0F) as u32;
    let year = (((raw_u16 >> 5) & 0x07) | ((raw_u16 >> 9) & 0x78)) as u32 + 2000;

    if (1..=12).contains(&month) && (1..=31).contains(&day) {
        return Some(format!("{:04}-{:02}-{:02}", year, month, day));
    }

    None
}

fn parse_mbus_datetime_f(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 {
        return None;
    }
    let min = (bytes[0] & 0x3F) as u32;
    let hour = (bytes[1] & 0x1F) as u32;
    let day = (bytes[2] & 0x1F) as u32;

    let year_low = (bytes[2] >> 5) & 0x07;
    let year_high = (bytes[3] >> 4) & 0x0F;
    let year_offset = ((year_high << 3) | year_low) as i32;
    let year = 2000 + year_offset;

    let month = (bytes[3] & 0x0F) as u32;

    if (1..=12).contains(&month) && (1..=31).contains(&day) && hour < 24 && min < 60 {
        return Some(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:00",
            year, month, day, hour, min
        ));
    }

    None
}

/// Helper to parse DIF and DIFE stack metadata (Storage Number, Tariff, Device)
fn parse_dif_dife_metadata(dif_stack: &[u8]) -> (u32, u32, u32) {
    if dif_stack.is_empty() {
        return (0, 0, 0);
    }

    let mut storage_no = ((dif_stack[0] >> 6) & 0x01) as u32;
    let mut tariff = 0u32;
    let mut device = 0u32;

    if dif_stack.len() > 1 {
        let dife1 = dif_stack[1];
        storage_no |= ((dife1 & 0x0F) as u32) << 1;
        tariff = ((dife1 >> 4) & 0x03) as u32;
        device = ((dife1 >> 6) & 0x01) as u32;
    }

    if dif_stack.len() > 2 {
        let dife2 = dif_stack[2];
        storage_no |= ((dife2 & 0x0F) as u32) << 5;
        tariff |= (((dife2 >> 4) & 0x03) as u32) << 2;
    }

    (storage_no, tariff, device)
}

/// Evaluates standard VIF / VIFE descriptors for measurement descriptions, units, and scales.
pub fn parse_vif(primary_vif: u8, vif_stack: &[u8]) -> (String, String, f64) {
    let base_vif = primary_vif & 0x7F;

    // FD Extension VIFs (0xFD & 0x7F = 0x7D)
    if base_vif == 0x7D && vif_stack.len() > 1 {
        let vife = vif_stack[1] & 0x7F;
        match vife {
            0x17 => return ("Error Flags".to_string(), "none".to_string(), 1.0),
            0x74 => return ("Remaining Battery Lifetime".to_string(), "days".to_string(), 1.0),
            _ => return ("Extension Metric".to_string(), "raw".to_string(), 1.0),
        }
    }

    match base_vif {
        // Volume (0x10 .. 0x17)
        0x10..=0x17 => {
            let exp = (base_vif & 0x07) as i32 - 6;
            let scale = 10f64.powi(exp);

            let desc = if vif_stack.len() > 1 {
                match vif_stack[1] & 0x7F {
                    0x3B => "Forward Volume".to_string(),
                    0x3C => "Backward Volume".to_string(),
                    _ => "Volume".to_string(),
                }
            } else {
                "Volume".to_string()
            };

            (desc, "m³".to_string(), scale)
        }

        // Energy (0x00 .. 0x07): 10^(nnn-3) Wh = 10^(nnn-6) kWh
        0x00..=0x07 => {
            let exp = (base_vif & 0x07) as i32 - 6;
            let scale = 10f64.powi(exp);
            ("Energy".to_string(), "kWh".to_string(), scale)
        }

        // Operating Time (0x20..=0x23)
        0x20..=0x23 => {
            let scale = match base_vif & 0x03 {
                0 => 1.0,
                1 => 60.0,
                2 => 3600.0,
                3 => 86400.0,
                _ => 1.0,
            };
            ("Operating Time".to_string(), "seconds".to_string(), scale)
        }

        // On Time Duration (0x24..=0x27)
        0x24..=0x27 => {
            let scale = match base_vif & 0x03 {
                0 => 1.0,
                1 => 60.0,
                2 => 3600.0,
                3 => 86400.0,
                _ => 1.0,
            };
            ("On Time Duration".to_string(), "seconds".to_string(), scale)
        }

        // Volume Flow (0x38 .. 0x3F)
        0x38..=0x3F => {
            let exp = (base_vif & 0x07) as i32 - 6;
            let scale = 10f64.powi(exp);
            ("Current Flow".to_string(), "m³/h".to_string(), scale)
        }

        // Flow Temperature (0x58 .. 0x5B)
        0x58..=0x5B => {
            let exp = (base_vif & 0x03) as i32 - 3;
            let scale = 10f64.powi(exp);
            ("Flow Temperature".to_string(), "°C".to_string(), scale)
        }

        // Return Temperature (0x5C .. 0x5F)
        0x5C..=0x5F => {
            let exp = (base_vif & 0x03) as i32 - 3;
            let scale = 10f64.powi(exp);
            ("Return Temperature".to_string(), "°C".to_string(), scale)
        }

        // Date / DateTime (0x6C, 0x6D)
        0x6C | 0x6D => ("Date and Time".to_string(), "".to_string(), 1.0),

        _ => ("Unknown Metric".to_string(), "raw".to_string(), 1.0),
    }
}

fn evaluate_record(
    primary_dif: u8,
    primary_vif: u8,
    vif_stack: &[u8],
    data_segment: &[u8],
) -> (String, String, String) {
    let base_vif = primary_vif & 0x7F;

    // Check for Date and Time records before numeric processing
    if base_vif == 0x6D && data_segment.len() >= 4 {
        if let Some(dt) = parse_mbus_datetime_f(data_segment) {
            return ("Date and Time".to_string(), "".to_string(), dt);
        }
    } else if base_vif == 0x6C && data_segment.len() >= 2 {
        if let Some(date_str) = parse_mbus_date(data_segment) {
            return ("Target Date".to_string(), "".to_string(), date_str);
        }
    }

    let data_type = primary_dif & 0x0F;

    // 1. Decode numeric raw value according to DIF data type
    let raw_val: f64 = match data_type {
        // Binary Integer types
        0x01 => data_segment.first().map(|&b| b as i8 as f64).unwrap_or(0.0),
        0x02 => {
            if data_segment.len() >= 2 {
                i16::from_le_bytes([data_segment[0], data_segment[1]]) as f64
            } else {
                0.0
            }
        }
        0x03 => {
            if data_segment.len() >= 3 {
                i32::from_le_bytes([data_segment[0], data_segment[1], data_segment[2], 0]) as f64
            } else {
                0.0
            }
        }
        0x04 => {
            if data_segment.len() >= 4 {
                i32::from_le_bytes([
                    data_segment[0],
                    data_segment[1],
                    data_segment[2],
                    data_segment[3],
                ]) as f64
            } else {
                0.0
            }
        }

        // BCD Data Types (0x09=2B, 0x0A=4B, 0x0B=6B, 0x0C=8B, 0x0E=12B BCD)
        0x09 | 0x0A | 0x0B | 0x0C | 0x0E => parse_bcd_bytes(data_segment),

        // 32-bit Float
        0x05 => {
            if data_segment.len() >= 4 {
                f32::from_le_bytes([
                    data_segment[0],
                    data_segment[1],
                    data_segment[2],
                    data_segment[3],
                ]) as f64
            } else {
                0.0
            }
        }
        _ => 0.0,
    };

    // 2. Map VIF / VIFE unit and scale factor
    let (description, unit, scale) = parse_vif(primary_vif, vif_stack);

    let final_val = raw_val * scale;
    let formatted_val = format!("{:.6}", final_val)
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string();

    let formatted_val = if formatted_val.is_empty() || formatted_val == "-" {
        "0".to_string()
    } else {
        formatted_val
    };

    (description, unit, formatted_val)
}

// ============================================================================
// PUBLIC MBUS STREAM PARSER
// ============================================================================

pub fn parse_wmbus_records(raw_bytes: &[u8]) -> Vec<ParsedMeasurements> {
    let mut processed_records = Vec::new();
    if raw_bytes.is_empty() {
        return processed_records;
    }

    let mut idx = 0;

    // Fast-forward initial transport header (0x7A/0x78 = 5 bytes, 0x72/0x73/0x7E = 13 bytes) or filler bytes (0x2F)
    if raw_bytes.len() >= 2 && raw_bytes[0] == 0x2F && raw_bytes[1] == 0x2F {
        while idx < raw_bytes.len() && raw_bytes[idx] == 0x2F {
            idx += 1;
        }
    } else if raw_bytes.len() >= 4 {
        match raw_bytes[0] {
            0x78 | 0x7A => idx = 5,
            0x72 | 0x73 | 0x7E => idx = 13,
            _ => {
                if raw_bytes.len() >= 12 && (raw_bytes[10] == 0x78 || raw_bytes[10] == 0x7A) {
                    idx = 15;
                } else if raw_bytes.len() >= 12 && (raw_bytes[10] == 0x72 || raw_bytes[10] == 0x7E) {
                    idx = 23;
                } else {
                    idx = 0;
                }
            }
        }
    }

    while idx < raw_bytes.len() {
        let start_idx = idx;
        let dif = raw_bytes[idx];

        if dif == 0x2F {
            idx += 1;
            continue;
        }

        if dif == 0x0F || dif == 0x1F {
            break;
        }

        // 1. Traverse DIF & DIFE stack
        let mut dif_stack = Vec::new();
        loop {
            if idx >= raw_bytes.len() {
                break;
            }
            let byte = raw_bytes[idx];
            idx += 1;
            dif_stack.push(byte);
            if (byte & 0x80) == 0 {
                break;
            }
        }

        if idx >= raw_bytes.len() {
            break;
        }

        // 2. Traverse VIF & VIFE stack
        let mut vif_stack = Vec::new();
        loop {
            if idx >= raw_bytes.len() {
                break;
            }
            let byte = raw_bytes[idx];
            idx += 1;
            vif_stack.push(byte);
            if (byte & 0x80) == 0 {
                break;
            }
        }

        let header_end_idx = idx;
        let header_bytes = &raw_bytes[start_idx..header_end_idx];
        let header_raw_hex = hex::encode(header_bytes).to_uppercase();

        let primary_dif = dif_stack[0];
        let primary_vif = vif_stack[0];

        let data_type = primary_dif & 0x0F;

        let data_len = match data_type {
            0x00 => 0,
            0x01 | 0x09 => 1,
            0x02 | 0x0A => 2,
            0x03 | 0x0B => 3,
            0x04 | 0x0C | 0x05 => 4,
            0x06 | 0x0E => 6,
            0x07 | 0x0F => 8,
            0x0D => {
                if idx < raw_bytes.len() {
                    let len = raw_bytes[idx] as usize;
                    idx += 1;
                    len
                } else {
                    0
                }
            }
            _ => 0,
        };

        if idx + data_len > raw_bytes.len() {
            break;
        }

        let data_segment = &raw_bytes[idx..idx + data_len];
        idx += data_len;

        let (storage_no, tariff, device) = parse_dif_dife_metadata(&dif_stack);

        let (name, unit, value) = evaluate_record(
            primary_dif,
            primary_vif,
            &vif_stack,
            data_segment,
        );

        processed_records.push(ParsedMeasurements {
            header_raw: header_raw_hex,
            storage_no,
            tariff,
            device,
            dib: format!("{:02X}", primary_dif),
            vib: format!("{:02X}", primary_vif),
            value,
            unit,
            description: name,
        });
    }

    processed_records
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessResult {
    pub driver_name: String,
    pub manufacturer: String,
    pub device_type: u8,
    pub dll: DllHeaderInfo,
    pub parsed_measurements: Vec<ParsedMeasurements>,
    pub payload_fields: serde_json::Value,
}

pub trait MeterDriver: Send + Sync {
    fn supports(&self, header: &DllHeader) -> bool;
    fn parse(
        &self,
        raw_payload: &[u8],
        oms_mode: Option<u8>,
        key: Option<&[u8]>,
    ) -> Result<ProcessResult, ParseError>;
}