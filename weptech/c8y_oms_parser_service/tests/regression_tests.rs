// tests/regression_tests.rs
//
// Regression tests for parser / decryption bugs. Each test fails on the
// code before the corresponding fix.

use c8y_oms_parser_service::registry::build_driver_registry;
use c8y_oms_parser_service::traits::{parse_vif, parse_wmbus_records, ParsedMeasurements};

const MODE7_KEY: &str = "00112233445566778899AABBCCDDEEFF";

/// Synthetic Mode 7 telegram (M=DME, ID 12345678, MCR 1) with the same
/// plaintext as `axioma_mode5_frame`. Kenc = CMAC(MODE7_KEY, 00 || MCR || ID
/// || 07*7) = A743BC414BA92837575C4FFACC9E2F87 and the ciphertext were
/// computed with `openssl mac ... CMAC` and `openssl enc -aes-128-cbc -iv 0`.
fn mode7_frame() -> Vec<u8> {
    let mut frame = vec![0x00, 0x44, 0xA5, 0x11, 0x78, 0x56, 0x34, 0x12, 0x01, 0x07];
    frame.extend_from_slice(&[0x8C, 0x00, 0x33]); // ELL
    frame.extend_from_slice(&[0x90, 0x0F, 0x00, 0x2C, 0x25]); // AFL, FCL, MCL
    frame.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // MCR
    frame.extend_from_slice(&[0x00; 8]); // MAC
    frame.extend_from_slice(&[0x7A, 0x33, 0x00, 0x10, 0x07, 0x10]); // TPL: mode 7, 1 block, KDF A
    frame.extend(hex::decode("44f91571d1f78fd26180bdc8795d469b").unwrap());
    frame[0] = (frame.len() - 1) as u8;
    frame
}

/// Builds a full wM-Bus frame for the Axioma meter (M=AXI, ID 09724574,
/// version 0x20, type 0x07) from everything after the DLL header and sets L.
fn axioma_frame(after_dll: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x00, 0x44, 0x09, 0x07, 0x74, 0x45, 0x72, 0x09, 0x20, 0x07];
    frame.extend_from_slice(after_dll);
    frame[0] = (frame.len() - 1) as u8;
    frame
}

fn find<'a>(records: &'a [ParsedMeasurements], header: &str) -> &'a ParsedMeasurements {
    records
        .iter()
        .find(|r| r.header_raw == header)
        .unwrap_or_else(|| panic!("record {} missing in {:?}", header, records))
}

/// Plaintext 2F2F 0413 10270000 02FD74 2F00 2F2F2F, encrypted with
/// `openssl enc -aes-128-cbc -nopad -K 000102030405060708090A0B0C0D0E0F
///  -iv 0907744572092007 3333333333333333`.
fn axioma_mode5_frame() -> Vec<u8> {
    let mut after_dll = vec![0x7A, 0x33, 0x00, 0x10, 0x05]; // ACC=0x33, CF: mode 5, 1 block
    after_dll.extend(hex::decode("0555a3c2c92cbf949bcf51aabc6b10a6").unwrap());
    axioma_frame(&after_dll)
}

#[test]
fn mode5_decrypts_with_oms_iv_and_tpl_offset() {
    let key = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let result = build_driver_registry()
        .process(&axioma_mode5_frame(), Some(5), Some(&key))
        .expect("Mode 5 frame must decrypt");

    let records = &result.parsed_measurements;
    assert_eq!(records.len(), 2, "{:?}", records);
    assert_eq!(find(records, "0413").value, "10");
    // Data byte 0x2F followed by AES filler 0x2F2F2F
    assert_eq!(find(records, "02FD74").value, "47");
}

#[test]
fn mode5_long_tpl_header_uses_tpl_address_for_iv() {
    // DLL address (radio module 44332211) differs from the meter address in
    // the long TPL header. The TPL fields give the same IV as
    // `axioma_mode5_frame`, so the same ciphertext must decrypt.
    let mut frame = vec![0x00, 0x44, 0x09, 0x07, 0x11, 0x22, 0x33, 0x44, 0x01, 0x37];
    frame.extend_from_slice(&[0x72, 0x74, 0x45, 0x72, 0x09, 0x09, 0x07, 0x20, 0x07]); // CI ID M VER TYPE
    frame.extend_from_slice(&[0x33, 0x00, 0x10, 0x05]); // ACC STS CF: mode 5, 1 block
    frame.extend(hex::decode("0555a3c2c92cbf949bcf51aabc6b10a6").unwrap());
    frame[0] = (frame.len() - 1) as u8;

    let key = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let result = build_driver_registry()
        .process(&frame, Some(5), Some(&key))
        .expect("Mode 5 frame with long TPL header must decrypt");

    assert_eq!(find(&result.parsed_measurements, "0413").value, "10");
    assert_eq!(find(&result.parsed_measurements, "02FD74").value, "47");
}

#[test]
fn encrypted_frame_without_key_is_rejected() {
    let registry = build_driver_registry();
    let frame = axioma_mode5_frame();

    assert!(registry.process(&frame, Some(5), None).is_err());
    assert!(registry.process(&frame, None, None).is_err());
}

#[test]
fn mode7_wrong_key_is_rejected() {
    let registry = build_driver_registry();
    let key = hex::decode(MODE7_KEY).unwrap();
    assert!(registry.process(&mode7_frame(), Some(7), Some(&key)).is_ok());

    let result = registry.process(&mode7_frame(), Some(7), Some(&[0u8; 16]));
    assert!(result.is_err(), "wrong key produced: {:?}", result);
}

#[test]
fn mode5_wrong_key_is_rejected() {
    let result = build_driver_registry().process(&axioma_mode5_frame(), Some(5), Some(&[0u8; 16]));
    assert!(result.is_err(), "wrong key produced: {:?}", result);
}

#[test]
fn ci_0x78_has_no_tpl_header() {
    let frame = axioma_frame(&[0x78, 0x04, 0x13, 0x10, 0x27, 0x00, 0x00]);
    let result = build_driver_registry().process(&frame, None, None).unwrap();

    assert_eq!(result.parsed_measurements.len(), 1, "{:?}", result.parsed_measurements);
    assert_eq!(find(&result.parsed_measurements, "0413").value, "10");
}

#[test]
fn unencrypted_trailing_0x2f_data_byte_is_kept() {
    let frame = axioma_frame(&[0x7A, 0x33, 0x00, 0x00, 0x00, 0x01, 0xFD, 0x74, 0x2F]);
    let result = build_driver_registry().process(&frame, None, None).unwrap();

    assert_eq!(find(&result.parsed_measurements, "01FD74").value, "47");
}

#[test]
fn record_data_is_not_mistaken_for_tpl_header() {
    // Decrypted application data (no CI byte). Byte 10 is 0x7A, which the
    // header heuristic took for a CI field and skipped 15 bytes.
    let records = [
        0x04, 0x13, 0x10, 0x27, 0x00, 0x00, // Volume 10 m³
        0x02, 0xFD, 0x74, 0x00, 0x7A, // Battery 0x7A00 days
        0x2F, // AES filler
    ];
    let parsed = parse_wmbus_records(&records);

    assert_eq!(parsed.len(), 2, "{:?}", parsed);
    assert_eq!(find(&parsed, "0413").value, "10");
    assert_eq!(find(&parsed, "02FD74").value, "31232");
}

#[test]
fn energy_vif_scales_to_kwh() {
    // VIF 0x03 = 10^(3-3) Wh = 0.001 kWh
    let (_, unit, scale) = parse_vif(0x03, &[0x03]);
    assert_eq!(unit, "kWh");
    assert!((scale - 0.001).abs() < 1e-12, "scale = {}", scale);

    // VIF 0x06 = 10^(6-3) Wh = 1 kWh
    let (_, _, scale) = parse_vif(0x06, &[0x06]);
    assert!((scale - 1.0).abs() < 1e-12, "scale = {}", scale);
}

#[test]
fn on_time_and_operating_time_are_not_swapped() {
    assert_eq!(parse_vif(0x20, &[0x20]).0, "On Time");
    assert_eq!(parse_vif(0x24, &[0x24]).0, "Operating Time");
}
