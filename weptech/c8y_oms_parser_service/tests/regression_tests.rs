// tests/regression_tests.rs
//
// Regression tests for parser / decryption bugs. Each test fails on the
// code before the corresponding fix.

use c8y_oms_parser_service::registry::build_driver_registry;
use c8y_oms_parser_service::traits::{parse_vif, parse_wmbus_records, ParsedMeasurements};

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
