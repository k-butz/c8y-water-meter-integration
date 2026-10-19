// tests/regression_tests.rs
//
// Regression tests for parser / decryption bugs. Each test fails on the
// code before the corresponding fix.

use c8y_oms_parser_service::traits::parse_vif;

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
