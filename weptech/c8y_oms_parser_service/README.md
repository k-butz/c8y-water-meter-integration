# c8y-oms-parser Microservice

A high-performance, containerized Rust microservice built on **Axum** and **Tokio** designed for Cumulocity. It parses, decrypts (Mode 5 / Mode 7), and extracts telemetric records from Wireless M-Bus (wM-Bus) and Open Metering System (OMS) payloads.

---
## Features
* **Multi-Mode Decryption Support**: Engineered to parse unencrypted payloads as well as encrypted wM-Bus/OMS data streams utilizing Mode 5 (AES-CBC) and Mode 7 (AES-CBC with CMAC-based key derivation, KDF A).
* **Driver Registry Architecture**: Extensible, trait-based driver dispatch system (`MeterDriver`) supporting manufacturer-specific profiles (ex: Diehl, Axioma).
* **DIF/VIF Record Parsing**: Decodes standard and extended M-Bus data structures including Volume, Energy, Flow Rates, Temperatures, Time, Diagnostic Alarm Vectors, and Battery Status.
* **Exact Field & Record Tracking**: Exposes `header_raw`, `dib`, `vib`, `storage_no`, `tariff`, and `device` indices for every measurement, enabling upstream applications to differentiate identical physical quantities (e.g., Forward vs. Return Flow).
* **Enterprise Auditability & Key Masking**: Integrated `tracing` structured logging that automatically redacts sensitive AES keys and cleans payload attributes for secure, non-ANSI Cloud Logging Compliance.
* **Low Footprint & Async Throughput**: Built in pure Rust on top of Axum/Tokio for near-zero memory footprint and ultra-fast, concurrent execution under high-volume IoT microservice loads.
---

## Architecture & Integration Flow

```
  +-------------------------------------------------------------+
  |                   Cumulocity Platform.                      |
  +-------------------------------------------------------------+
                                |
                   HTTP POST /api/v1/parse
                   (Base64 Payload + Key + OMS Mode)
                                |
                                v
  +-------------------------------------------------------------+
  |                    Axum Web Framework                       |
  |  - Request Auditing & Sensitive Key Masking (`main.rs`)     |
  +-------------------------------------------------------------+
                                |
                                v
  +-------------------------------------------------------------+
  |                     DriverRegistry                          |
  |  - Header Extraction (M-Field, Device Type, Version)        |
  |  - Driver Dispatch (first driver whose supports() matches)  |
  +-------------------------------------------------------------+
         /                      |                      \
        v                       v                       v
+---------------+       +---------------+       +---------------+
| Axioma Driver |       | Diehl Driver  |       | MeterX Driver |
|  (AXI / ASI)  |       |   (HYDRUS)    |       |     (MTX)     |
+---------------+       +---------------+       +---------------+
```
### Integration & Processing Flow
1. **Payload Ingestion**: Cumulocity forwards incoming LNS/Gateway payloads (`POST /api/v1/parse`) containing base64 frames and optional AES encryption keys.
2. **Middleware & Masking**: Axum handles incoming requests, logs execution metrics, and masks sensitive `encryptionkey` values before writing audit records.
3. **Header Inspection**: `DriverRegistry` extracts M-Bus Data Link Layer (DLL) header parameters (Manufacturer M-Field, Device Type, and Version).
4. **Driver Selection**: Registered drivers are checked in registration order. The first driver whose `supports()` matches the DLL header parses the telegram. If no driver matches, the request fails with `422`.
5. **Decryption & Deframe**: The selected driver handles Mode 5 (AES-CBC) or Mode 7 (AES-CBC with CMAC-based key derivation) payload decryption.
6. **Measurement Extraction**: Records are converted into structured measurement objects containing values, units, tariffs, and storage numbers, then returned as JSON to Cumulocity.

### Core Characteristics
* **Runtime**: Axum on Tokio (Async I/O).
* **Target Container**: Docker (`linux/amd64`), binding on port `80`.
* **Logging & Auditing**: Non-ANSI, JSON-friendly structured logs (`tracing`) with automatic AES key redaction.
* **Extensibility**: Trait-based `MeterDriver` pattern enabling fast support for new manufacturer profiles without breaking core OMS parsing.
---

## Supported Drivers & Meters

| Driver Name | Manufacturer Code (M-Field) | Target Hardware | Decryption Support |
| :--- | :--- | :--- | :--- |
| **`DiehlDriver`** | `DME` / `HYD` | Diehl HYDRUS Ultrasonic Water Meter | Mode 7 (AES-CBC, KDF A) |
| **`AxiomaDriver`** | `AXI` / `ASI` | Axioma Qalcosonic W1 | Unencrypted, Mode 5 |
| **`MeterXDriver`** | `MTX` | Not specified | Unencrypted, Mode 5, Mode 7 (per `oms_mode`) |

There is no generic fallback driver: telegrams from other manufacturers are rejected with `422`.

---
## HeaderRaw Reference Map
When mapping outputs in downstream Cumulocity microservices, any other external service, match against the `header_raw` field in extracted measurements:
| `header_raw` | Description | Typical Unit | JSON Value Example |
| :--- | :--- | :--- | :--- |
| `046D` | Date and Time string | ISO8601 | `2026-08-04T10:00:00Z` |
| `0413` | Standard Volume | `m³` | `1245.892` |
| `0420` | Meter Operating Time | `seconds` | `2568600.00` |
| `023B` | Volume Flow Rate | `m³/h` | `1.250` |
| `0259` | Flow Temperature | `°C` | `18.5` |
| `0A5A` | Flow Temperature | `°C` | `18.5` |
| `01FD74` | Remaining Battery Life | `days` | `97` |
| `02FD74` | Remaining Battery Life | `days` | `97` |
---
## REST API Specification

### Endpoint: `POST /api/v1/parse`

#### Request Payload
```json
{
  "payload": "iAEEA2k...",
  "oms_mode": 7,
  "encryptionkey": "00112233445566778899AABBCCDDEEFF"
}
```

* `payload` *(string, required)*: Base64-encoded raw wM-Bus radio frame.
* `oms_mode` *(number)*: Security mode override (`5` or `7`).
* `encryptionkey` *(string, optional)*: Hex-encoded AES key.

#### Successful Response (`200 OK`)
```json
{
  "status": "success",
  "data": {
    "driver_name": "DiehlDriver",
    "manufacturer": "DME",
    "device_type": 7,
    "dll": {
      "manufacturer_code": "DME",
      "device_type_raw": 7,
      "version": 99
    },
    "parsed_measurements": [
    {
        "header_raw": "0C13",
        "storage_no": 0,
        "tariff": 0,
        "device": 0,
        "dib": "0C",
        "vib": "13",
        "value": "0.2",
        "unit": "m³",
        "description": "Volume"
      },
      {
        "header_raw": "0A5A",
        "storage_no": 0,
        "tariff": 0,
        "device": 0,
        "dib": "0A",
        "vib": "5A",
        "value": "29",
        "unit": "°C",
        "description": "Flow Temperature"
      }
    ]
  },
  "error": null
}
```

#### Error Responses
* **`400 Bad Request`**: Base64 decoding error or invalid hex encryption key.
* **`422 Unprocessable Entity`**: Payload cannot be parsed or no compatible driver claimed the header.


---


## Adding Support for New Meters

Each manufacturer is handled by a driver implementing the `MeterDriver` trait (`src/traits.rs`):

```rust
pub trait MeterDriver: Send + Sync {
    fn supports(&self, header: &DllHeader) -> bool;
    fn parse(
        &self,
        raw_payload: &[u8],
        oms_mode: Option<u8>,
        key: Option<&[u8]>,
    ) -> Result<ProcessResult, ParseError>;
}
```

`supports()` decides from the DLL header whether the driver handles the telegram. `parse()` decrypts the payload via `SecurityEngine` and extracts the records with `parse_wmbus_records`.

### Step 1: Create the driver (`src/drivers/custom_vendor.rs`)

The simplest starting point is a copy of `src/drivers/meter_x.rs`, which contains only the standard decryption and record parsing. Rename the struct and adjust `supports()`:

```rust
impl MeterDriver for CustomVendorDriver {
    fn supports(&self, header: &DllHeader) -> bool {
        // Three-letter manufacturer code from the M-field
        header.manufacturer_code() == "ABC"
    }

    // parse(): as in meter_x.rs, plus vendor-specific post-processing
    // of the parsed records if needed (see diehl.rs for an example)
}
```

### Step 2: Expose the module (`src/drivers/mod.rs`)

```rust
pub mod custom_vendor;
```

### Step 3: Register the driver (`src/registry.rs`)

Drivers are checked in registration order, so register specific drivers before broader ones:

```rust
use crate::drivers::custom_vendor::CustomVendorDriver;

pub fn build_driver_registry() -> DriverRegistry {
    let mut registry = DriverRegistry::new();

    registry.register(Box::new(AxiomaDriver::new()));
    registry.register(Box::new(DiehlDriver::new()));
    registry.register(Box::new(MeterXDriver::new()));
    registry.register(Box::new(CustomVendorDriver::new()));

    registry
}
```

### Step 4: Add a test (`tests/`)

Use a real telegram of the meter, as in `tests/meter_payload_tests.rs`:

```rust
use base64::engine::general_purpose;
use base64::Engine;
use c8y_oms_parser_service::registry::build_driver_registry;

#[test]
fn test_custom_vendor_parsing() {
    let registry = build_driver_registry();
    let raw_payload = general_purpose::STANDARD.decode("...").unwrap();

    let result = registry.process(&raw_payload, None, None).unwrap();
    assert_eq!(result.driver_name, "CustomVendorDriver");
}
```

---

## Building and Packaging

Cumulocity microservices require a **Linux x86_64 Docker container** packaged inside a `.zip` archive alongside a `cumulocity.json` manifest.

### Prerequisites
- [Rust & Cargo](https://www.rust-lang.org/)
- [Docker](https://www.docker.com/)
- `zip` utility

---

### Step 1: Check the `cumulocity.json` Manifest
The manifest is part of this project (`cumulocity.json`). It defines the application name, version, isolation, resources and health probes.

---

### Step 2: Build Local Docker Image
Build the container using multi-stage builds for small binary footprints:

```bash
docker build --platform linux/amd64 -t c8y-oms-parser:latest .
```

---

### Step 3: Package for Cumulocity

Cumulocity expects the Docker image saved as `image.tar` zipped together with `cumulocity.json`:

```bash
# 1. Export the Docker image as a tarball
docker save c8y-oms-parser:latest -o image.tar

# 2. Compress image.tar and cumulocity.json into a deployable zip file
zip c8y-oms-parser.zip image.tar cumulocity.json

# 3. Clean up the intermediary tar archive
rm image.tar
```

---

## Deployment to Cumulocity

1. Log into your **Cumulocity Tenant**.
2. Go to **Administration** -> **Ecosystem** -> **Microservices**.
3. Click **Add Microservice** and upload \`c8y-oms-parser.zip\`.
4. Verify that the health status turns **Green / UP**.

