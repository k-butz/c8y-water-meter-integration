// Handles transport-layer security (Mode 5 AES-CBC & Mode 7 AES-CBC
// with KDF A) and post-decryption verification.
//
// src/security.rs

use aes::Aes128;
use aes::cipher::{
    block_padding::NoPadding,
    BlockDecryptMut,
    KeyIvInit,
};
use cbc::Decryptor;
use cmac::{Cmac, Mac};

use crate::traits::ParseError;

type Aes128CbcDec = Decryptor<Aes128>;
type Aes128Cmac = Cmac<Aes128>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    None,
    Mode5,
    Mode7,
}

impl From<Option<u8>> for EncryptionMode {
    fn from(val: Option<u8>) -> Self {
        match val {
            Some(5) => EncryptionMode::Mode5,
            Some(7) => EncryptionMode::Mode7,
            _ => EncryptionMode::None,
        }
    }
}

// ================================================================
// TRANSPORT LAYER HEADER
// ================================================================

struct TplHeader {
    /// Header length including the CI field
    len: usize,
    access_no: u8,
    cf: u16,
    /// Manufacturer + address used for the Mode 5 IV (None if the frame has no TPL header)
    iv_prefix: Option<[u8; 8]>,
}

impl TplHeader {
    fn security_mode(&self) -> u8 {
        ((self.cf >> 8) & 0x1F) as u8
    }

    fn encrypted_blocks(&self) -> usize {
        ((self.cf >> 4) & 0x0F) as usize
    }
}

// ================================================================
// MODE 7 PARSED SECURITY INFORMATION (Moved to module scope)
// ================================================================

struct Mode7SecurityInfo {
    meter_id: [u8; 4],
    message_counter: [u8; 4],
    ciphertext: Vec<u8>,
}

pub struct SecurityEngine;

impl SecurityEngine {
    /// Returns the application data (data records) following the transport
    /// layer header, decrypted according to `mode`.
    pub fn decrypt_payload(
        mode: EncryptionMode,
        raw_payload: &[u8],
        header_len: usize,
        key: Option<&[u8]>,
    ) -> Result<Vec<u8>, ParseError> {
        if raw_payload.len() <= header_len {
            return Err(ParseError::HeaderError(
                "Payload shorter than specified header length".into(),
            ));
        }

        match mode {
            EncryptionMode::None => {
                let tpl = Self::parse_tpl(raw_payload, header_len)?;

                if tpl.security_mode() != 0 {
                    return Err(ParseError::DecryptionError(format!(
                        "Telegram is encrypted (security mode {}), but no key or OMS mode was given",
                        tpl.security_mode()
                    )));
                }

                Ok(raw_payload[header_len + tpl.len..].to_vec())
            }

            // ---------------------------------------------------------
            // MODE 5
            // ---------------------------------------------------------
            EncryptionMode::Mode5 => {
                let key_bytes = key.ok_or_else(|| {
                    ParseError::DecryptionError(
                        "OMS Mode 5 requires a 128-bit key".into(),
                    )
                })?;

                Self::validate_key(key_bytes)?;

                let tpl = Self::parse_tpl(raw_payload, header_len)?;

                if tpl.security_mode() != 5 {
                    return Err(ParseError::DecryptionError(format!(
                        "Expected Security Mode 5, found Mode {}",
                        tpl.security_mode()
                    )));
                }

                let iv_prefix = tpl.iv_prefix.ok_or_else(|| {
                    ParseError::DecryptionError(
                        "Mode 5 requires a short or long TPL header".into(),
                    )
                })?;

                // IV = M-field + A-field followed by 8x Access Number
                let mut iv = [tpl.access_no; 16];
                iv[0..8].copy_from_slice(&iv_prefix);

                let encrypted_len = tpl.encrypted_blocks() * 16;

                if encrypted_len == 0 {
                    return Err(ParseError::DecryptionError(
                        "Mode 5 configuration specifies zero encrypted blocks".into(),
                    ));
                }

                let ciphertext_start = header_len + tpl.len;
                let ciphertext_end = ciphertext_start + encrypted_len;

                if raw_payload.len() < ciphertext_end {
                    return Err(ParseError::DecryptionError(format!(
                        "Telegram contains only {} bytes after TPL, \
                         but Mode 5 requires {} encrypted bytes",
                        raw_payload.len() - ciphertext_start,
                        encrypted_len
                    )));
                }

                let mut buf = raw_payload[ciphertext_start..ciphertext_end].to_vec();

                let cipher = Aes128CbcDec::new_from_slices(
                    key_bytes,
                    &iv,
                )
                    .map_err(|e| {
                        ParseError::DecryptionError(format!(
                            "Mode 5 cipher initialization failed: {}",
                            e
                        ))
                    })?;

                cipher
                    .decrypt_padded_mut::<NoPadding>(&mut buf)
                    .map_err(|e| {
                        ParseError::DecryptionError(format!(
                            "Mode 5 decryption failed: {:?}",
                            e
                        ))
                    })?;

                Self::verify_plaintext(&buf)?;

                Ok(buf)
            }

            // ---------------------------------------------------------
            // MODE 7
            // ---------------------------------------------------------
            EncryptionMode::Mode7 => {
                let persistent_key = key.ok_or_else(|| {
                    ParseError::DecryptionError(
                        "OMS Mode 7 requires a 128-bit key".into(),
                    )
                })?;

                Self::validate_key(persistent_key)?;

                let security = Self::parse_mode7(raw_payload, header_len)?;

                let kenc = Self::derive_mode7_kenc(
                    persistent_key,
                    &security.message_counter,
                    &security.meter_id,
                )?;

                let iv = [0u8; 16];

                let mut buf = security.ciphertext.to_vec();

                let cipher = Aes128CbcDec::new_from_slices(
                    &kenc,
                    &iv,
                )
                    .map_err(|e| {
                        ParseError::DecryptionError(format!(
                            "Mode 7 cipher initialization failed: {}",
                            e
                        ))
                    })?;

                cipher
                    .decrypt_padded_mut::<NoPadding>(&mut buf)
                    .map_err(|e| {
                        ParseError::DecryptionError(format!(
                            "Mode 7 AES-CBC decryption failed: {:?}",
                            e
                        ))
                    })?;

                Self::verify_plaintext(&buf)?;

                Ok(buf)
            }
        }
    }

    // ================================================================
    // TPL PARSER
    // ================================================================

    fn parse_tpl(raw_payload: &[u8], ci_pos: usize) -> Result<TplHeader, ParseError> {
        let ci = raw_payload[ci_pos];

        let len = match ci {
            // No TPL header
            0x78 => 1,
            // Short TPL header: CI ACC STS CF CF
            0x7A => 5,
            // Long TPL header: CI ID(4) M(2) VER TYPE ACC STS CF CF
            0x72 | 0x73 | 0x7E => 13,
            _ => {
                return Err(ParseError::InvalidFrame(format!(
                    "Unsupported CI field 0x{:02X}",
                    ci
                )))
            }
        };

        if raw_payload.len() < ci_pos + len {
            return Err(ParseError::InvalidFrame(format!(
                "Incomplete TPL header for CI 0x{:02X}",
                ci
            )));
        }

        let h = &raw_payload[ci_pos..ci_pos + len];

        let tpl = match len {
            1 => TplHeader {
                len,
                access_no: 0,
                cf: 0,
                iv_prefix: None,
            },
            5 => {
                // Short header: manufacturer and address come from the DLL
                let mut iv_prefix = [0u8; 8];
                iv_prefix.copy_from_slice(&raw_payload[2..10]);
                TplHeader {
                    len,
                    access_no: h[1],
                    cf: u16::from_le_bytes([h[3], h[4]]),
                    iv_prefix: Some(iv_prefix),
                }
            }
            _ => {
                // Long header: manufacturer and address come from the TPL
                let mut iv_prefix = [0u8; 8];
                iv_prefix[0..2].copy_from_slice(&h[5..7]);
                iv_prefix[2..6].copy_from_slice(&h[1..5]);
                iv_prefix[6..8].copy_from_slice(&h[7..9]);
                TplHeader {
                    len,
                    access_no: h[9],
                    cf: u16::from_le_bytes([h[11], h[12]]),
                    iv_prefix: Some(iv_prefix),
                }
            }
        };

        Ok(tpl)
    }

    // ================================================================
    // MODE 7 PARSER
    // ================================================================

    fn parse_mode7(
        raw_payload: &[u8],
        ell_pos: usize,
    ) -> Result<Mode7SecurityInfo, ParseError> {
        if raw_payload.len() < 35 {
            return Err(ParseError::DecryptionError(
                "Mode 7 telegram is too short".into(),
            ));
        }

        let meter_id = [
            raw_payload[4],
            raw_payload[5],
            raw_payload[6],
            raw_payload[7],
        ];

        if raw_payload[ell_pos] != 0x8C {
            return Err(ParseError::DecryptionError(format!(
                "Expected Mode 7 ELL CI 0x8C, found 0x{:02X}",
                raw_payload[ell_pos]
            )));
        }

        let afl_pos = ell_pos + 3;

        if raw_payload.len() < afl_pos + 4 {
            return Err(ParseError::DecryptionError(
                "Incomplete AFL header".into(),
            ));
        }

        if raw_payload[afl_pos] != 0x90 {
            return Err(ParseError::DecryptionError(format!(
                "Expected AFL CI 0x90, found 0x{:02X}",
                raw_payload[afl_pos]
            )));
        }

        let afl_len = raw_payload[afl_pos + 1] as usize;
        let fcl = u16::from_le_bytes([raw_payload[afl_pos + 2], raw_payload[afl_pos + 3]]);
        let tpl_pos = afl_pos + 2 + afl_len;

        // AFL fields follow the FCL in order MCL, KI, MCR, MAC, ML
        let mut mcr_pos = afl_pos + 4;
        if fcl & (1 << 13) != 0 {
            mcr_pos += 1;
        }
        if fcl & (1 << 9) != 0 {
            mcr_pos += 2;
        }

        if fcl & (1 << 11) == 0 {
            return Err(ParseError::DecryptionError(format!(
                "Mode 7 AFL has no message counter (FCL=0x{:04X})",
                fcl
            )));
        }

        if mcr_pos + 4 > tpl_pos || raw_payload.len() < tpl_pos + 6 {
            return Err(ParseError::DecryptionError(
                "Incomplete AFL header".into(),
            ));
        }

        let message_counter = [
            raw_payload[mcr_pos],
            raw_payload[mcr_pos + 1],
            raw_payload[mcr_pos + 2],
            raw_payload[mcr_pos + 3],
        ];

        if raw_payload[tpl_pos] != 0x7A {
            return Err(ParseError::DecryptionError(format!(
                "Expected Mode 7 short TPL CI 0x7A, found 0x{:02X}",
                raw_payload[tpl_pos]
            )));
        }

        let cf = u16::from_le_bytes([
            raw_payload[tpl_pos + 3],
            raw_payload[tpl_pos + 4],
        ]);

        let cfe = raw_payload[tpl_pos + 5];

        let mode = ((cf >> 8) & 0x1F) as u8;

        if mode != 7 {
            return Err(ParseError::DecryptionError(format!(
                "Expected Security Mode 7, found Mode {}",
                mode
            )));
        }

        let key_id = cfe & 0x0F;
        let kdf_selection = (cfe >> 4) & 0x03;

        if kdf_selection != 1 {
            return Err(ParseError::DecryptionError(format!(
                "Unsupported Mode 7 KDF selection: {} (CFE=0x{:02X})",
                kdf_selection,
                cfe
            )));
        }

        if key_id != 0 {
            return Err(ParseError::DecryptionError(format!(
                "Unsupported Mode 7 Key ID: {} (CFE=0x{:02X})",
                key_id,
                cfe
            )));
        }

        let encrypted_blocks = ((cf >> 4) & 0x0F) as usize;

        if encrypted_blocks == 0 {
            return Err(ParseError::DecryptionError(
                "Mode 7 configuration specifies zero encrypted blocks"
                    .into(),
            ));
        }

        let encrypted_len = encrypted_blocks * 16;

        let ciphertext_start = tpl_pos + 6;

        let ciphertext_end = ciphertext_start + encrypted_len;

        if raw_payload.len() < ciphertext_end {
            return Err(ParseError::DecryptionError(format!(
                "Telegram contains only {} bytes after TPL, \
                 but Mode 7 requires {} encrypted bytes",
                raw_payload.len().saturating_sub(ciphertext_start),
                encrypted_len
            )));
        }

        let ciphertext =
            raw_payload[ciphertext_start..ciphertext_end].to_vec();

        Ok(Mode7SecurityInfo {
            meter_id,
            message_counter,
            ciphertext,
        })
    }

    // ================================================================
    // MODE 7 KDF A
    // ================================================================

    fn derive_mode7_kenc(
        persistent_key: &[u8],
        message_counter: &[u8; 4],
        meter_id: &[u8; 4],
    ) -> Result<[u8; 16], ParseError> {
        Self::validate_key(persistent_key)?;

        let mut kdf_input = [0u8; 16];

        // DC = 00 for Kenc from meter
        kdf_input[0] = 0x00;

        // Message Counter
        kdf_input[1..5].copy_from_slice(message_counter);

        // Meter ID
        kdf_input[5..9].copy_from_slice(meter_id);

        // Fixed KDF padding
        kdf_input[9..16].copy_from_slice(&[
            0x07,
            0x07,
            0x07,
            0x07,
            0x07,
            0x07,
            0x07,
        ]);

        let mut mac =
            Aes128Cmac::new_from_slice(persistent_key)
                .map_err(|e| {
                    ParseError::DecryptionError(format!(
                        "Mode 7 KDF CMAC initialization failed: {:?}",
                        e
                    ))
                })?;

        mac.update(&kdf_input);

        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut kenc = [0u8; 16];
        kenc.copy_from_slice(&bytes);

        Ok(kenc)
    }

    // ================================================================
    // KEY VALIDATION
    // ================================================================

    fn validate_key(key: &[u8]) -> Result<(), ParseError> {
        if key.len() != 16 {
            return Err(ParseError::DecryptionError(format!(
                "Invalid key length: expected 16 bytes, got {}",
                key.len()
            )));
        }

        Ok(())
    }

    // ================================================================
    // PLAINTEXT VERIFICATION
    // ================================================================

    /// Decrypted OMS data starts with 0x2F2F; anything else means a wrong key.
    fn verify_plaintext(decrypted: &[u8]) -> Result<(), ParseError> {
        if !decrypted.starts_with(&[0x2F, 0x2F]) {
            return Err(ParseError::DecryptionError(
                "Decrypted data does not start with 0x2F2F (wrong key?)".into(),
            ));
        }

        Ok(())
    }
}
