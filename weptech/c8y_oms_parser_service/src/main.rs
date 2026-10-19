// src/main.rs

use std::sync::Arc;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;

// Import from the library crate target
use c8y_oms_parser_service::registry::{build_driver_registry, DriverRegistry};
use c8y_oms_parser_service::traits::ProcessResult;

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<DriverRegistry>,
}

#[derive(Deserialize, Debug)]
pub struct ParseRequest {
    pub payload: String,
    pub oms_mode: Option<u8>,
    pub encryptionkey: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct ParseResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ProcessResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex).map_err(|e| e.to_string())
}

/// Helper function to safely redact encryption keys in audit logs
fn mask_key(key: Option<&String>) -> String {
    match key {
        Some(k) if k.len() >= 8 => format!("{}***{}", &k[..4], &k[k.len() - 4..]),
        Some(_) => "***".to_string(),
        None => "NONE".to_string(),
    }
}

/// Helper function to cleanly format optional OMS mode values
fn format_oms_mode(mode: Option<u8>) -> String {
    match mode {
        Some(m) => m.to_string(),
        None => "AUTO".to_string(),
    }
}

async fn parse_handler(
    State(state): State<AppState>,
    Json(req): Json<ParseRequest>,
) -> (StatusCode, Json<ParseResponse>) {
    // 1. Audit Log: Request Payload
    info!(
        target: "oms_audit::request",
        payload_b64 = %req.payload,
        oms_mode = %format_oms_mode(req.oms_mode),
        encryption_key = %mask_key(req.encryptionkey.as_ref()),
        "Received OMS parse request"
    );

    // 2. Base64 decode payload
    let raw_payload = match BASE64.decode(&req.payload) {
        Ok(bytes) => bytes,
        Err(err) => {
            let err_msg = format!("Invalid base64 payload: {}", err);
            let response = ParseResponse {
                status: "error".into(),
                data: None,
                error: Some(err_msg.clone()),
            };

            warn!(
                target: "oms_audit::response",
                status = 400,
                error = %err_msg,
                "Parse request rejected (Base64 decode failed)"
            );

            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // 3. Decode optional hex key
    let key_bytes = match &req.encryptionkey {
        Some(hex_str) => match hex_to_bytes(hex_str) {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                let err_msg = format!("Invalid encryption key format: {}", err);
                let response = ParseResponse {
                    status: "error".into(),
                    data: None,
                    error: Some(err_msg.clone()),
                };

                warn!(
                    target: "oms_audit::response",
                    status = 400,
                    error = %err_msg,
                    "Parse request rejected (Key hex parse failed)"
                );

                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        None => None,
    };

    // 4. Process via DriverRegistry
    let (status_code, response) = match state.registry.process(&raw_payload, req.oms_mode, key_bytes.as_deref()) {
        Ok(result) => (
            StatusCode::OK,
            ParseResponse {
                status: "success".into(),
                data: Some(result),
                error: None,
            },
        ),
        Err(err) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            ParseResponse {
                status: "error".into(),
                data: None,
                error: Some(err.to_string()),
            },
        ),
    };

    // 5. Audit Log: Output Response Payload (Serialized as JSON)
    let response_json = serde_json::to_string(&response).unwrap_or_default();

    info!(
        target: "oms_audit::response",
        status = status_code.as_u16(),
        response_data = %response_json,
        "Completed OMS parse request"
    );

    (status_code, Json(response))
}

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber with disabled ANSI color codes for container stdout logging
    let subscriber = FmtSubscriber::builder()
        .with_ansi(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    let registry = build_driver_registry();
    let state = AppState {
        registry: Arc::new(registry),
    };

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/api/v1/parse", post(parse_handler))
        .with_state(state);

    // Binds to port 80 (required for standard Docker/Cumulocity microservice containers)
    let listener = tokio::net::TcpListener::bind("0.0.0.0:80")
        .await
        .expect("Failed to bind TCP listener on port 80");

    info!("Service running on http://0.0.0.0:80");
    axum::serve(listener, app)
        .await
        .expect("Failed to start Axum web server");
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes_rejects_non_ascii_without_panic() {
        assert!(hex_to_bytes("aä1").is_err());
        assert_eq!(hex_to_bytes("0aFF").unwrap(), vec![0x0A, 0xFF]);
    }

}
