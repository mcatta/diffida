mod vault;
mod hasher;

use std::fs::read_to_string;
use anyhow::Error;
use axum::{
    routing::{get, post},
    Router, 
    response::IntoResponse, 
    http::{
        HeaderMap, header, StatusCode
    }, 
    Json
};
use json::JsonValue;
use schnorrkel::Signature;
use serde::Deserialize;
use vault::keystore::PublicKey;

#[macro_use]
extern crate json;


#[shuttle_runtime::main]
async fn axum() -> shuttle_axum::ShuttleAxum {
    let router = Router::new()
        .route("/doc", get(get_doc_file))
        .route("/api/generate", get(generate_seed))
        .route("/api/sign", post(sign_message))
        .route("/api/verify", post(verify_message));

    Ok(router.into())
}

async fn get_doc_file() -> impl IntoResponse {
    match read_to_string("assets/swagger.yml") {
        Ok(content) => (StatusCode::OK, content),
        Err(_) => (StatusCode::NOT_FOUND, String::new()),
    }
}

/**
 * Generate a new random menmonic
 */
async fn generate_seed() -> impl IntoResponse {
    let response = object! {
        "mnemonic": vault::mnemonic::generate()
    };
    
    create_json_response(response).into_response()
}

/**
 * Sign a message starting from the payload.
 * 
 * @param payload Body
 */
async fn sign_message(Json(payload): Json<SignMessagePayload>) -> impl IntoResponse {
    let private_key = vault::keystore::private_key_from_phrase(&payload.mnemonic)
        .map_err(|_| Error::msg("Invalid Mnemonic"));

    match private_key {
        Ok(keystore) => {
            let signature = keystore.sign(&payload.message).to_bytes();
        
            let response: JsonValue = object! {
                "message": payload.message,
                "signature": hasher::base64::encode(&signature),
                "public_key": hasher::base64::encode(&keystore.public_key().to_bytes())
            };

            create_json_response(response).into_response()
        },
        Err(_) => bad_request().into_response(),
    }
}

/**
 * Verify signature
 * 
 * @param payload
 */
async fn verify_message(Json(payload): Json<VerifyMessagePayload>) -> impl IntoResponse {
    let public_key_result: Result<PublicKey, Error> = hasher::base64::decode(&payload.public_key)
        .and_then(|v: Vec<u8>| -> Result<[u8; 32], _> { 
            v.as_slice().try_into().map_err(|_| Error::msg("Invalid signature key"))
        })
        .and_then(|h|PublicKey::new(h).map_err(|_| Error::msg("Invalid public key")));

    let signature_result: Result<Signature, Error> = hasher::base64::decode(&payload.signature)
        .and_then(|v: Vec<u8>| -> Result<[u8; 64], _> { 
            v.as_slice().try_into().map_err(|_| Error::msg("Invalid signature key"))
        })
        .and_then(|h| Signature::from_bytes(&h).map_err(|_| Error::msg("Invalid signature key")));

    match public_key_result {
        Ok(public_key) => {
            match signature_result {
                Ok(signature) => {
                    let matched_signature = public_key.verify(&payload.message, &signature).is_ok();
                    let response = object! {
                        "message": payload.message,
                        "match": matched_signature
                    };
                    
                    create_json_response(response).into_response()
                },
                Err(_) => bad_request().into_response(),
            }
        },
        Err(_) => bad_request().into_response(),
    }
}

fn create_json_response(json: JsonValue) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    (headers, json::stringify(json))
}

fn bad_request() -> impl IntoResponse {
    (StatusCode::BAD_REQUEST, "".to_string())
}

#[derive(Deserialize)]
struct SignMessagePayload {
    message: String,
    mnemonic: Vec<String>
}

#[derive(Deserialize)]
struct VerifyMessagePayload {
    message: String,
    public_key: String,
    signature: String
}

#[cfg(test)]
mod api_tests {
    use tokio::runtime::Runtime;

    use super::*;

    #[test]
    fn test_sign_message() {
        // Given
        let rt = Runtime::new().unwrap();
        let words: Vec<String>  = "scrutinio casaccio cedibile oste tumulto irrorare notturno uffa doganale classico esercito vibrante".split(" ").map(|s| s.to_string()).collect();
        let payload = SignMessagePayload {
            message: "Hello, world!".to_string(),
            mnemonic: words,
        };

        // When
        let result = rt.block_on(sign_message(Json(payload)));

        // Then
        assert!(result.into_response().status().is_success());
    }

    #[test]
    fn test_sign_message_empty_params() {
        // Given
        let rt = Runtime::new().unwrap();
        let payload = SignMessagePayload {
            message: "Hello, world!".to_string(),
            mnemonic: vec![],
        };
        
        // When
        let result = rt.block_on(sign_message(Json(payload)));
        assert!(!result.into_response().status().is_success());
    }

    #[test]
    fn test_verify_message() {
        // Given
        let rt = Runtime::new().unwrap();
        let payload = VerifyMessagePayload {
            message: "Hello, world!".to_string(),
            public_key: "ag1DFUCYJ9obNA5eWrhQqhzifFr41DesUD6BxsdwPBE".to_string(),
            signature: "UBYHg5Tgeywbm8K5HHEdIM4jnS8sbrnP+yB0a6oGp1FJnukFxtNFzX8XrmRhm92jzbyxWHxKTMZoyAKG+oJyjA".to_string(),
        };

        // When
        let result = rt.block_on(verify_message(Json(payload)));

        // Then
        assert!(result.into_response().status().is_success());
    }

    #[test]
    fn test_verify_message_empty_params() {
        // Given
        let rt = Runtime::new().unwrap();
        let payload = VerifyMessagePayload {
            message: "Hello, world!".to_string(),
            public_key: "".to_string(),
            signature: "".to_string(),
        };

        // When
        let result = rt.block_on(verify_message(Json(payload)));

        // Then
        assert!(!result.into_response().status().is_success());
    }

    #[test]
    fn test_generate_seed() {
        // Given
        let rt = Runtime::new().unwrap();

        // When
        let result = rt.block_on(generate_seed());

        // Then
        assert!(result.into_response().status().is_success());
    }
}