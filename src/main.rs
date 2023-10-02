use std::fs::read_to_string;

use axum::{routing::get, routing::post, Router, response::IntoResponse, http::{HeaderMap, header}, Json};
use bip39::{Mnemonic, MnemonicType, Language};
use json::JsonValue;
use schnorrkel::{keys, Keypair, Signature, PublicKey};
use substrate_bip39::mini_secret_from_entropy;
use serde::Deserialize;
use base64::{Engine as _, engine::general_purpose};

#[macro_use]
extern crate json;

const LANGUAGE: Language = Language::Italian;

#[shuttle_runtime::main]
async fn axum() -> shuttle_axum::ShuttleAxum {
    let router = Router::new()
        .route("/doc", get(get_doc_file))
        .route("/api/generate", get(generate_seed))
        .route("/api/sign", post(sign_message))
        .route("/api/verify", post(verify_message));

    Ok(router.into())
}

async fn get_doc_file() -> String {
    read_to_string("assets/swagger.yml")
        .expect("Failure fetching the file")
}

/**
 * Generate a new random menmonic
 */
async fn generate_seed() -> impl IntoResponse {
    let mnemonic: Mnemonic = Mnemonic::new(MnemonicType::Words12, LANGUAGE);
    let words: Vec<&str> = mnemonic.phrase().split(" ").collect();

    let response = object! {
        "mnemonic": words
    };
    
    create_json_response(response)
}

/**
 * Sign a message starting from the payload.
 * 
 * @param payload Body
 */
async fn sign_message(Json(payload): Json<SignMessagePayload>) -> impl IntoResponse {
    let mnemonic: Mnemonic = Mnemonic::from_phrase(&payload.mnemonic.join(" "), LANGUAGE)
        .expect("Invalid passphrase");

    let key_pair: Keypair = mini_secret_from_entropy(mnemonic.entropy(), "")
        .expect("Invalid KeyPair generation")
        .expand_to_keypair(keys::ExpansionMode::Uniform);

    let signature = key_pair.sign_simple(&[], &payload.message.as_bytes())
        .to_bytes();
    let hashed_signature = general_purpose::STANDARD_NO_PAD.encode(signature);
    let public_key = general_purpose::STANDARD_NO_PAD.encode(key_pair.public.to_bytes());

    let response = object! {
        "message": payload.message,
        "signature": hashed_signature,
        "public_key": public_key
    };
    
    create_json_response(response)
}

/**
 * Verify signature
 * 
 * @param payload
 */
async fn verify_message(Json(payload): Json<VerifyMessagePayload>) -> impl IntoResponse {
    let public_key = PublicKey::from_bytes(&decode_hash_32(payload.public_key))
        .expect("Invalid public_key");

    let signature = Signature::from_bytes(&decode_hash_64(payload.signature))
        .expect("Failed signature decoding");

    let match_result = match public_key.verify_simple(&[], &payload.message.as_bytes(), &signature) {
        Ok(_) => true,
        Err(_) => false,
    };

    let response = object! {
        "message": payload.message,
        "match": match_result
    };
    
    create_json_response(response)
}

fn create_json_response(json: JsonValue) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    (headers, json::stringify(json))
}

fn decode_hash_64(str: String) -> [u8; 64] {
    let res = general_purpose::STANDARD_NO_PAD.decode(str)
        .expect("Decode hash failed");
    let array:[u8; 64] = res.try_into().expect("Error on converting");
    array
}

fn decode_hash_32(str: String) -> [u8; 32] {
    let res = general_purpose::STANDARD_NO_PAD.decode(str)
        .expect("Decode hash failed");
    let array:[u8; 32] = res.try_into().expect("Error on converting");
    array
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