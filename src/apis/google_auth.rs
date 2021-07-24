use serde::{Deserialize, Serialize};
use common_components::{Result, error};
use crate::env::Env;

const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

#[derive(Serialize)]
struct ExchangeGrantTokenRequest<'a> {
    client_id:      &'a str,
    client_secret:  &'a str,
    code:           &'a str,
    grant_type:     &'static str,
    redirect_uri:   &'a str
}

#[derive(Deserialize)]
pub struct ExchangeGrantTokenResponse {
    pub access_token:   String,
    pub expires_in:     u64,
    pub refresh_token:  Option<String>,
    pub id_token:       String,
    pub scope:          String,
}

pub fn exchange_grant_token(env: &Env, code: &str, redirect_uri: &str) -> Result<ExchangeGrantTokenResponse> {
    let payload = match serde_json::to_string(&ExchangeGrantTokenRequest {
        client_id:      &env.google_client_id,
        client_secret:  &env.google_client_secret,
        code,
        grant_type:     "authorization_code",
        redirect_uri
    }) {
        Ok(p) => p,
        Err(e) => return Err(error!(e, "Failed to serialize ExchangeGrantTokenRequest"))
    };

    let response = match reqwest::blocking::Client::new()
        .post(GOOGLE_TOKEN_ENDPOINT)
        .body(payload)
        .send() {

        Ok(r) => r,
        Err(e) => return Err(error!(e, "Failed to send request"))
    };

    match response.json() {
        Ok(rp) => Ok(rp),
        Err(e) => Err(error!(e, "Failed to deserialize response payload"))
    }
}

#[derive(Serialize)]
struct ExchangeRefreshTokenRequest<'a> {
    client_id:      &'a str,
    client_secret:  &'a str,
    grant_type:     &'static str,
    refresh_token:  &'a str
}

#[derive(Deserialize)]
pub struct ExchangeRefreshTokenResponse {
    pub access_token:   String,
    pub expires_in:     i64,
    pub scope:          String,
}

pub fn refresh_token(env: &Env, refresh_token: &str) -> Result<ExchangeRefreshTokenResponse> {
    let payload = match serde_json::to_string(&ExchangeRefreshTokenRequest {
        client_id:      &env.google_client_id,
        client_secret:  &env.google_client_secret,
        grant_type:     "refresh_token",
        refresh_token
    }) {
        Ok(p) => p,
        Err(e) => return Err(error!(e, "Failed to serialize request payload"))
    };

    let response = match reqwest::blocking::Client::new()
        .post(GOOGLE_TOKEN_ENDPOINT)
        .body(payload)
        .send() {

        Ok(r) => r,
        Err(e) => return Err(error!(e, "Failed to send request"))
    };

    match response.json() {
        Ok(rp) => Ok(rp),
        Err(e) => Err(error!(e, "Failed to deserialize response payload"))
    }
}
