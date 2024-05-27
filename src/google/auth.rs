use std::env;
use crate::multiuse::auth::*;

pub async fn client() -> CoreClient {
    let client_id = env::var("GOOGLE_CLIENT_ID").unwrap();
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").unwrap();
    let issuer_url = "https://accounts.google.com".to_string();
    let redirect_url = env::var("SERVICE_ADDR").unwrap();
    let redirect_url = format!("{}/auth/google/callback", redirect_url);

    create_oidc_client(client_id, client_secret, issuer_url, redirect_url).await
}

pub struct GoogleAuthUseCase;

impl GoogleAuthUseCase {
    pub fn new() -> Self {
        Self{}
    }
}

impl OidcAuthUseCase for GoogleAuthUseCase {}