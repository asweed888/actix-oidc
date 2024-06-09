use crate::multiuse::auth::*;
use crate::multiuse::env;

pub async fn client() -> CoreClient {
    let client_id = env::google_client_id().unwrap();
    let client_secret = env::google_client_secret().unwrap();
    let issuer_url = "https://accounts.google.com".to_string();
    let redirect_url = env::service_addr().unwrap();
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