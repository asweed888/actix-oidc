use openidconnect::core::CoreClient;
use std::env;
use crate::utils::client::r#mod::create_oidc_client;

pub async fn oidc_client() -> CoreClient {
    let client_id = env::var("GOOGLE_CLIENT_ID").unwrap();
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").unwrap();
    let issuer_url = "https://accounts.google.com".to_string();
    let redirect_url = "http://localhost:3000/auth/google/callback".to_string();

    create_oidc_client(client_id, client_secret, issuer_url, redirect_url).await
}