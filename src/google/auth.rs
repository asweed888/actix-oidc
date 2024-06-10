use crate::multiuse::auth::*;
use crate::multiuse::env;

pub async fn client() -> CoreClient {
    let client_id = env::google_client_id().unwrap();
    let client_id = ClientId::new(client_id.to_string());

    let client_secret = env::google_client_secret().unwrap();
    let client_secret = ClientSecret::new(client_secret.to_string());

    let issuer_url = "https://accounts.google.com".to_string();
    let issuer_url = IssuerUrl::new(issuer_url.to_string()).unwrap();

    let redirect_url = env::service_addr().unwrap();
    let redirect_url = format!("{}/auth/google/callback", redirect_url);
    let redirect_url = RedirectUrl::new(redirect_url.to_string()).unwrap();

    let provider_metadata = CoreProviderMetadata::discover_async(
        issuer_url, async_http_client
    ).await.unwrap();

    CoreClient::from_provider_metadata(
        provider_metadata,
        client_id,
        Some(client_secret),
    )
    .set_redirect_uri(redirect_url)
}

pub struct GoogleAuthApi;

impl GoogleAuthApi {
    pub fn new() -> Self {
        Self{}
    }
}

impl OidcAuthApi for GoogleAuthApi {}