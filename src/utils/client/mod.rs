use openidconnect::{
    core::{
        CoreClient, CoreProviderMetadata,
    },
    reqwest::async_http_client,
    ClientId, ClientSecret, IssuerUrl, RedirectUrl,
};

pub(crate) async fn create_oidc_client(
    client_id: String,
    client_secret: String,
    issuer_url: String,
    redirect_url: String,
) -> CoreClient {
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = ClientSecret::new(client_secret.to_string());
    let issuer_url = IssuerUrl::new(issuer_url.to_string()).unwrap();

    let provider_metadata = CoreProviderMetadata::discover_async(
        issuer_url, async_http_client
    ).await.unwrap();

    let redirect_url = RedirectUrl::new(redirect_url.to_string()).unwrap();

    CoreClient::from_provider_metadata(
        provider_metadata,
        client_id,
        Some(client_secret),
    )
    .set_redirect_uri(redirect_url)
}