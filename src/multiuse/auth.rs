pub use actix_web::{
    web,
    App,
    HttpResponse, Error,
    HttpServer,
    Responder,
    http::header::LOCATION
};
pub use actix_web::cookie::Key;
pub use actix_session::{Session, SessionMiddleware, storage::RedisSessionStore};
pub use actix_session::config::PersistentSession;
pub use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreAuthenticationFlow},
    reqwest::async_http_client,
    ClientId, ClientSecret, IssuerUrl, RedirectUrl,
    AuthenticationFlow, AuthorizationCode,
    CsrfToken, Nonce,
    PkceCodeChallenge, PkceCodeVerifier,
    AccessTokenHash,
    OAuth2TokenResponse,
};
pub use openidconnect::{AccessToken, Scope};
pub use serde::{Deserialize, Serialize};
use crate::multiuse::error::{OIDCError, SessionError};
use crate::multiuse::env;
use crate::oidc;


#[derive(Serialize, Deserialize, Debug)]
pub struct OpenIdConnectState {
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
    pub nonce: Nonce
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Identity {
    pub user: User
}

pub trait OidcAuthApi {
    async fn login(
        &self,
        session: Session,
        client: CoreClient,
    ) -> Result<HttpResponse, Error> {
        Ok(oidc::login(session, client).await?)
    }
    async fn callback(
        &self,
        session: Session,
        client: CoreClient,
        query: web::Query<AuthRequest>,
    ) -> Result<HttpResponse, Error> {
        Ok(oidc::callback(session, client, query).await?)
    }
}


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