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

