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
    OAuth2TokenResponse,
};
pub use openidconnect::{AccessToken, Scope};
pub use serde::{Deserialize, Serialize};


#[derive(Deserialize)]
pub struct AuthRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token: String,
}

pub trait OidcAuthUseCase {
    async fn login(
        &self,
        _session: Session,
        data: web::Data<CoreClient>
    ) -> Result<HttpResponse, Error> {
        let (authorize_url, _csrf_token, _nonce) = data.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

        Ok(
            HttpResponse::Found()
            .insert_header((LOCATION, authorize_url.to_string()))
            .finish()
        )
    }
    async fn callback(
        &self,
        _session: Session,
        data: web::Data<CoreClient>,
        query: web::Query<AuthRequest>,
    ) -> Result<HttpResponse, Error> {
        let code = AuthorizationCode::new(query.into_inner().code);
        match data.exchange_code(code).request_async(async_http_client).await {
            Ok(token_response) => Ok(HttpResponse::Ok().json(token_response.access_token())),
            Err(e) => Ok(HttpResponse::BadRequest().body(e.to_string())),
        }
    }
    async fn revoke_token(&self, form: web::Form<RevokeRequest>) -> Result<HttpResponse, Error> {
        let client = reqwest::Client::new();
        let response = client.post("https://oauth2.googleapis.com/revoke")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("token={}", form.token))
            .send()
            .await;

        match response {
            Ok(_) => Ok(HttpResponse::Ok().body("Token revoked successfully")),
            Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
        }
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