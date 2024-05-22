pub use actix_web::{web, App, HttpResponse, HttpServer, Responder, http::header::LOCATION};
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

#[async_trait::async_trait]
pub trait OidcOperation {
    async fn login(
        _session: Session,
        data: web::Data<CoreClient>
    ) -> anyhow::Result<String> {
        let (authorize_url, _csrf_token, _nonce) = data.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

        Ok(authorize_url.to_string())
    }
    async fn callback(
        _session: Session,
        query: web::Query<AuthRequest>,
        data: web::Data<CoreClient>,
    ) -> anyhow::Result<()> {
        let code = openidconnect::AuthorizationCode::new(query.into_inner().code);
        match data.exchange_code(code).request_async(async_http_client).await {
            Ok(token_response) => HttpResponse::Ok().json(token_response.access_token()),
            Err(e) => HttpResponse::BadRequest().body(e.to_string()),
        }
        Ok(())
    }
    async fn revoke_token(form: web::Form<RevokeRequest>) -> impl Responder {
        let client = reqwest::Client::new();
        let response = client.post("https://oauth2.googleapis.com/revoke")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("token={}", form.token))
            .send()
            .await;

        match response {
            Ok(_) => HttpResponse::Ok().body("Token revoked successfully"),
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        }
    }
}