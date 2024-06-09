use crate::multiuse::auth::*;
use crate::multiuse::error::{SessionError, OIDCError};
use crate::multiuse::env;

pub async fn login(
    session: Session,
    client: web::Data<CoreClient>,
) -> Result<HttpResponse, Error> {
    // 認証済みの場合はsecret_page_rootへリダイレクト
    if let Some(_identity) = session.get::<Identity>("identity")
        .map_err(|_| SessionError::ReadSessionError("unknown".to_string()))? {
            return Ok(
                HttpResponse::TemporaryRedirect()
                .insert_header((LOCATION, env::secret_page_root().unwrap()))
                .finish()
            )
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token, nonce) = client.authorize_url(
        AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    )
    .add_scope(Scope::new("email".to_string()))
    .add_scope(Scope::new("profile".to_string()))
    .set_pkce_challenge(pkce_challenge)
    .url();

    let oidc_state = OpenIdConnectState {
        pkce_verifier,
        csrf_token,
        nonce,
    };

    session.insert("oidc_state", &oidc_state).unwrap();
    Ok(
        HttpResponse::Found()
        .insert_header((LOCATION, auth_url.to_string()))
        .finish()
    )
}

pub async fn callback(
    session: Session,
    client: web::Data<CoreClient>,
    query: web::Query<AuthRequest>,
) -> Result<HttpResponse, Error> {
    // 認証済みの場合はsecret_page_rootへリダイレクト
    if let Some(_identity) = session.get::<Identity>("identity")
        .map_err(|_| SessionError::ReadSessionError("unknown".to_string()))? {
            return Ok(
                HttpResponse::TemporaryRedirect()
                .insert_header((LOCATION, env::secret_page_root().unwrap()))
                .finish()
            )
    }

    let code = AuthorizationCode::new(query.into_inner().code);
    if let Some(oidc_state) = session.get::<OpenIdConnectState>("oidc_state")? {
        let token_response = client.exchange_code(code)
            .set_pkce_verifier(oidc_state.pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(|_| OIDCError::ExchangeTokenError)?;

        let id_token = token_response.extra_fields().id_token()
            .ok_or_else(|| OIDCError::EmptyIdTokenError)?;

        let claims = id_token.claims(
            &client.id_token_verifier(),
            &oidc_state.nonce,
        )
        .map_err(|err| {
            println!("Error is: {:?}", err);
            OIDCError::ClaimsVerificationError
        })?;

        match claims.access_token_hash() {
            None => { Err(OIDCError::MissingTokenHashError) }
            Some(given_token_hash) => {
                let calculated_token_hash = AccessTokenHash::from_token(
                    token_response.access_token(),
                    &id_token.signing_alg().map_err(|_| OIDCError::SigningError)?,
                ).map_err(|_| OIDCError::SigningError)?;

                if calculated_token_hash != *given_token_hash {
                    Err(OIDCError::AccessTokenVerificationError)
                }
                else {
                    Ok(())
                }
            }
        }?;


        let user_id = claims.subject().to_string();

        if let (Some(mail), Some(name)) = (
            &claims.email().map(|mail| mail.as_str()),
            &claims.name().map(|localized_claim| {
                localized_claim.get(claims.locale().map(|locale| locale)).unwrap().as_str()
            }),
        ) {
            let identity = Identity {
                user: User {
                    id: user_id.clone(),
                    name: name.to_string(),
                    email: mail.to_string(),
                },
            };

            session.insert("identity", identity)
                .map_err(|_| SessionError::WriteSessionError(user_id.clone()))?;
        } else {
            return Err(Error::from(OIDCError::ClaimsContentError(user_id.clone())));
        }

        let access_token = token_response.access_token().secret().to_string();

        let client = reqwest::Client::new();
        client.post("https://oauth2.googleapis.com/revoke")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("token={}", access_token))
            .send()
            .await
            .unwrap();

        session.remove("oidc_state");
    }
    else {
        return Err(Error::from(OIDCError::CsrfStateError));
    };

    Ok(
        HttpResponse::TemporaryRedirect()
        .insert_header((LOCATION, env::secret_page_root().unwrap()))
        .finish()
    )
}


pub async fn logout(
    session: Session,
) -> Result<HttpResponse, Error> {
    if let Some(_identity) = session.get::<Identity>("identity")
        .map_err(|_| SessionError::ReadSessionError("unknown".to_string()))? {

        session.purge();
        Ok(
            HttpResponse::TemporaryRedirect()
            .insert_header((LOCATION, env::public_page_root().unwrap()))
            .finish()
        )
    }
    else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}