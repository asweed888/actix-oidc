use std::env;

pub fn service_addr() -> anyhow::Result<String> {
    Ok(env::var("SERVICE_ADDR").unwrap())
}

pub fn google_client_id() -> anyhow::Result<String> {
    Ok(env::var("GOOGLE_CLIENT_ID").unwrap())
}

pub fn google_client_secret() -> anyhow::Result<String> {
    Ok(env::var("GOOGLE_CLIENT_SECRET").unwrap())
}

pub fn secret_page_root() -> anyhow::Result<String> {
    Ok(env::var("SECRET_PAGE_ROOT").unwrap())
}
pub fn public_page_root() -> anyhow::Result<String> {
    Ok(env::var("PUBLIC_PAGE_ROOT").unwrap())
}
pub fn login_page_root() -> anyhow::Result<String> {
    Ok(env::var("LOGIN_PAGE_ROOT").unwrap())
}