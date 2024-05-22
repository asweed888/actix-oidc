use crate::usecase::oidc_api;
use crate::infrastructure::repository::oidc_operation::OidcOperationRepository;


pub async fn login(){
    oidc_api::login(OidcOperationRepository::new());
}
