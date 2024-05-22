use oidc::usecase::oidc_api;
use oidc::infrastructure::repository::oidc_operation::OidcOperationRepository;

fn main() {
    println!("Hello, world!");
    oidc_api::login(OidcOperationRepository::new());
}
