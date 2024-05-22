use crate::domain::model::oidc_operation::entity::OidcOperation;


pub struct OidcOperationRepository{}

impl OidcOperationRepository {
    pub fn new() -> Self {
        Self{}
    }
}

impl OidcOperation for OidcOperationRepository {}
