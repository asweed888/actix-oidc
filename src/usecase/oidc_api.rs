use crate::domain::model::oidc_operation::entity::OidcOperation;
use crate::infrastructure::repository::oidc_operation::OidcOperationRepository;
use crate::domain::model::oidc_operation::entity::{
    web,
    Session,
    CoreClient,
};

pub async fn login<R>(
    repo: R,
    // session: Session,
    // data: web::Data<CoreClient>,
)
where
    R: OidcOperation
{
    repo
}

