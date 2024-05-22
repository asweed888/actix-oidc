pub mod utils {
    pub mod client {
        pub mod r#mod;
        pub mod google;
    }
}
pub mod domain {
    pub mod model {
        pub mod oidc_operation {
            pub mod entity;
        }
    }
    pub mod repository {
        pub mod oidc_operation;
    }
}
pub mod infrastructure {
    pub mod repository {
        pub mod oidc_operation;
    }
}
pub mod usecase {
    pub mod oidc_api;
}
pub mod presentation {
    pub mod http {
        pub mod handler {
            pub mod oidc_operation;
        }
    }
}
// Automatically exported by saba.


