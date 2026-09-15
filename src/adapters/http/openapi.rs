use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use utoipa_swagger_ui::SwaggerUi;

use crate::adapters::http::routes;

#[derive(OpenApi)]
#[openapi(
    paths(
        routes::user::register,
        routes::user::me,
        routes::user::change_password,
        routes::auth::login,
        routes::auth::refresh,
        routes::auth::logout,
    ),
    components(schemas(
        routes::user::RegisterPayload,
        routes::user::RegisterResponse,
        routes::user::UserResponse,
        routes::user::ChangePasswordPayload,
        routes::auth::LoginPayload,
        routes::auth::LoginResponse,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "user", description = "User registration and profile endpoints"),
        (name = "auth", description = "Authentication endpoints"),
    )
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

pub fn swagger_ui() -> SwaggerUi {
    SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi())
}
