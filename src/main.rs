use std::net::SocketAddr;

use dotenvy::dotenv;
use tracing::info;

use clean_architecture::infra::{app::create_app, setup::init_app_state};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    let app_state = init_app_state().await?;

    let app = create_app(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();

    info!("Backend listening at {}", &listener.local_addr().unwrap());

    // `with_connect_info` is required for tower_governor's per-IP rate limiting on
    // /login and /register to extract the peer address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

    Ok(())
}
