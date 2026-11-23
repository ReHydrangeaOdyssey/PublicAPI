use crate::transport::Error;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: std::net::SocketAddr,
    certificate: String,
    private_key: String,
    internal_ca: String,
    internal_identity: String,
    private_url: String,
    game_server_url: String,
    access_public_key: String,
    access_issuer: String,
    discord_public_key: Option<String>,
    discord_issuer: Option<String>,
    allowed_providers: Vec<String>,
    client_origin: String,
    public_origin: String,
    required_version: String,
    rate_limit_per_minute: u32,
}
pub async fn run() -> Result<(), Error> {
    let path = std::env::args()
        .nth(1)
        .ok_or("configuration JSON path required")?;
    let config: Config = serde_json::from_slice(&tokio::fs::read(path).await?)?;
    for origin in [&config.client_origin, &config.public_origin] {
        let url = reqwest::Url::parse(origin)?;
        if url.scheme() != "https" || url.origin().ascii_serialization() != *origin {
            return Err("HTTPS origin required".into());
        }
    }
    if config.required_version.is_empty() {
        return Err("version required".into());
    }
    let key =
        jsonwebtoken::DecodingKey::from_ed_pem(&tokio::fs::read(config.access_public_key).await?)?;
    let discord = match (config.discord_public_key, config.discord_issuer) {
        (Some(path), Some(issuer)) => Some((
            jsonwebtoken::DecodingKey::from_ed_pem(&tokio::fs::read(path).await?)?,
            issuer,
        )),
        (None, None) => None,
        _ => return Err("Discord key and issuer must be configured together".into()),
    };
    let auth =
        crate::auth::Auth::new(key, config.access_issuer, discord, config.allowed_providers)?;
    let client =
        crate::transport::internal_client(&config.internal_ca, &config.internal_identity).await?;
    let rate = crate::rate_limit::RateLimit::new(
        config.rate_limit_per_minute,
        std::time::Duration::from_secs(60),
    )?;
    let app = crate::application::Application {
        auth,
        client,
        private_url: config.private_url,
        game_server_url: config.game_server_url,
        client_origin: config.client_origin,
        public_origin: config.public_origin,
        required_version: config.required_version,
        rate: std::sync::Arc::new(tokio::sync::Mutex::new(rate)),
    };
    let tls = crate::transport::tls_config(&config.certificate, &config.private_key, None).await?;
    axum_server::bind_rustls(config.listen, tls)
        .serve(
            crate::application::router(app)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    Ok(())
}
