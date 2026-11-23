use crate::rpc::{Context, Failure, ordinary_id};
use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::sync::Arc;
const MAX_TOKEN: usize = 8192;
const LIFETIME_SECONDS: u64 = 300;
#[derive(Clone)]
pub struct Auth {
    access_key: Arc<DecodingKey>,
    access_issuer: String,
    discord: Option<(Arc<DecodingKey>, String)>,
    pub providers: Vec<String>,
}
#[derive(Clone, serde::Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    iat: u64,
    exp: u64,
    player_id: Option<u64>,
    sid: Option<String>,
    jti: Option<String>,
}
pub struct Authorization {
    pub provider: String,
    pub subject: String,
    pub discord_id: u64,
    pub token_id: Vec<u8>,
}
impl Auth {
    pub fn new(
        access_key: DecodingKey,
        access_issuer: String,
        discord: Option<(DecodingKey, String)>,
        providers: Vec<String>,
    ) -> Result<Self, crate::transport::Error> {
        if providers.is_empty()
            || access_issuer.is_empty()
            || providers.iter().any(|p| p != "NONE" && p != "DISCORD")
            || (providers.iter().any(|p| p == "DISCORD") && discord.is_none())
        {
            return Err("unavailable authorization provider".into());
        }
        Ok(Self {
            access_key: Arc::new(access_key),
            access_issuer,
            discord: discord.map(|(key, issuer)| (Arc::new(key), issuer)),
            providers,
        })
    }
    pub fn context(
        &self,
        headers: &HeaderMap,
        body_token: &str,
        player: u64,
    ) -> Result<Context, Failure> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| *v == body_token)
            .ok_or(Failure::UNAUTHORIZED)?;
        let claims = verify(token, &self.access_key, &self.access_issuer, "game-api")?;
        let account = claims
            .sub
            .parse::<u64>()
            .map_err(|_| Failure::UNAUTHORIZED)?;
        let session = claims
            .sid
            .and_then(|v| uuid::Uuid::parse_str(&v).ok())
            .filter(|v| !v.is_nil())
            .ok_or(Failure::UNAUTHORIZED)?;
        if !ordinary_id(account)
            || !ordinary_id(player)
            || claims.player_id != Some(player)
            || claims.sub != account.to_string()
        {
            return Err(Failure::UNAUTHORIZED);
        }
        Ok(Context {
            account_id: account,
            player_id: player,
            session_id: session,
        })
    }
    pub fn additional(&self, provider: &str, token: &str) -> Result<Authorization, Failure> {
        if !self.providers.iter().any(|p| p == provider) {
            return Err(Failure::BAD_REQUEST);
        }
        if provider == "NONE" {
            return Ok(Authorization {
                provider: provider.into(),
                subject: String::new(),
                discord_id: 0,
                token_id: Vec::new(),
            });
        }
        if token.is_empty() {
            return Err(Failure(StatusCode::UNAUTHORIZED, 32));
        }
        let (key, issuer) = self.discord.as_ref().ok_or(Failure::BAD_REQUEST)?;
        let claims = verify(token, key, issuer, "game-discord-authorization")
            .map_err(|_| Failure(StatusCode::UNAUTHORIZED, 33))?;
        let discord_id = claims
            .sub
            .parse::<u64>()
            .ok()
            .filter(|id| *id != 0)
            .ok_or(Failure(StatusCode::UNAUTHORIZED, 33))?;
        let jti = claims.jti.ok_or(Failure(StatusCode::UNAUTHORIZED, 33))?;
        let id = uuid::Uuid::parse_str(&jti).map_err(|_| Failure(StatusCode::UNAUTHORIZED, 33))?;
        if id.is_nil() || id.to_string() != jti || discord_id.to_string() != claims.sub {
            return Err(Failure(StatusCode::UNAUTHORIZED, 33));
        }
        Ok(Authorization {
            provider: provider.into(),
            subject: claims.sub,
            discord_id,
            token_id: id.as_bytes().to_vec(),
        })
    }
}
fn verify(token: &str, key: &DecodingKey, issuer: &str, audience: &str) -> Result<Claims, Failure> {
    if token.len() > MAX_TOKEN {
        return Err(Failure::UNAUTHORIZED);
    }
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp"]);
    validation.leeway = 0;
    let claims = jsonwebtoken::decode::<Claims>(token, key, &validation)
        .map_err(|_| Failure::UNAUTHORIZED)?
        .claims;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Failure::UNAVAILABLE)?
        .as_secs();
    if claims.iss != issuer
        || claims.aud != audience
        || claims.iat > now
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > LIFETIME_SECONDS
    {
        return Err(Failure::UNAUTHORIZED);
    }
    Ok(claims)
}
pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Failure> {
    let mut values = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|s| s.trim().split_once('='))
        .filter(|(key, _)| *key == name)
        .map(|(_, value)| value);
    let value = values.next().ok_or(Failure::UNAUTHORIZED)?;
    if values.next().is_some() {
        return Err(Failure::UNAUTHORIZED);
    }
    Ok(value)
}
pub fn csrf(headers: &HeaderMap, origin: &str) -> Result<(), Failure> {
    if headers.get("origin").and_then(|v| v.to_str().ok()) != Some(origin) {
        return Err(Failure::FORBIDDEN);
    }
    let cookie = cookie(headers, "__Host-CsrfToken")?;
    let header = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .ok_or(Failure::FORBIDDEN)?;
    let cookie = URL_SAFE_NO_PAD
        .decode(cookie)
        .map_err(|_| Failure::FORBIDDEN)?;
    let header = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| Failure::FORBIDDEN)?;
    if cookie.len() != 32 || header.len() != 32 {
        return Err(Failure::FORBIDDEN);
    }
    let difference = cookie
        .iter()
        .zip(header)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b));
    if difference != 0 {
        return Err(Failure::FORBIDDEN);
    }
    Ok(())
}
pub fn refresh_token(headers: &HeaderMap) -> Result<Vec<u8>, Failure> {
    let encoded = cookie(headers, "__Host-RefreshToken")?;
    let token = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Failure(StatusCode::UNAUTHORIZED, 30))?;
    if token.len() != 32 {
        return Err(Failure(StatusCode::UNAUTHORIZED, 30));
    }
    Ok(token)
}
pub fn refresh_cookie(token: &[u8]) -> String {
    if token.is_empty() {
        "__Host-RefreshToken=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".into()
    } else {
        // Session cookie: rotation cannot extend the fixed DB session expiry.
        format!(
            "__Host-RefreshToken={}; Secure; HttpOnly; SameSite=Strict; Path=/",
            URL_SAFE_NO_PAD.encode(token)
        )
    }
}
