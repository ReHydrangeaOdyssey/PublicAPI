use crate::{
    auth::{Auth, csrf, refresh_cookie, refresh_token},
    protocol::game::{privateapi as q, publicapi as p},
    rate_limit::RateLimit,
    rpc::{self, Context, Failure},
};
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
#[derive(Clone)]
pub struct Application {
    pub auth: Auth,
    pub client: reqwest::Client,
    pub private_url: String,
    pub game_server_url: String,
    pub client_origin: String,
    pub public_origin: String,
    pub required_version: String,
    pub rate: Arc<Mutex<RateLimit>>,
}
pub fn router(state: Application) -> Router {
    Router::new()
        .route("/v1/public/{method}", post(dispatch).options(preflight))
        .route("/auth/authorize", get(authorize))
        .route("/auth/authorize.js", get(authorize_script))
        .fallback(|| async { Failure::NOT_FOUND })
        .layer(DefaultBodyLimit::max(rpc::MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
async fn boundary(
    State(state): State<Application>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if request.version() != axum::http::Version::HTTP_2 {
        return Failure::BAD_REQUEST.into_response();
    }
    let origin = request.headers().get(header::ORIGIN).cloned();
    let valid_origin = origin
        .as_ref()
        .is_some_and(|v| v.as_bytes() == state.client_origin.as_bytes());
    if origin.as_ref().is_some_and(|v| {
        v.as_bytes() != state.client_origin.as_bytes()
            && v.as_bytes() != state.public_origin.as_bytes()
    }) {
        return Failure::FORBIDDEN.into_response();
    }
    let mut response = rpc::normalize_response(next.run(request).await);
    if valid_origin {
        if let Some(origin) = origin {
            response
                .headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        }
        response
            .headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    response
}
async fn preflight(
    State(state): State<Application>,
    headers: HeaderMap,
) -> Result<Response, Failure> {
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(&state.client_origin)
        || headers
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|v| v.to_str().ok())
            != Some("POST")
    {
        return Err(Failure::FORBIDDEN);
    }
    Ok((
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS"),
            (
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Authorization, Content-Type",
            ),
        ],
    )
        .into_response())
}
async fn dispatch(
    State(state): State<Application>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Failure> {
    state.rate.lock().await.check(format!("ip:{}", peer.ip()))?;
    match method.as_str() {
        "GetAdditionalAuthorizationConfig" => {
            let _: p::GetAdditionalAuthorizationConfigRequest = rpc::decode(&headers, body)?;
            Ok(rpc::response(p::GetAdditionalAuthorizationConfigResponse {
                available_providers: state.auth.providers.clone(),
            }))
        }
        "CreateAccount" => state.create(&headers, body).await,
        "Login" => state.login(&headers, body).await,
        "RefreshAccessToken" => state.refresh(&headers, body).await,
        "Logout" => state.logout(&headers, body).await,
        "IssueAuthorizationCode" => state.issue(&headers, body).await,
        "ExchangeAuthorizationCode" => state.exchange(&headers, body).await,
        "CreateGuild" => state.create_guild(&headers, body).await,
        "GetInitialGuildStatus" => state.initial_guild(&headers, body).await,
        "UpdateArenaParty" | "StartArenaBattle" => state.arena(&method, &headers, body).await,
        "SendFriendRequest"
        | "RespondFriendRequest"
        | "RemoveFriend"
        | "ListFriends"
        | "ListNotifications"
        | "GetPlayerProfile"
        | "GetArenaParty" => state.player(&method, &headers, body).await,
        _ => Err(Failure::NOT_FOUND),
    }
}
impl Application {
    pub(crate) async fn private<Q: prost::Message, R: prost::Message + Default>(
        &self,
        method: &str,
        request: Q,
        context: Option<&Context>,
    ) -> Result<R, Failure> {
        rpc::call(
            &self.client,
            &self.private_url,
            &format!("/v1/private/{method}"),
            request,
            context,
            None,
        )
        .await
    }
    async fn create(&self, headers: &HeaderMap, body: Bytes) -> Result<Response, Failure> {
        csrf(headers, &self.public_origin)?;
        let r: p::CreateAccountRequest = rpc::decode(headers, body)?;
        self.rate
            .lock()
            .await
            .check(format!("login:{}", r.login_id))?;
        let auth = self.auth.additional(
            &r.additional_authorization_provider,
            &r.discord_authorization_token,
        )?;
        let response: q::CreateAccountPrivateResponse = self
            .private(
                "CreateAccount",
                q::CreateAccountPrivateRequest {
                    login_id: r.login_id,
                    password: r.password,
                    user_name: r.user_name,
                    discord_user_id: auth.discord_id,
                    discord_authorization_token_id: auth.token_id,
                    additional_authorization_provider: auth.provider,
                    additional_authorization_subject: auth.subject,
                },
                None,
            )
            .await?;
        Ok(rpc::response(p::CreateAccountResponse {
            player_id: response.player_id,
        }))
    }
    async fn login(&self, headers: &HeaderMap, body: Bytes) -> Result<Response, Failure> {
        csrf(headers, &self.public_origin)?;
        let r: p::LoginRequest = rpc::decode(headers, body)?;
        if r.client_version.is_empty() {
            return Err(Failure::BAD_REQUEST);
        }
        if r.client_version != self.required_version {
            let mut response = rpc::response(p::LoginVersionErrorResponse {
                error_code: 24,
                required_version: self.required_version.clone(),
            });
            *response.status_mut() = StatusCode::CONFLICT;
            return Ok(response);
        }
        self.rate
            .lock()
            .await
            .check(format!("login:{}", r.login_id))?;
        let auth = self.auth.additional(
            &r.additional_authorization_provider,
            &r.discord_authorization_token,
        )?;
        let response: q::AuthenticateAccountResponse = self
            .private(
                "AuthenticateAccount",
                q::AuthenticateAccountRequest {
                    login_id: r.login_id,
                    password: r.password,
                    discord_user_id: auth.discord_id,
                    discord_authorization_token_id: auth.token_id,
                    additional_authorization_provider: auth.provider,
                    additional_authorization_subject: auth.subject,
                },
                None,
            )
            .await?;
        let token = response.refresh_token;
        if token.len() != 32 {
            return Err(Failure::UNAVAILABLE);
        }
        cookie_response(
            rpc::response(p::LoginResponse {
                player_id: response.player_id,
                access_token: response.access_token,
            }),
            &token,
        )
    }
    async fn refresh(&self, headers: &HeaderMap, body: Bytes) -> Result<Response, Failure> {
        csrf(headers, &self.public_origin)?;
        let _: p::RefreshAccessTokenRequest = rpc::decode(headers, body)?;
        let result = self
            .private::<_, q::RefreshAccessTokenPrivateResponse>(
                "RefreshAccessToken",
                q::RefreshAccessTokenPrivateRequest {
                    refresh_token: refresh_token(headers)?,
                },
                None,
            )
            .await;
        match result {
            Ok(r) if r.refresh_token.len() == 32 => cookie_response(
                rpc::response(p::RefreshAccessTokenResponse {
                    access_token: r.access_token,
                }),
                &r.refresh_token,
            ),
            Err(e) if e.0 == StatusCode::UNAUTHORIZED => cookie_response(e.into_response(), &[]),
            _ => Err(Failure::UNAVAILABLE),
        }
    }
    async fn logout(&self, headers: &HeaderMap, body: Bytes) -> Result<Response, Failure> {
        csrf(headers, &self.public_origin)?;
        let _: p::LogoutRequest = rpc::decode(headers, body)?;
        let _: q::LogoutPrivateResponse = self
            .private(
                "Logout",
                q::LogoutPrivateRequest {
                    refresh_token: refresh_token(headers)?,
                },
                None,
            )
            .await?;
        cookie_response(rpc::response(p::LogoutResponse {}), &[])
    }
    async fn issue(&self, headers: &HeaderMap, body: Bytes) -> Result<Response, Failure> {
        csrf(headers, &self.public_origin)?;
        let r: p::IssueAuthorizationCodeRequest = rpc::decode(headers, body)?;
        if r.redirect_uri != format!("{}/auth/callback/", self.client_origin)
            || r.code_challenge_sha256.len() != 32
        {
            return Err(Failure::BAD_REQUEST);
        }
        let r: q::IssueAuthorizationCodePrivateResponse = self
            .private(
                "IssueAuthorizationCodePrivate",
                q::IssueAuthorizationCodePrivateRequest {
                    refresh_token: refresh_token(headers)?,
                    redirect_uri: r.redirect_uri,
                    code_challenge_sha256: r.code_challenge_sha256,
                },
                None,
            )
            .await?;
        Ok(rpc::response(p::IssueAuthorizationCodeResponse {
            authorization_code: r.authorization_code,
        }))
    }
    async fn exchange(&self, headers: &HeaderMap, body: Bytes) -> Result<Response, Failure> {
        let r: p::ExchangeAuthorizationCodeRequest = rpc::decode(headers, body)?;
        if r.redirect_uri != format!("{}/auth/callback/", self.client_origin)
            || r.authorization_code.len() != 32
            || !(43..=128).contains(&r.code_verifier.len())
            || !r
                .code_verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(Failure::BAD_REQUEST);
        }
        let r: q::RedeemAuthorizationCodePrivateResponse = self
            .private(
                "RedeemAuthorizationCodePrivate",
                q::RedeemAuthorizationCodePrivateRequest {
                    authorization_code: r.authorization_code,
                    redirect_uri: r.redirect_uri,
                    code_verifier_sha256: Sha256::digest(r.code_verifier.as_bytes()).to_vec(),
                },
                None,
            )
            .await?;
        Ok(rpc::response(p::ExchangeAuthorizationCodeResponse {
            access_token: r.access_token,
            player_id: r.player_id,
        }))
    }
    async fn create_guild(&self, headers: &HeaderMap, body: Bytes) -> Result<Response, Failure> {
        let r: p::CreateGuildRequest = rpc::decode(headers, body)?;
        let context = self.auth.context(headers, &r.access_token, r.player_id)?;
        let r: q::CreateGuildPrivateResponse = self
            .private(
                "CreateGuildPrivate",
                q::CreateGuildPrivateRequest {
                    guild_name: r.guild_name,
                    daytime_start_time: r.daytime_start_time,
                    nighttime_start_time: r.nighttime_start_time,
                },
                Some(&context),
            )
            .await?;
        Ok(rpc::response(p::CreateGuildResponse {
            guild_id: r.guild_id,
        }))
    }
    async fn initial_guild(&self, headers: &HeaderMap, body: Bytes) -> Result<Response, Failure> {
        let r: p::GetInitialGuildStatusRequest = rpc::decode(headers, body)?;
        let context = self.auth.context(headers, &r.access_token, r.player_id)?;
        let r: q::GetInitialGuildStatusPrivateResponse = self
            .private(
                "GetInitialGuildStatusPrivate",
                q::GetInitialGuildStatusPrivateRequest {
                    player_id: context.player_id,
                },
                Some(&context),
            )
            .await?;
        Ok(rpc::response(p::GetInitialGuildStatusResponse {
            initial_guild_created: r.initial_guild_created,
            guild_id: r.guild_id,
        }))
    }
}
fn cookie_response(mut response: Response, token: &[u8]) -> Result<Response, Failure> {
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&refresh_cookie(token)).map_err(|_| Failure::UNAVAILABLE)?,
    );
    Ok(response)
}
async fn authorize() -> Response {
    ([(header::CONTENT_TYPE,"text/html; charset=utf-8"),(header::CONTENT_SECURITY_POLICY,"default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"),
        (header::REFERRER_POLICY,"no-referrer")],include_str!("../static/authorize.html")).into_response()
}
async fn authorize_script(State(state): State<Application>) -> Response {
    let settings = serde_json::json!({ "providers":state.auth.providers, "version":state.required_version,
        "callback":format!("{}/auth/callback/",state.client_origin) });
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        format!(
            "const settings = {};\n{}",
            settings,
            include_str!("../static/authorize.js")
        ),
    )
        .into_response()
}
