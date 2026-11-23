use crate::protocol::game::publicapi::ApiErrorResponse;
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use prost::Message;

pub const MAX_BODY: usize = 1024 * 1024;
pub const CONTEXT_HEADER: &str = "x-authenticated-context";

#[derive(Clone, Copy, Debug)]
pub struct Failure(pub StatusCode, pub i32);
impl Failure {
    pub const BAD_REQUEST: Self = Self(StatusCode::BAD_REQUEST, 0);
    pub const UNAUTHORIZED: Self = Self(StatusCode::UNAUTHORIZED, 2);
    pub const FORBIDDEN: Self = Self(StatusCode::FORBIDDEN, 0);
    pub const NOT_FOUND: Self = Self(StatusCode::NOT_FOUND, 0);
    pub const CONFLICT: Self = Self(StatusCode::CONFLICT, 41);
    pub const UNAVAILABLE: Self = Self(StatusCode::SERVICE_UNAVAILABLE, 31);
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (
            self.0,
            [
                (header::CONTENT_TYPE, "application/x-protobuf"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            ApiErrorResponse { error_code: self.1 }.encode_to_vec(),
        )
            .into_response()
    }
}

pub fn response<M: Message>(message: M) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/x-protobuf"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        message.encode_to_vec(),
    )
        .into_response()
}

pub fn decode<M: Message + Default>(headers: &HeaderMap, body: Bytes) -> Result<M, Failure> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/x-protobuf")
    {
        return Err(Failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, 0));
    }
    M::decode(body).map_err(|_| Failure::BAD_REQUEST)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub account_id: u64,
    pub player_id: u64,
    pub session_id: uuid::Uuid,
}
impl Context {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, Failure> {
        let raw = headers.get(CONTEXT_HEADER).ok_or(Failure::UNAUTHORIZED)?;
        let value: Self =
            serde_json::from_slice(raw.as_bytes()).map_err(|_| Failure::UNAUTHORIZED)?;
        if !ordinary_id(value.account_id)
            || !ordinary_id(value.player_id)
            || value.session_id.is_nil()
        {
            return Err(Failure::UNAUTHORIZED);
        }
        Ok(value)
    }
}
pub fn ordinary_id(id: u64) -> bool {
    id != 0 && id != u64::MAX
}

pub async fn call<Q: Message, R: Message + Default>(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    request: Q,
    context: Option<&Context>,
    operation_id: Option<uuid::Uuid>,
) -> Result<R, Failure> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let mut request = client
        .post(url)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(request.encode_to_vec());
    if let Some(context) = context {
        request = request.header(
            CONTEXT_HEADER,
            serde_json::to_string(context).map_err(|_| Failure::BAD_REQUEST)?,
        );
    }
    if let Some(id) = operation_id {
        if id.is_nil() {
            return Err(Failure::BAD_REQUEST);
        }
        request = request.header("x-operation-id", id.to_string());
    }
    let mut result = request.send().await.map_err(|_| Failure::UNAVAILABLE)?;
    if result.version() != reqwest::Version::HTTP_2 {
        return Err(Failure::UNAVAILABLE);
    }
    if result
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/x-protobuf")
    {
        return Err(Failure::UNAVAILABLE);
    }
    let status = result.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = result.chunk().await.map_err(|_| Failure::UNAVAILABLE)? {
        if chunk.len() > MAX_BODY.saturating_sub(bytes.len()) {
            return Err(Failure::UNAVAILABLE);
        }
        bytes.extend_from_slice(&chunk);
    }
    if status != StatusCode::OK {
        let error = ApiErrorResponse::decode(bytes.as_slice()).map_err(|_| Failure::UNAVAILABLE)?;
        return Err(Failure(status, error.error_code));
    }
    R::decode(bytes.as_slice()).map_err(|_| Failure::UNAVAILABLE)
}
