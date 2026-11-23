use crate::{
    application::Application,
    protocol::game::{privateapi as q, publicapi as p},
    rpc::{self, Failure},
};
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use prost::Message;
impl Application {
    pub(crate) async fn player(
        &self,
        method: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Response, Failure> {
        macro_rules! forward {
            ($request:ty,$response:ty,$method:literal,$convert:expr) => {{
                let r: $request = rpc::decode(headers, body)?;
                let context = self.auth.context(headers, &r.access_token, r.player_id)?;
                let r: $response = self.private($method, ($convert)(r), Some(&context)).await?;
                Ok(rpc::response(r))
            }};
        }
        match method {
            "SendFriendRequest" => forward!(
                p::SendFriendRequestRequest,
                q::SendFriendRequestPrivateResponse,
                "SendFriendRequestPrivate",
                |r: p::SendFriendRequestRequest| q::SendFriendRequestPrivateRequest {
                    sender_player_id: r.player_id,
                    recipient_player_id: r.target_player_id
                }
            ),
            "RespondFriendRequest" => forward!(
                p::RespondFriendRequestRequest,
                q::RespondFriendRequestPrivateResponse,
                "RespondFriendRequestPrivate",
                |r: p::RespondFriendRequestRequest| q::RespondFriendRequestPrivateRequest {
                    recipient_player_id: r.player_id,
                    sender_player_id: r.sender_player_id,
                    approve: r.approve
                }
            ),
            "RemoveFriend" => forward!(
                p::RemoveFriendRequest,
                q::RemoveFriendPrivateResponse,
                "RemoveFriendPrivate",
                |r: p::RemoveFriendRequest| q::RemoveFriendPrivateRequest {
                    player_id: r.player_id,
                    friend_player_id: r.friend_player_id
                }
            ),
            "ListFriends" => forward!(
                p::ListFriendsRequest,
                q::ListFriendsPrivateResponse,
                "ListFriendsPrivate",
                |r: p::ListFriendsRequest| q::ListFriendsPrivateRequest {
                    player_id: r.player_id
                }
            ),
            "ListNotifications" => forward!(
                p::ListNotificationsRequest,
                q::ListFriendRequestsPrivateResponse,
                "ListFriendRequestsPrivate",
                |r: p::ListNotificationsRequest| q::ListFriendRequestsPrivateRequest {
                    recipient_player_id: r.player_id
                }
            ),
            "GetArenaParty" => forward!(
                p::GetArenaPartyRequest,
                q::GetMyArenaPartyPrivateResponse,
                "GetMyArenaPartyPrivate",
                |r: p::GetArenaPartyRequest| q::GetMyArenaPartyPrivateRequest {
                    player_id: r.player_id
                }
            ),
            "GetPlayerProfile" => {
                let r: p::GetPlayerProfileRequest = rpc::decode(headers, body)?;
                let context = self.auth.context(headers, &r.access_token, r.player_id)?;
                let r: q::GetPlayerProfilePrivateResponse = self
                    .private(
                        "GetPlayerProfilePrivate",
                        q::GetPlayerProfilePrivateRequest {
                            requester_player_id: context.player_id,
                            target_player_id: r.target_player_id,
                        },
                        Some(&context),
                    )
                    .await?;
                Ok(rpc::response(r.profile.ok_or(Failure::UNAVAILABLE)?))
            }
            _ => Err(Failure::NOT_FOUND),
        }
    }
    pub(crate) async fn arena(
        &self,
        method: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Response, Failure> {
        let (context, encoded) = match method {
            "UpdateArenaParty" => {
                let r: p::UpdateArenaPartyRequest = rpc::decode(headers, body)?;
                party(&r.characters)?;
                (
                    self.auth.context(headers, &r.access_token, r.player_id)?,
                    r.encode_to_vec(),
                )
            }
            "StartArenaBattle" => {
                let r: p::ArenaBattleRequest = rpc::decode(headers, body)?;
                if !r.mode.is_some_and(|v| v == 0 || v == 1) || r.client_version.is_empty() {
                    return Err(Failure::BAD_REQUEST);
                }
                party(&r.local_characters)?;
                (
                    self.auth.context(headers, &r.access_token, r.player_id)?,
                    r.encode_to_vec(),
                )
            }
            _ => return Err(Failure::NOT_FOUND),
        };
        let mut response = self
            .client
            .post(format!(
                "{}/v1/public/{method}",
                self.game_server_url.trim_end_matches('/')
            ))
            .header(header::CONTENT_TYPE, "application/x-protobuf")
            .header(
                rpc::CONTEXT_HEADER,
                serde_json::to_string(&context).map_err(|_| Failure::UNAVAILABLE)?,
            )
            .body(encoded)
            .send()
            .await
            .map_err(|_| Failure::UNAVAILABLE)?;
        if response.version() != reqwest::Version::HTTP_2
            || response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                != Some("application/x-protobuf")
        {
            return Err(Failure::UNAVAILABLE);
        }
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Failure::UNAVAILABLE)? {
            if chunk.len() > rpc::MAX_BODY.saturating_sub(bytes.len()) {
                return Err(Failure::UNAVAILABLE);
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut result = if status == StatusCode::OK {
            if method == "StartArenaBattle" {
                rpc::response(
                    p::ArenaBattleResponse::decode(bytes.as_slice())
                        .map_err(|_| Failure::UNAVAILABLE)?,
                )
            } else {
                rpc::response(
                    p::UpdateArenaPartyResponse::decode(bytes.as_slice())
                        .map_err(|_| Failure::UNAVAILABLE)?,
                )
            }
        } else {
            let error =
                p::ApiErrorResponse::decode(bytes.as_slice()).map_err(|_| Failure::UNAVAILABLE)?;
            if status == StatusCode::CONFLICT && error.error_code == 24 {
                rpc::response(
                    p::ClientVersionMismatchResponse::decode(bytes.as_slice())
                        .map_err(|_| Failure::UNAVAILABLE)?,
                )
            } else if status == StatusCode::CONFLICT
                && method == "StartArenaBattle"
                && (0..=4).contains(&error.error_code)
            {
                rpc::response(p::ArenaBattleErrorResponse {
                    error_code: error.error_code,
                })
            } else {
                return Err(Failure(status, error.error_code));
            }
        };
        *result.status_mut() = status;
        Ok(result)
    }
}
fn party(characters: &[p::ArenaPartyCharacter]) -> Result<(), Failure> {
    let mut ids = std::collections::BTreeSet::new();
    let mut positions = std::collections::BTreeSet::new();
    if !(1..=5).contains(&characters.len()) {
        return Err(Failure::BAD_REQUEST);
    }
    for c in characters {
        if c.character_id == u32::MAX
            || c.main_skill_id == u32::MAX
            || !(1..=9).contains(&c.position)
            || !ids.insert(c.character_id)
            || !positions.insert(c.position)
            || c.follower_character_id.len() != 2
            || c.ability_id.len() != 2
        {
            return Err(Failure::BAD_REQUEST);
        }
    }
    Ok(())
}
