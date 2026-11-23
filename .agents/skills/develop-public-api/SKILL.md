---
name: develop-public-api
description: PublicAPIのブラウザ認証・公開Protobuf RPC・内部API転送を変更する際に使用する。
---

# PublicAPIの変更

以下のパスはリポジトリルート基準。隣接する `../Specifications` の最新仕様と実装を確認してから変更する。参照先がない場合は仕様の所在を確認し、READMEやこのskillを仕様の代用にしない。

## 参照と実装境界

Specifications/design/server/ 配下の public_api.md、session.md と design/system/api_transport.md・api_request_validation.md を対象機能に応じて読む。通信型を変更するときはSpecificationsのprotoと各利用側のコピー・生成設定を照合する。

- `application.rs` が公開RPC・認可画面・CORSの入口、`player.rs` がプレイヤー系転送、`auth.rs` がJWT/Cookie/CSRF検証。
- BodyとAuthorization HeaderのAccess Token一致、Player ID、sid、issuer/audience、有効期限を検証し、内部Contextは検証結果から作る。
- Cookieを使う認可画面と静的ClientのCross-Origin RPCを区別する。Originは完全一致、Refresh CookieはSecure/HttpOnly/SameSite=Strict/Path=/。CSRF検証を省かない。
- PKCEコードはPrivateAPIで単回使用を確定する。ブラウザ側にRefresh TokenやAccess Tokenを永続保存する経路を追加しない。
- 内部通信もHTTP/2・TLS・mTLSを使用し、応答サイズとProtobuf型を検証する。Method固有の業務エラーを共通エラーに誤変換しない。
- 認可画面の変更では `static/authorize.js` とCSP、配信設定、Protobuf処理を併せて確認する。
- 騎士団戦Ownerへの転送・更新Streamは未接続。既存のArena転送が騎士団戦にも対応していると仮定しない。

## 検証と引継ぎ

既存テストが対象機能を検証する場合は実行し、`cargo build --offline --locked`、`cargo clippy --offline --locked -- -D warnings`、`cargo fmt --check` で確認する。依存未取得なら無断で外部取得せず、必要なものを示す。新規テストの作成は適用されるAGENTS.mdとユーザー指示に従う。

READMEの実装済み機能と未接続箇所を実コードに合わせる。運用環境が必要な未実施検証をビルド結果と区別して報告する。skill自体は依存追加、DB migration実行、pushやデプロイへの許可を与えない。
