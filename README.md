# PublicAPI

ReHydrangeaOdysseyのゲーム再現プロジェクトを構成するサーバーコンポーネントです。仕様の正本は[Specifications](https://github.com/ReHydrangeaOdyssey/Specifications)です。

## 実装済みの機能・基盤

- HTTP/2・TLS 1.3の公開Protobuf RPC、JWT検証、CORS、CSRF、レート制限。
- ブラウザ認可画面、登録・ログイン・Refresh・Logout・PKCE認可コード交換。
- 初期騎士団、プロフィール、フレンド、Arena編成・対戦APIの内部転送。
- フレームワークのエラーを含むProtobuf応答とno-store設定。

## 現在の制限

騎士団戦Ownerへの転送・購読Stream、施設や所属管理などの公開APIは未接続です。レート制限はプロセス内管理で、複数Replica間の共有はありません。

## 開発

リポジトリルートで次を実行します。未取得の依存がある場合、offline実行は失敗します。

```sh
cargo build --offline --locked
cargo clippy --offline --locked -- -D warnings
cargo fmt --check
```

起動設定は [src/config.rs](src/config.rs) を参照してください。設定JSONのパスを第1引数として渡します。証明書・秘密鍵・認証情報をリポジトリへ保存しないでください。

今後の実装作業向けskill: [develop-public-api](.agents/skills/develop-public-api/SKILL.md)。実装済みの範囲はソースと最新仕様を併せて確認してください。
