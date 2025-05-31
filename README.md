# Huma API プロジェクト

このプロジェクトは、Go言語とHumaフレームワークを使用したRESTful APIです。
モジュール化されたアーキテクチャにより、拡張性と保守性を重視した設計になっています。

## アーキテクチャ概要
- **フレームワーク**: Huma v2.32.0 (OpenAPI 3.1準拠)
- **ルーター**: Chi
- **データベース**: MySQL 8.0 with GORM
- **認証**: AWS Cognito / Cognito Local
- **開発環境**: Docker Compose + Air (ホットリロード)

## 技術スタック
- **Go**: 1.24.1
- **Huma v2**: OpenAPI準拠のREST APIフレームワーク
- **Chi**: 軽量なHTTPルーター
- **GORM**: Go用のORM
- **MySQL**: リレーショナルデータベース
- **AWS Cognito**: ユーザー認証・管理
- **Docker**: コンテナ化

## 主要機能

### 🔐 認証システム
- **ユーザー登録・認証**: メール確認付きサインアップ
- **トークン管理**: JWT + AWS Cognito統合
- **パスワード管理**: 強度チェック、リセット、変更
- **セキュリティ**: ミドルウェアベースの認証・認可

### 🛠 開発者体験
- **OpenAPI文書**: 自動生成された詳細なAPI仕様書
- **バリデーション**: Huma組み込みのリクエスト/レスポンス検証
- **エラーハンドリング**: RFC 7807準拠の統一エラーレスポンス
- **ホットリロード**: Air による自動リロード

### 🏗 アーキテクチャ特徴
- **グループ化ルーティング**: 認証・認可レベル別のルート管理
- **モジュラー設計**: 独立したビジネスドメイン
- **ミドルウェア**: 横断的関心事の分離
- **設定管理**: 環境変数ベースの設定

## プロジェクト構造
```
.
├── cmd/                    # アプリケーションエントリーポイント
│   ├── server/            # HTTPサーバー
│   └── migration/         # データベースマイグレーション
├── app/                   # アプリケーション層
│   ├── config/           # 設定管理
│   ├── middleware/       # HTTPミドルウェア (認証、CORS等)
│   ├── modules/          # ビジネスモジュール
│   │   ├── auth/        # 認証モジュール (Cognito統合)
│   │   └── users/       # ユーザー管理モジュール
│   └── shared/           # 共通ユーティリティ
│       ├── errors/      # 統一エラーハンドリング
│       ├── response/    # レスポンス管理
│       └── utils/       # JWT、パスワード、バリデーション
├── pkg/                   # 再利用可能なパッケージ
├── .docker/              # Docker設定
└── scripts/              # 運用スクリプト
```

## 環境構築

### 必要な環境
- Docker
- Docker Compose
- Make (オプション)

### 初期セットアップ

1. **リポジトリのクローン**
```bash
git clone https://github.com/asakuno/huma-sample.git
cd huma-sample
git checkout master-dev2-refactor
```

2. **環境変数の設定**
```bash
cp .env.example .env
# 必要に応じて .env ファイルを編集
```

3. **プロジェクトの初期化（推奨）**
```bash
make init
```

または手動で：
```bash
docker-compose build
docker-compose up -d
# データベースが起動するまで待機
make migrate-seed
```

## 認証機能 (AWS Cognito)

### ローカル開発環境 (Cognito Local)
開発環境では、AWS Cognitoの代わりに`cognito-local`を使用してローカルで認証機能をテストできます。

```bash
# docker-compose.ymlに既に設定済み
# cognito-localは自動的に起動します
```

**ローカルCognito設定:**
- エンドポイント: `http://localhost:9229`
- User Pool ID: `local_test_pool`
- Client ID: `local_test_client`

### 本番環境 (AWS Cognito)
本番環境では、実際のAWS Cognitoを使用します。

1. **AWS Cognitoユーザープールの作成**
2. **アプリクライアントの作成**
3. **環境変数の設定**
```bash
USE_COGNITO_LOCAL=false
AWS_REGION=ap-northeast-1
COGNITO_USER_POOL_ID=your-actual-pool-id
COGNITO_APP_CLIENT_ID=your-actual-client-id
COGNITO_APP_CLIENT_SECRET=your-actual-client-secret  # オプション
```

## API仕様

### OpenAPI仕様書
Humaフレームワークにより、OpenAPI 3.1準拠のAPI仕様書が自動生成されます。
- **Swagger UI**: `http://localhost:8888/docs`
- **OpenAPI JSON**: `http://localhost:8888/openapi.json`
- **OpenAPI YAML**: `http://localhost:8888/openapi.yaml`

### 主要エンドポイント

#### 🏥 ヘルスチェック
```http
GET /health
```

#### 🔐 認証エンドポイント (パブリック)
- `POST /auth/signup` - ユーザー登録
- `POST /auth/verify-email` - メール確認
- `POST /auth/login` - ログイン
- `POST /auth/refresh` - トークンリフレッシュ
- `POST /auth/forgot-password` - パスワードリセット要求
- `POST /auth/reset-password` - パスワードリセット実行
- `GET /auth/health` - 認証サービスヘルスチェック

#### 🔒 認証エンドポイント (認証必須)
- `POST /auth/change-password` - パスワード変更
- `POST /auth/logout` - ログアウト
- `GET /auth/profile` - プロフィール取得

#### 🎯 サンプルエンドポイント
- `GET /greeting/{name}` - 挨拶メッセージ

## Humaフレームワークの活用

### ✨ 新機能・改善点

#### 1. **統一エラーハンドリング**
```go
// Humaの標準エラー機能を活用
func NewBadRequestError(message string, details ...string) error {
    if len(details) > 0 {
        errs := make([]error, len(details))
        for i, detail := range details {
            errs[i] = &huma.ErrorDetail{
                Message:  detail,
                Location: "body",
            }
        }
        return huma.Error422UnprocessableEntity(message, errs...)
    }
    return huma.Error400BadRequest(message)
}
```

#### 2. **グループ化ルーティング**
```go
// パブリックルート（認証不要）
publicGroup := huma.NewGroup(authGroup)
huma.Post(publicGroup, "/signup", controller.SignUp, ...)

// プロテクトルート（認証必須）
protectedGroup := huma.NewGroup(authGroup)
protectedGroup.UseMiddleware(middleware.RequireAuth(cfg.JWT.Secret))
huma.Post(protectedGroup, "/change-password", controller.ChangePassword, ...)
```

#### 3. **高度なバリデーション**
```go
type SignUpRequest struct {
    Body struct {
        Email    string `json:"email" format:"email" doc:"User email address"`
        Username string `json:"username" minLength:"3" maxLength:"50" pattern:"^[a-zA-Z0-9_-]+$"`
        Password string `json:"password" minLength:"8" maxLength:"128"`
        Name     string `json:"name" minLength:"2" maxLength:"100"`
    }
}
```

#### 4. **改善されたミドルウェア**
```go
// Humaの組み込みエラー処理を活用
func handleAuthError(ctx huma.Context, err error) {
    api := ctx.Operation().API
    if statusErr, ok := err.(huma.StatusError); ok {
        huma.WriteErr(api, ctx, statusErr.GetStatus(), statusErr.Error())
    } else {
        huma.WriteErr(api, ctx, 500, err.Error())
    }
}
```

## 使用方法

### 開発環境の起動
```bash
make dev
# または
docker-compose up -d
```

### API例

#### ユーザー登録
```http
POST /auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "testuser",
  "password": "Password123!",
  "name": "Test User"
}
```

#### ログイン
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "Password123!"
}
```

### 認証が必要なエンドポイント
```http
GET /auth/profile
Authorization: Bearer your-jwt-token
```

## データベース管理

#### マイグレーション
```bash
# マイグレーション実行
make migrate

# サンプルデータの投入
make seed

# マイグレーション + シード（一括実行）
make migrate-seed

# ロールバック
make rollback
```

#### データベース接続
```bash
# MySQLシェルに接続
make db-shell
```

### 開発コマンド

```bash
# ログ表示
make logs          # 全サービスのログ
make dev-logs      # アプリケーションのログのみ

# コンテナ管理
make up            # コンテナ起動
make down          # コンテナ停止
make ps            # コンテナ状態確認

# アプリケーション
make shell         # アプリケーションコンテナにアクセス
make test          # テスト実行
make go-tidy       # go mod tidy実行

# クリーンアップ
make clean         # コンテナとボリュームを削除
make fresh         # クリーンアップ後に初期化
```

## 設定

### 環境変数
| 変数名 | 説明 | デフォルト値 |
|--------|------|-------------|
| `APP_NAME` | アプリケーション名 | `huma-sample` |
| `APP_ENV` | 実行環境 | `development` |
| `DB_HOST` | データベースホスト | `mysql` |
| `DB_USER` | データベースユーザー | `user` |
| `DB_PASS` | データベースパスワード | `password` |
| `DB_NAME` | データベース名 | `database` |
| `DB_PORT` | データベースポート | `3306` |
| `GOLANG_PORT` | アプリケーションポート | `8888` |
| `JWT_SECRET` | JWT秘密鍵 | `secret_key` |
| `USE_COGNITO_LOCAL` | ローカルCognito使用フラグ | `true` |
| `COGNITO_LOCAL_ENDPOINT` | ローカルCognitoエンドポイント | `http://cognito-local:9229` |

## トラブルシューティング

### よくある問題

1. **データベース接続エラー**
```bash
# データベースコンテナの状態確認
make ps
# データベースログ確認
docker-compose logs mysql
```

2. **ポート競合**
```bash
# 使用中のポートを確認
lsof -i :8888
lsof -i :3306
lsof -i :9229  # Cognito Local
```

3. **マイグレーションエラー**
```bash
# データベースを再作成
make clean
make init
```

4. **Cognito Local接続エラー**
```bash
# Cognito Localのログ確認
docker-compose logs cognito-local
# コンテナ再起動
docker-compose restart cognito-local
```

### ログ確認
```bash
# 全体のログ
make logs

# アプリケーションのみ
make dev-logs

# 特定のサービス
docker-compose logs mysql
docker-compose logs nginx
docker-compose logs cognito-local
```

## 新機能・改善点

### 🆕 Huma v2.32.0 活用

#### Group機能
- パブリック/プロテクトルートの明確な分離
- ミドルウェアの階層的適用
- 管理者専用ルートの準備

#### 強化されたバリデーション
- JSON Schema準拠のリクエスト検証
- 自動的なエラーレスポンス生成
- パターンマッチング、長さ制限など

#### 改善されたエラーハンドリング
- RFC 7807準拠のエラーフォーマット
- 詳細なエラー位置情報
- 統一されたエラーレスポンス

#### OpenAPI 3.1 完全対応
- より豊富なスキーマ定義
- 改善された型安全性
- 自動生成されるクライアントSDK対応

## 貢献

1. フォークする
2. フィーチャーブランチを作成 (`git checkout -b feature/amazing-feature`)
3. 変更をコミット (`git commit -m 'Add some amazing feature'`)
4. ブランチにプッシュ (`git push origin feature/amazing-feature`)
5. プルリクエストを作成

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。

---

## 更新履歴

### v2.0.0 (master-dev2-refactor)
- Huma v2.32.0の機能を全面活用
- Group機能によるルーティング整理
- 統一エラーハンドリングの実装
- バリデーション機能の強化
- OpenAPI文書の改善
- ミドルウェアアーキテクチャの最適化

### v1.0.0 (master-dev2)
- 基本的なHuma APIの実装
- AWS Cognito統合
- 基本的な認証機能
