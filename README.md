# Huma API プロジェクト (with AWS Cognito Authentication)

このプロジェクトは、Go言語とHumaフレームワークを使用したRESTful APIです。
AWS Cognitoを使用したWebログイン機能を実装し、モジュール化されたClean Architectureにより、拡張性と保守性を重視した設計になっています。

## 🏗️ アーキテクチャ概要
- **フレームワーク**: Huma v2 (OpenAPI準拠)
- **ルーター**: Chi
- **認証**: AWS Cognito + JWT
- **データベース**: MySQL 8.0
- **開発環境**: Docker Compose + Air (ホットリロード)

## 📁 プロジェクト構造
```
├── auth/                    # 認証モジュール (Clean Architecture)
│   ├── domain/             # ドメイン層
│   │   ├── entity/         # エンティティ
│   │   ├── repository/     # リポジトリインターフェース
│   │   └── service/        # ドメインサービス
│   ├── usecase/            # ユースケース層
│   ├── infrastructure/     # インフラストラクチャ層
│   │   ├── cognito/        # AWS Cognito実装
│   │   └── persistence/    # データベース実装
│   └── presentation/       # プレゼンテーション層
│       ├── handler/        # HTTPハンドラー
│       └── middleware/     # 認証ミドルウェア
├── cmd/                    # アプリケーションエントリーポイント
├── app/                    # アプリケーション層
├── pkg/                    # 再利用可能なパッケージ
├── shared/                 # 共通ユーティリティ
├── scripts/                # 運用スクリプト
└── .docker/                # Docker設定
```

## 🚀 セットアップ

### 1. 環境変数の設定
```bash
cp .env.example .env
```

`.env`ファイルを編集して、AWS Cognitoの設定を追加してください：
```env
# AWS Cognito Configuration
COGNITO_USER_POOL_ID=ap-northeast-1_xxxxxxxxx
COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
COGNITO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 2. AWS Cognitoの設定

#### User Poolの作成
1. AWS Management Consoleでカメラ Cognitoサービスを開く
2. "User pools"を選択して新しいUser Poolを作成
3. 以下の設定を行う：
   - **Sign-in options**: Email, Username
   - **Password policy**: 任意の強度設定
   - **Multi-factor authentication**: Optional (推奨)
   - **App clients**: 新しいApp clientを作成

#### App Clientの設定
```
Authentication flows:
☑️ ALLOW_USER_PASSWORD_AUTH
☑️ ALLOW_REFRESH_TOKEN_AUTH
☑️ ALLOW_USER_SRP_AUTH
```

### 3. Docker環境での起動
```bash
# コンテナの起動
docker-compose up -d

# ログの確認
docker-compose logs -f app
```

### 4. ローカル環境での起動
```bash
# 依存関係のインストール
go mod tidy

# データベースの起動（MySQLが必要）
docker-compose up -d mysql

# アプリケーションの起動
go run cmd/server/main.go
```

## 🔐 認証API

### エンドポイント一覧

| Method | Endpoint | Description | 認証要否 |
|--------|----------|-------------|---------|
| POST | `/auth/login` | ユーザーログイン | 不要 |
| POST | `/auth/logout` | ユーザーログアウト | 要 |
| GET | `/auth/me` | ユーザープロフィール取得 | 要 |
| PUT | `/auth/me` | ユーザープロフィール更新 | 要 |
| POST | `/auth/refresh` | トークンリフレッシュ | 要 |
| POST | `/auth/forgot-password` | パスワードリセット要求 | 不要 |
| POST | `/auth/confirm-forgot-password` | パスワードリセット確認 | 不要 |
| POST | `/admin/users` | ユーザー作成（管理者） | 要（管理者） |

### 使用例

#### ログイン
```bash
curl -X POST http://localhost:8888/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your-username",
    "password": "your-password"
  }'
```

#### プロフィール取得（認証必要）
```bash
curl -X GET http://localhost:8888/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### 保護されたエンドポイント
```bash
curl -X GET http://localhost:8888/api/v1/greeting/world \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🌐 API ドキュメント

サーバー起動後、以下のURLでOpenAPI仕様書を確認できます：
- **Swagger UI**: http://localhost:8888/docs
- **OpenAPI JSON**: http://localhost:8888/openapi.json

## 🧪 テスト

```bash
# 単体テスト
go test ./auth/domain/...
go test ./auth/usecase/...

# 統合テスト
go test ./auth/infrastructure/...

# E2Eテスト
go test ./auth/presentation/...
```

## 🛠️ 開発ガイドライン

### Clean Architecture
このプロジェクトはClean Architectureに基づいて構成されています：

1. **Domain層**: ビジネスロジックとエンティティ
2. **Usecase層**: アプリケーション固有のビジネスロジック
3. **Infrastructure層**: 外部システム（DB、Cognito）との連携
4. **Presentation層**: HTTP関連の処理

### 新機能の追加
1. Domainエンティティの定義
2. Repositoryインターフェースの作成
3. Usecaseの実装
4. Infrastructureの実装
5. Handlerとルーティングの追加

## 🔒 セキュリティ考慮事項

- JWT トークンの適切な管理
- CORS 設定の適切な構成
- Rate Limiting の実装（必要に応じて）
- HTTPS通信の強制（本番環境）
- 機密情報は環境変数で管理
- SQL インジェクション対策（準備文使用）

## 📝 環境変数

| 変数名 | 説明 | デフォルト値 |
|--------|------|-------------|
| `DB_HOST` | データベースホスト | `mysql` |
| `DB_PORT` | データベースポート | `3306` |
| `DB_USER` | データベースユーザー | `user` |
| `DB_PASSWORD` | データベースパスワード | `password` |
| `DB_NAME` | データベース名 | `database` |
| `COGNITO_USER_POOL_ID` | CognitoユーザープールID | - |
| `COGNITO_CLIENT_ID` | CognitoクライアントID | - |
| `COGNITO_CLIENT_SECRET` | Cognitoクライアントシークレット | - |
| `AWS_REGION` | AWSリージョン | `ap-northeast-1` |
| `JWT_SECRET` | JWTシークレットキー | - |

## 🚨 トラブルシューティング

### よくある問題

1. **Cognito認証エラー**: User PoolとApp Clientの設定を確認
2. **データベース接続エラー**: MySQL サービスの起動を確認
3. **CORS エラー**: フロントエンドのオリジンをCORS設定に追加

### ログの確認
```bash
# アプリケーションログ
docker-compose logs -f app

# データベースログ
docker-compose logs -f mysql
```

## 🤝 コントリビューション

1. フォークしてブランチを作成
2. 変更を実装
3. テストの実行
4. プルリクエストの作成

## 📄 ライセンス

MIT License

## 📞 サポート

問題が発生した場合は、GitHubのIssuesを使用してください。
