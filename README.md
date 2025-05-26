# Huma API プロジェクト

このプロジェクトは、Go言語とHumaフレームワークを使用したRESTful APIです。
モジュール化されたアーキテクチャにより、拡張性と保守性を重視した設計になっています。

## アーキテクチャ概要
- **フレームワーク**: Huma v2 (OpenAPI準拠)
- **ルーター**: Chi
- **データベース**: MySQL 8.0 with GORM
- **開発環境**: Docker Compose + Air (ホットリロード)

## 技術スタック
- **Go**: 1.24.1
- **Huma v2**: OpenAPI準拠のREST APIフレームワーク
- **Chi**: 軽量なHTTPルーター
- **GORM**: Go用のORM
- **MySQL**: リレーショナルデータベース
- **Docker**: コンテナ化

## プロジェクト構造
```
.
├── cmd/                    # アプリケーションエントリーポイント
│   ├── server/            # HTTPサーバー
│   └── migration/         # データベースマイグレーション
├── app/                   # アプリケーション層
│   ├── config/           # 設定管理
│   ├── middleware/       # HTTPミドルウェア
│   ├── modules/          # ビジネスモジュール
│   └── shared/           # 共通ユーティリティ
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
git checkout master-dev
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

## 使用方法

### 開発環境の起動
```bash
make dev
# または
docker-compose up -d
```

### API エンドポイント
- **Health Check**: `GET http://localhost:8888/health`
- **Greeting**: `GET http://localhost:8888/greeting/{name}`
- **API Documentation**: `http://localhost:8888/docs`

### データベース管理

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

# または直接
docker exec -it huma-sample-mysql mysql -uuser -ppassword database
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

## データベース設計

### User モデル
```go
type User struct {
    ID        uint           `gorm:"primarykey" json:"id"`
    CreatedAt time.Time      `json:"created_at"`
    UpdatedAt time.Time      `json:"updated_at"`
    DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
    
    Name     string `gorm:"type:varchar(100);not null" json:"name"`
    Email    string `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
    Password string `gorm:"type:varchar(255);not null" json:"-"`
    Role     string `gorm:"type:varchar(50);default:'user'" json:"role"`
    IsActive bool   `gorm:"default:true" json:"is_active"`
}
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

## API仕様

### OpenAPI仕様書
Humaフレームワークにより、OpenAPI 3.0準拠のAPI仕様書が自動生成されます。
- **Swagger UI**: `http://localhost:8888/docs`
- **OpenAPI JSON**: `http://localhost:8888/openapi.json`

### エンドポイント例

#### Health Check
```http
GET /health
```

レスポンス:
```json
{
  "status": "ok",
  "database": "connected",
  "time": "2023-01-01T00:00:00Z"
}
```

#### Greeting
```http
GET /greeting/world
```

レスポンス:
```json
{
  "message": "Hello, world!"
}
```

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
```

3. **マイグレーションエラー**
```bash
# データベースを再作成
make clean
make init
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
```

## 貢献

1. フォークする
2. フィーチャーブランチを作成 (`git checkout -b feature/amazing-feature`)
3. 変更をコミット (`git commit -m 'Add some amazing feature'`)
4. ブランチにプッシュ (`git push origin feature/amazing-feature`)
5. プルリクエストを作成

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。
