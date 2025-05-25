# Auth モジュール

## 役割・責務
アプリケーションの認証・認可機能を担当します。
ユーザーのログイン、ログアウト、トークン管理、権限チェックを行います。

## 機能概要
- ユーザー認証（ログイン/ログアウト）
- JWTトークンの生成・検証
- パスワードリセット
- 権限ベースアクセス制御（RBAC）

## ファイル構成と責務

### controller.go
- `/auth/login` - ユーザーログイン
- `/auth/logout` - ユーザーログアウト
- `/auth/refresh` - トークンリフレッシュ
- `/auth/forgot-password` - パスワードリセット要求
- `/auth/reset-password` - パスワードリセット実行

### service.go
- `Authenticate()` - 認証処理
- `GenerateTokens()` - JWT/リフレッシュトークン生成
- `ValidateToken()` - トークン検証
- `RefreshToken()` - トークンリフレッシュ
- `ResetPassword()` - パスワードリセット処理

### repository.go
- `GetUserByEmail()` - メールアドレスでユーザー検索
- `GetUserByID()` - IDでユーザー検索
- `UpdateLastLogin()` - 最終ログイン時刻更新
- `SavePasswordResetToken()` - パスワードリセットトークン保存

### model.go
```go
type AuthUser struct {
    ID           uint   `json:"id"`
    Email        string `json:"email"`
    PasswordHash string `json:"-"`
    LastLoginAt  *time.Time `json:"last_login_at"`
    IsActive     bool   `json:"is_active"`
}

type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"`
}
```

### dto.go
```go
type LoginRequest struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8"`
}

type LoginResponse struct {
    User   AuthUser   `json:"user"`
    Tokens TokenPair  `json:"tokens"`
}

type RefreshTokenRequest struct {
    RefreshToken string `json:"refresh_token" validate:"required"`
}
```