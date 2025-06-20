# Utils ディレクトリ

## 役割・責務
アプリケーション全体で使用される汎用的なユーティリティ関数群を提供します。

## ファイル構成
- `jwt.go` - JWT トークンの生成・検証
- `password.go` - パスワードハッシュ化・検証
- `validate.go` - バリデーション関数

## 実装方針
- 純粋関数として実装
- エラーハンドリングの統一
- 設定可能なパラメータ

## AI開発ガイドライン
- セキュリティベストプラクティスの遵守（特にJWT、パスワード）
- テストカバレッジ100%を目指す
- パフォーマンスを考慮した実装