# MCP エンタープライズ・データスイート（セキュリティガードレール内蔵）

> 🌐 **[English Documentation (README.md)](./README.md)**

LangGraph・Claude Code・Cursor・Gemini CLI等のAIエージェントから社内データへ安全に接続するための、**Python + TypeScript 構成の本番志向 Model Context Protocol（MCP）サーバー群**です。全ツール呼び出しに **読み取り専用SQLガードレール・RBAC権限制御・PII自動マスキング・レート制限・監査ログ** を組み込んでいます。

## 同梱MCPサーバー（3種）

1. **SQL Analytics MCP（Python）:** `SELECT` / `WITH` のみ許可（`DROP`/`DELETE`/複文を完全ブロック）、最大件数クランプ、ロール別PII自動マスキング。
2. **Hybrid Vector KB MCP（Python）:** コサイン類似度＋語彙一致のハイブリッド検索による社内規程・設計書検索。
3. **Enterprise Ops Bridge MCP（TypeScript）:** 障害一覧照会・HITL承認フラグ付き変更チケット起票（`analyst` は閲覧のみ、`engineer`/`admin` のみ起票可）。

## テスト実行

```bash
cd python && pip install -e ".[dev]" && ruff check src tests && pytest -v
cd ../typescript && npm install && npm run typecheck && npm test
```

## 作成者

**あぶどら・まもん（工学博士 / PMP）**  
[GitHub](https://github.com/mabdullah-ml) · [LinkedIn](https://www.linkedin.com/in/mamunabdullah01)
