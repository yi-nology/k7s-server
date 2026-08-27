# k7s-server

k7s 的 HTTP 服务器 + MCP 服务器，从 `k7s-desktop` 抽取而来。

## 依赖关系

```
k7s-deps (共享依赖)
  └─ k7s-core (业务逻辑)
       └─ k7s-server (本项目: web + MCP server)
            ├─ k7s (Docker 构建)
            └─ k7s-desktop (Tauri 桌面)
```

## 包含内容

- `src/web/` — Axum HTTP 服务器 (SSE, auth, handlers)
- `src/mcp/` — MCP 服务器 (stdio + Streamable HTTP)
- `src/bin/k7s-web.rs` — Web 服务器入口
- `src/bin/k7s-mcp.rs` — MCP 服务器入口

## 鉴权模型（k7s-web）

`k7s-web` 通过 HTTP 暴露完整的 Kubernetes 控制面（apply/delete/drain/exec、读取 Secret），
因此除 `/api/health` 外**所有端点都在鉴权门后**：

- **浏览器会话**：单用户密码门（`/api/auth/*` 签发 HttpOnly cookie，首次访问时设置密码）。
- **API / MCP 客户端**：每个请求都必须携带 `Authorization: Bearer $K7S_WEB_TOKEN`。
  这**包括** `/mcp`（MCP over HTTP，暴露 shell/exec 等工具）、`/api/events`（SSE 事件流，
  会广播终端输出）和 `/api/status`（泄漏当前 context 与 API server 地址）。

Token 来源：设置了 `K7S_WEB_TOKEN` 就使用它；否则在数据目录生成一个随机 token
（loopback 绑定下 SPA 可经 `GET /api/web-token` 自动获取）。非 loopback 绑定（如
`0.0.0.0`）**必须**显式设置 `K7S_WEB_TOKEN`，否则服务端会拒绝发布 token 并大声告警。

相关环境变量：

| 变量 | 说明 |
|---|---|
| `K7S_WEB_TOKEN` | API + MCP 的 Bearer token（非 loopback 必须设置，用强随机值如 `openssl rand -base64 32`） |
| `K7S_HOOK_TOKEN` | `/hooks/*` AI webhook 的独立 token（不设置则 webhook 禁用） |
| `K7S_ALLOWED_ORIGINS` | 额外允许的 CORS 源（逗号分隔） |

## MCP 客户端连接（Streamable HTTP）

MCP over HTTP 端点为 `http://<host>:<port>/mcp`，连接时**必须**配置 Bearer token
（即 `K7S_WEB_TOKEN`），否则所有请求返回 401。

Claude Desktop（`claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "k7s": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer <K7S_WEB_TOKEN>"
      }
    }
  }
}
```

Cursor（`~/.cursor/mcp.json`，支持环境变量展开）：

```json
{
  "mcpServers": {
    "k7s": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer ${K7S_WEB_TOKEN}"
      }
    }
  }
}
```

curl 快速验证：

```sh
curl -s -H "Authorization: Bearer $K7S_WEB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
  http://127.0.0.1:8080/mcp
```

> 注意：把 k7s-web 暴露到局域网时，必须设置强随机 `K7S_WEB_TOKEN` 并置于 TLS
> 反向代理之后——k7s-web 本身是明文 HTTP。

## 构建

```bash
# Web 服务器二进制 (带嵌入式前端)
cargo build --release --features web --bin k7s-web

# MCP 服务器二进制
cargo build --release --features mcp --bin k7s-mcp
```

## Docker 构建

```bash
# 从父目录 (包含 k7s-server, k7s-core, k7s-deps, dist/)
docker build -t ghcr.io/yi-nology/k7s:latest -f k7s-server/Dockerfile .
```
