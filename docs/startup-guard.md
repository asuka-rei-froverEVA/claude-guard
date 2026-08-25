# 启动前守护设计

`v0.1.0` 的目标是把官方 Claude Code 启动前的关键风险收敛到一个脚本里。它不改变现有 CC Switch/GPT 工作流，也不接管其他 AI 应用的代理配置。

## 入口

用户执行：

```bash
claude-guard [claude args...]
```

脚本读取安全配置：

```json
{
  "command": "/absolute/path/to/original/claude",
  "allowed_ips": ["203.0.113.10"],
  "allowed_cidrs": ["203.0.113.0/24"]
}
```

`command` 必须是原始 Claude CLI 的绝对路径，避免递归调用 wrapper。

## 检查顺序

1. 检查依赖：`curl`、`jq`。
2. 检查安全配置存在且 `command` 合法。
3. 检查官方 settings 文件存在。
4. 检查官方 settings 不含反代/base URL/托管 token 残留。
5. 检查默认 `~/.claude` 是否存在旧 CC Switch 残留，默认只警告。
6. 检查官方 settings 允许 TUI 内后台任务，同时关闭脱离终端的后台会话、排程、工作流、Remote Control、deep link、hooks 和自动更新。
7. 检查当前项目 settings 没有改写官方路由、凭据、证书、provider、retry 或生命周期策略。
8. 检查 CLI 参数没有覆盖 settings 或开启后台/Remote Control。
9. 检查原始 Claude Code 客户端版本、SHA-256、macOS Team ID 和已知 date/time watermark 逻辑。
10. 检查模型参数没有误写已知危险别名。
11. 通过指定代理和备用 IP 源获取当前 IPv4 出口。
12. 检查 `api.anthropic.com` TLS 和 HTTP CONNECT。
13. 以 warn 模式检查 `platform.claude.com`。
14. 检查 `api.anthropic.com` IPv6 不可达。
15. 如果当前 IP 在 `allowed_ips` 或 `allowed_cidrs` 白名单中，允许启动 Claude。

## Fail closed

以下情况直接拒绝启动：

- 缺少配置。
- `command` 不是绝对路径。
- 官方 settings 包含 `ANTHROPIC_BASE_URL`、`apiKeyHelper`、`PROXY_MANAGED` 等残留。
- watermark-capable 客户端与 `ANTHROPIC_BASE_URL` 或高风险时区等激活条件同时存在。
- 生命周期保护不完整，或 `CLAUDE_CODE_RETRY_WATCHDOG` 被启用。
- 项目设置或 CLI 参数试图覆盖受守护的官方路径。
- 客户端版本、哈希或 macOS 签名与固定值不一致。
- `blocked_plugins` 中的 detached 插件被启用。
- `api.anthropic.com` TLS/CONNECT 检查失败。
- IPv6 可直连 `api.anthropic.com`。
- 当前出口 IP 不在白名单，且用户未手动输入 `unsafe`。

## 非目标

- 不清洗服务端标记、客户端归因或设备指纹。
- 不规避封禁或其他平台保护措施。
- 不自动重启 Claude。
- 不修改 Clash/Mihomo 配置。
- 不读取或打印 Claude token。
