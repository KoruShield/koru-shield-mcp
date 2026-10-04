# Koru Shield MCP Server

Manage your [Koru Shield](https://korushield.com) DNS protection through AI assistants. Block domains, check policies, review blocked queries, manage schedules, and more, all through natural language.

## What it does

Exposes your Koru Shield account as [Model Context Protocol](https://modelcontextprotocol.io) tools:

| Tool | What it does |
|---|---|
| `list_profiles` / `get_profile` | List and inspect DNS protection profiles |
| `create_rule` / `list_rules` / `delete_rule` | Block or allow domains per profile |
| `list_filter_categories` / `set_filter_category` | Toggle categories (adult, gambling, social media...) |
| `simulate_policy` | Check if a domain would be blocked right now |
| `get_logs` | Recent DNS queries: allowed, blocked, when |
| `analytics_summary` | Totals, blocked percentage, encrypted queries |
| `list_schedules` / `create_schedule` / `delete_schedule` | Time windows (bedtime, homework hours) |
| `list_devices` | Devices enrolled per profile |
| `get_entitlements` | Plan, limits, current usage |
| `get_referral_code` | Your referral link |

Example prompts once connected:

- "Block tiktok.com on the Kids profile"
- "Would youtube.com be blocked on Kids right now?"
- "Show me what got blocked today"
- "Turn on adult content filtering for the whole house"
- "Add a bedtime schedule 9pm to 7am on weekdays for the Kids profile"

## Setup

### 1. Get a Koru Shield API key

Sign in at https://my.korushield.com, go to API keys, and create one. Copy the key.

### 2. Install

No install needed. Run directly with npx:

```bash
npx -y korushield-mcp-server
```

Set your key as an environment variable:

```bash
export KORU_SHIELD_API_KEY="your-key-here"
```

Optional: `KORU_SHIELD_API_URL` overrides the API base URL (default `https://my.korushield.com/api`).

### 3. Connect your AI client

**Claude Code**

```bash
claude mcp add koru-shield -- npx -y korushield-mcp-server
```

(Claude Code passes environment through, so export `KORU_SHIELD_API_KEY` first. Or use the HTTP transport below with a header.)

**Cursor / VS Code**

Add to your MCP config (`~/.cursor/mcp.json` or VS Code `mcp.json`):

```json
{
  "mcpServers": {
    "koru-shield": {
      "command": "npx",
      "args": ["-y", "korushield-mcp-server"],
      "env": {
        "KORU_SHIELD_API_KEY": "your-key-here"
      }
    }
  }
}
```

**Claude Desktop**

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "koru-shield": {
      "command": "npx",
      "args": ["-y", "korushield-mcp-server"],
      "env": {
        "KORU_SHIELD_API_KEY": "your-key-here"
      }
    }
  }
}
```

### HTTP transport (remote)

For clients that connect over HTTP (agents, hosted setups):

```bash
MCP_TRANSPORT=http PORT=3000 KORU_SHIELD_API_KEY="your-key-here" npx -y korushield-mcp-server
```

Or pass the key per-request instead of the env var:

```
POST https://your-host/mcp
Authorization: Bearer <koru-shield-api-key>
```

Health check: `GET /healthz`.

## Security notes

- Your API key grants full control of your Koru Shield account, including deleting rules and schedules. Treat it like a password.
- Prefer a dedicated API key for AI assistants so you can revoke it independently.
- The server never logs or transmits your key anywhere except to the Koru Shield API.

## Development

```bash
npm install
npm run build
npm start
```

Test with the MCP Inspector:

```bash
KORU_SHIELD_API_KEY="your-key-here" npm run inspector
```

## License

MIT
