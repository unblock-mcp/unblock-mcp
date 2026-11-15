# 🌐 Unblock MCP (x402 Micro-Toll Scraper)

> Autonomous AI Agent Web Scraping Tool with HTTP 402 Micropayments on Base, Polygon, BSC, Arbitrum, and Solana ($0.005 USDC per call).

---

## ⚡ Live Endpoints
- **Production MCP Endpoint**: `https://unblock-mcp-x402.unblock-mcp.workers.dev/mcp`
- **Machine Discovery Manifest**: `https://unblock-mcp-x402.unblock-mcp.workers.dev/.well-known/mcp.json`
- **Health Check**: `https://unblock-mcp-x402.unblock-mcp.workers.dev/health`

---

## 🔌 Connecting to Claude Desktop / Cursor

Add to your `mcp_config.json`:
```json
{
  "mcpServers": {
    "unblock-mcp": {
      "url": "https://unblock-mcp-x402.unblock-mcp.workers.dev/mcp"
    }
  }
}
```

---

## 🛡️ Built-in Defenses
- **Hardened SSRF Guard**: Strict port filtering (only 80/443), hex/octal/decimal IP evasion blocking, internal TLD blocking.
- **Indirect Prompt Injection Neutralizer**: Automatic sanitization of hostile prompt injection delimiters (`<|im_start|>`, `<<SYS>>`), explicit `<untrusted_scraped_content>` wrapper.
- **Replay & Sybil Protection**: KV-backed nonce tracking rejecting double-spend reuse.
- **Latency Budget**: Strict 15s timeout with automatic timeout fail-safe.
- **Multi-Chain Support**: Base, Polygon, BSC, Arbitrum, and Solana.
