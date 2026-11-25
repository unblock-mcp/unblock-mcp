# 🌐 Unblock MCP (x402 Micro-Toll Scraper) — [FROZEN / R&D ARCHIVE]

> **Status**: ❄️ **Frozen / R&D Hold (2026-11-25)**  
> **Reason**: Following the launch of `solana.ai`, `Pay.sh` (`@solana/pay-kit`), and Solana Payment Channels in November 2026, generic HTTP 402 paywall wrappers commoditized and simple scraping faces direct competition from Firecrawl/Apify. The prototype is preserved in **fail-closed** mode as an engineering reference.

---

## 🔒 Security Posture (Fail-Closed Mode)
- **Payment Settlement**: Production execution strictly fails closed (`HTTP 403`) unless a verified on-chain settlement facilitator (`COINBASE_CDP_API_KEY`) and non-zero recipient wallet are configured. Empty-wallet EIP-712 signatures cannot bypass billing.
- **Hardened SSRF Guard**: Strict port filtering (80/443), hex/octal/decimal/IPv4-mapped IPv6 blocking, internal TLD and DNS rebinding service blocking (`nip.io`, `sslip.io`, `traefik.me`).
- **Indirect Prompt Injection Neutralizer**: Automatic sanitization of prompt injection delimiters (`<|im_start|>`, `<<SYS>>`) wrapped in `<untrusted_scraped_content>`.
- **Replay Protection**: In-memory concurrency lock + Cloudflare KV nonce deduplication.

---

## ⚡ Local Verification
```bash
npx tsx tests/unit.test.ts
```
