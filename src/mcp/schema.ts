/**
 * Model Context Protocol (MCP) Tool Schemas and Server Manifests
 */

export const MCP_TOOLS = [
  {
    name: "fetch_clean_markdown",
    description:
      "Bypasses anti-bot/Cloudflare protections and returns clean, LLM-optimized Markdown text for any public web URL. Operates with pay-per-call micropayments ($0.005 USDC on Base).",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The full target URL (http or https) to scrape and convert to markdown.",
        },
      },
      required: ["url"],
    },
    x402: {
      price: "0.005",
      currency: "USDC",
      network: "base",
    },
  },
];

export const SERVER_INFO = {
  name: "unblock-mcp-x402",
  version: "1.0.0",
  description: "Autonomous Agent Web Scraping Tool with x402 Machine Micropayments",
  capabilities: {
    tools: {
      listChanged: false,
    },
  },
};
