/**
 * Configuration and Environment Interface for x402 MCP Server
 * Multi-chain Support & Security Thresholds
 */

export interface Env {
  PAYMENT_RECIPIENT_EVM: string;
  PAYMENT_RECIPIENT_SOLANA?: string;
  PAYMENT_AMOUNT_USDC: string;
  UPSTREAM_STEALTH_GATEWAY?: string;
  UPSTREAM_API_KEY?: string;
  NONCE_KV: KVNamespace;
  CACHE_KV: KVNamespace;
  COINBASE_CDP_API_KEY?: string;
  ENVIRONMENT?: string;
  ALLOW_MOCK_PAYMENT?: string;
}

export const PROTOCOL_CONFIG = {
  VERSION: "1.1.0",
  TOKEN_NAME: "USDC",
  TOKEN_DECIMALS: 6,
  DEFAULT_PRICE_USDC: "0.005",

  // Multi-Chain Networks
  NETWORKS: {
    base: {
      chainId: 8453,
      name: "Base",
      type: "evm",
      usdcContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
    polygon: {
      chainId: 137,
      name: "Polygon",
      type: "evm",
      usdcContract: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
    },
    bsc: {
      chainId: 56,
      name: "BNB Smart Chain",
      type: "evm",
      usdcContract: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
    },
    arbitrum: {
      chainId: 42161,
      name: "Arbitrum One",
      type: "evm",
      usdcContract: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    },
    solana: {
      name: "Solana",
      type: "solana",
      usdcMint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    },
  },

  // Security Thresholds
  SECURITY: {
    MAX_HTML_BODY_BYTES: 2 * 1024 * 1024, // 2MB max raw HTML
    MAX_MARKDOWN_CHARS: 150000, // 150k characters max markdown (~35k tokens)
    MAX_REDIRECTS: 3,
    MAX_CLOCK_SKEW_MS: 300000, // 5 minutes signature validity window
    ALLOWED_PORTS: [80, 443],
  },

  CACHE_TTL_SECONDS: 3600, // 1 hour edge cache
  NONCE_TTL_SECONDS: 86400, // 24 hours replay protection
  EXECUTION_TIMEOUT_MS: 15000, // 15s strict latency budget
};
