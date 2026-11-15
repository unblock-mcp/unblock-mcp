/**
 * Multi-Chain HTTP 402 Payment Required Protocol Middleware
 * Supports Base, Polygon, BSC, Arbitrum, and Solana
 */

import { Env, PROTOCOL_CONFIG } from "../config";

export interface PaymentChallenge {
  status: 402;
  headers: Record<string, string>;
  body: object;
}

export function createX402Challenge(env: Env, nonce: string): PaymentChallenge {
  const evmRecipient = env.PAYMENT_RECIPIENT_EVM || "0x0000000000000000000000000000000000000000";
  const solanaRecipient = env.PAYMENT_RECIPIENT_SOLANA || "";
  const amount = env.PAYMENT_AMOUNT_USDC || PROTOCOL_CONFIG.DEFAULT_PRICE_USDC;

  const acceptedNetworks: Array<Record<string, unknown>> = [
    {
      network: "base",
      type: "evm",
      chainId: PROTOCOL_CONFIG.NETWORKS.base.chainId,
      tokenContract: PROTOCOL_CONFIG.NETWORKS.base.usdcContract,
      recipient: evmRecipient,
      amount: amount,
    },
    {
      network: "polygon",
      type: "evm",
      chainId: PROTOCOL_CONFIG.NETWORKS.polygon.chainId,
      tokenContract: PROTOCOL_CONFIG.NETWORKS.polygon.usdcContract,
      recipient: evmRecipient,
      amount: amount,
    },
    {
      network: "bsc",
      type: "evm",
      chainId: PROTOCOL_CONFIG.NETWORKS.bsc.chainId,
      tokenContract: PROTOCOL_CONFIG.NETWORKS.bsc.usdcContract,
      recipient: evmRecipient,
      amount: amount,
    },
    {
      network: "arbitrum",
      type: "evm",
      chainId: PROTOCOL_CONFIG.NETWORKS.arbitrum.chainId,
      tokenContract: PROTOCOL_CONFIG.NETWORKS.arbitrum.usdcContract,
      recipient: evmRecipient,
      amount: amount,
    },
  ];

  if (solanaRecipient) {
    acceptedNetworks.push({
      network: "solana",
      type: "solana",
      usdcMint: PROTOCOL_CONFIG.NETWORKS.solana.usdcMint,
      recipient: solanaRecipient,
      amount: amount,
    });
  }

  const challengeData = {
    error: "Payment Required",
    protocol: "x402",
    version: PROTOCOL_CONFIG.VERSION,
    accepted_networks: acceptedNetworks,
    payment_details: {
      default_network: "base",
      amount: amount,
      currency: PROTOCOL_CONFIG.TOKEN_NAME,
      nonce: nonce,
      expiresAt: Date.now() + PROTOCOL_CONFIG.SECURITY.MAX_CLOCK_SKEW_MS,
    },
    instructions:
      "Select an accepted network (e.g. Base, Polygon, BSC, Solana), sign the authorization payload, and attach it to the 'PAYMENT-SIGNATURE' header.",
  };

  return {
    status: 402,
    headers: {
      "Content-Type": "application/json",
      "PAYMENT-REQUIRED": JSON.stringify(challengeData.payment_details),
      "X402-Networks": acceptedNetworks.map((n) => n.network).join(", "),
      "X402-Price": amount,
      "X402-Currency": PROTOCOL_CONFIG.TOKEN_NAME,
      "X402-Recipient-EVM": evmRecipient,
      "X402-Nonce": nonce,
    },
    body: challengeData,
  };
}

export function extractPaymentSignature(request: Request, bodyJson?: Record<string, unknown>): string | null {
  // 1. Check HTTP Header
  const headerSig = request.headers.get("PAYMENT-SIGNATURE") || request.headers.get("x-payment-signature");
  if (headerSig) return headerSig.trim();

  // 2. Check MCP _meta JSON payload
  if (bodyJson && typeof bodyJson === "object" && bodyJson._meta) {
    const meta = bodyJson._meta as Record<string, unknown>;
    if (meta["x402/payment"] && typeof meta["x402/payment"] === "string") {
      return meta["x402/payment"].trim();
    }
  }

  return null;
}
