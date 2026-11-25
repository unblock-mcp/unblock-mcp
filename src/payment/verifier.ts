/**
 * Payment Verifier and Anti-Replay Engine
 * Real EIP-712 Cryptographic Verification via viem
 */

import crypto from "node:crypto";
import { verifyTypedData, isAddress, getAddress, type Hex } from "viem";
import { Env, PROTOCOL_CONFIG } from "../config";

export interface X402Authorization {
  recipient: string;
  amount: string;
  currency: string;
  nonce: string;
  expiresAt: number | string;
}

export interface X402PaymentPayload {
  network?: string;
  signer: string;
  signature: string;
  authorization: X402Authorization;
}

export const X402_EIP712_DOMAIN = (chainId: number, verifyingContract: `0x${string}`) => ({
  name: "x402 Micropayment Protocol",
  version: "1",
  chainId,
  verifyingContract,
} as const);

export const X402_EIP712_TYPES = {
  PaymentAuthorization: [
    { name: "recipient", type: "address" },
    { name: "amount", type: "string" },
    { name: "currency", type: "string" },
    { name: "nonce", type: "string" },
    { name: "expiresAt", type: "uint256" },
  ],
} as const;

export interface VerificationResult {
  valid: boolean;
  signer?: string;
  error?: string;
  txHash?: string;
}

// Global in-memory isolate lock to prevent concurrent race condition replay attacks
const activeNonceLocks = new Set<string>();

export async function verifyAndSettlePayment(
  signatureOrPayload: string,
  nonce: string,
  env: Env
): Promise<VerificationResult> {
  // 1. In-memory concurrency gate (defeats sub-millisecond parallel replay race conditions)
  if (activeNonceLocks.has(nonce)) {
    return { valid: false, error: "Payment nonce is currently locked in-flight or already redeemed (replay attack rejected)." };
  }
  activeNonceLocks.add(nonce);
  let committed = false;

  try {
    // 2. Fail-closed check for unconfigured recipient outside test mode
    const isLocalTestMode = env.ENVIRONMENT === "test" && env.ALLOW_MOCK_PAYMENT === "true";
    if (!isLocalTestMode && (!env.PAYMENT_RECIPIENT_EVM || /^0x0+$/.test(env.PAYMENT_RECIPIENT_EVM))) {
      return {
        valid: false,
        error: "Server payment recipient is not configured (fail-closed hold mode).",
      };
    }

    // 3. Persistent Replay Protection: Check if this nonce was already redeemed in Edge KV
    const nonceKey = `nonce:${nonce}`;
    try {
      const existing = await env.NONCE_KV.get(nonceKey);
      if (existing) {
        return { valid: false, error: "Payment nonce has already been redeemed (replay attack rejected)." };
      }
    } catch (err) {
      console.warn("Nonce KV read error:", err);
    }

    // 4. Format validation (Strictly requires structured EIP-712 JSON payload)
    if (!signatureOrPayload || signatureOrPayload.length < 10) {
      return { valid: false, error: "Invalid or empty payment signature payload." };
    }

    let payload: X402PaymentPayload | null = null;
    if (signatureOrPayload.startsWith("{")) {
      try {
        payload = JSON.parse(signatureOrPayload) as X402PaymentPayload;
      } catch {
        return { valid: false, error: "Malformed JSON in payment payload." };
      }
    }

    if (!payload) {
      return {
        valid: false,
        error: "Unsupported signature format. Complete EIP-712 JSON authorization payload is required.",
      };
    }

    // 5. Validate authorization parameters
    const auth = payload.authorization;
    if (!auth) {
      return { valid: false, error: "Missing 'authorization' structure in payment payload." };
    }

    if (auth.nonce !== nonce) {
      return {
        valid: false,
        error: `Nonce mismatch: authorization nonce '${auth.nonce}' does not match challenge nonce '${nonce}'.`,
      };
    }

    const expiresAtMs = Number(auth.expiresAt);
    const now = Date.now();
    if (isNaN(expiresAtMs) || expiresAtMs < now) {
      return { valid: false, error: "Payment authorization has expired." };
    }

    if (expiresAtMs > now + PROTOCOL_CONFIG.SECURITY.MAX_CLOCK_SKEW_MS * 2) {
      return { valid: false, error: "Payment authorization expiresAt timestamp is suspiciously far in the future." };
    }

    if (auth.recipient.toLowerCase() !== env.PAYMENT_RECIPIENT_EVM.toLowerCase()) {
      return {
        valid: false,
        error: `Invalid recipient address: expected ${env.PAYMENT_RECIPIENT_EVM}, received ${auth.recipient}`,
      };
    }

    const paidAmount = parseFloat(auth.amount);
    const requiredAmount = parseFloat(env.PAYMENT_AMOUNT_USDC || PROTOCOL_CONFIG.DEFAULT_PRICE_USDC);
    if (isNaN(paidAmount) || paidAmount < requiredAmount) {
      return {
        valid: false,
        error: `Insufficient payment amount: received ${auth.amount}, required ${requiredAmount} USDC.`,
      };
    }

    if (!isAddress(payload.signer)) {
      return { valid: false, error: "Invalid signer EVM address format." };
    }

    if (!payload.signature || !payload.signature.startsWith("0x")) {
      return { valid: false, error: "Invalid signature format: expected 0x-prefixed hex string." };
    }

    // 6. Resolve Target EVM Network
    const networkKey = (payload.network || "base").toLowerCase();
    const networkConfig = PROTOCOL_CONFIG.NETWORKS[networkKey as keyof typeof PROTOCOL_CONFIG.NETWORKS];
    if (!networkConfig || networkConfig.type !== "evm") {
      return { valid: false, error: `Unsupported or non-EVM network: '${payload.network}'.` };
    }

    // 7. Cryptographic EIP-712 Signature Verification via viem
    try {
      const domain = X402_EIP712_DOMAIN(networkConfig.chainId, networkConfig.usdcContract as `0x${string}`);

      const isValidSig = await verifyTypedData({
        address: getAddress(payload.signer),
        domain,
        types: X402_EIP712_TYPES,
        primaryType: "PaymentAuthorization",
        message: {
          recipient: getAddress(auth.recipient),
          amount: String(auth.amount),
          currency: String(auth.currency),
          nonce: String(auth.nonce),
          expiresAt: BigInt(auth.expiresAt),
        },
        signature: payload.signature as Hex,
      });

      if (!isValidSig) {
        return {
          valid: false,
          error: "Cryptographic EIP-712 signature verification failed. Signature does not match signer and message.",
        };
      }
    } catch (verifyErr) {
      return {
        valid: false,
        error: `Cryptographic verification error: ${verifyErr instanceof Error ? verifyErr.message : String(verifyErr)}`,
      };
    }

    // 8. On-Chain Settlement via Facilitator (Fail-closed outside sandbox)
    let settledTxHash: string | undefined;
    if (env.COINBASE_CDP_API_KEY) {
      try {
        const settleRes = await fetch("https://api.cdp.coinbase.com/platform/v2/x402/settle", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${env.COINBASE_CDP_API_KEY}`,
          },
          body: JSON.stringify({
            network: networkKey,
            payload,
          }),
          signal: AbortSignal.timeout(10000),
        });
        if (settleRes.ok) {
          const settleData = (await settleRes.json()) as { txHash?: string };
          settledTxHash = settleData.txHash;
        } else {
          return {
            valid: false,
            error: `Facilitator settlement rejected (HTTP ${settleRes.status}).`,
          };
        }
      } catch (settleErr) {
        return {
          valid: false,
          error: `Facilitator settlement request failed: ${settleErr instanceof Error ? settleErr.message : String(settleErr)}`,
        };
      }
    } else if (!isLocalTestMode) {
      // Fail-closed: prevents empty-wallet EIP-712 signatures from bypassing billing when no facilitator is configured
      return {
        valid: false,
        error: "On-chain payment settlement facilitator is not configured (fail-closed).",
      };
    }

    const txHash =
      settledTxHash ||
      `0x${crypto.createHash("sha256").update(payload.signature + nonce).digest("hex")}`;

    // 9. Commit Nonce to KV (Anti-replay protection with 24h TTL)
    await commitNonce(env, nonceKey, payload.signer, auth.amount, networkKey, txHash);
    committed = true;

    return {
      valid: true,
      signer: payload.signer,
      txHash,
    };
  } finally {
    if (!committed) {
      activeNonceLocks.delete(nonce);
    }
  }
}

async function commitNonce(
  env: Env,
  nonceKey: string,
  signer: string,
  amount: string,
  network: string,
  txHash: string
): Promise<void> {
  try {
    await env.NONCE_KV.put(
      nonceKey,
      JSON.stringify({
        redeemedAt: Date.now(),
        signer,
        amount,
        network,
        txHash,
      }),
      { expirationTtl: PROTOCOL_CONFIG.NONCE_TTL_SECONDS }
    );
    // Keep in-memory lock active for 10 minutes to protect against cross-datacenter sync delays
    setTimeout(() => activeNonceLocks.delete(nonceKey.replace("nonce:", "")), 600_000);
  } catch (err) {
    console.error("Failed to commit consumed nonce to KV:", err);
  }
}
