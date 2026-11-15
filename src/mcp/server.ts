/**
 * MCP JSON-RPC 2.0 Protocol Engine
 */

import crypto from "node:crypto";
import { Env } from "../config";
import { MCP_TOOLS, SERVER_INFO } from "./schema";
import { extractPaymentSignature, createX402Challenge } from "../payment/x402";
import { verifyAndSettlePayment } from "../payment/verifier";
import { executeScrape } from "../scraper/engine";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id?: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export async function handleJsonRpc(
  request: Request,
  rpcReq: JsonRpcRequest,
  env: Env
): Promise<{ response: JsonRpcResponse; status: number; headers?: Record<string, string> }> {
  const reqId = rpcReq.id ?? null;

  // 1. Handshake: initialize
  if (rpcReq.method === "initialize") {
    return {
      status: 200,
      response: {
        jsonrpc: "2.0",
        id: reqId,
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: SERVER_INFO,
          capabilities: SERVER_INFO.capabilities,
        },
      },
    };
  }

  // 2. Handshake: notifications/initialized
  if (rpcReq.method === "notifications/initialized") {
    return {
      status: 200,
      response: { jsonrpc: "2.0", id: reqId, result: { status: "ready" } },
    };
  }

  // 3. Discovery: tools/list
  if (rpcReq.method === "tools/list") {
    return {
      status: 200,
      response: {
        jsonrpc: "2.0",
        id: reqId,
        result: {
          tools: MCP_TOOLS,
        },
      },
    };
  }

  // 4. Invocation: tools/call
  if (rpcReq.method === "tools/call") {
    const params = rpcReq.params || {};
    const toolName = params.name as string;
    const toolArgs = (params.arguments as Record<string, unknown>) || {};

    if (toolName !== "fetch_clean_markdown") {
      return {
        status: 400,
        response: {
          jsonrpc: "2.0",
          id: reqId,
          error: { code: -32601, message: `Tool not found: '${toolName}'` },
        },
      };
    }

    const targetUrl = toolArgs.url as string;
    if (!targetUrl || typeof targetUrl !== "string") {
      return {
        status: 400,
        response: {
          jsonrpc: "2.0",
          id: reqId,
          error: { code: -32602, message: "Missing required string argument: 'url'" },
        },
      };
    }

    // --- x402 PAYMENT CHECK ---
    const sig = extractPaymentSignature(request, rpcReq as unknown as Record<string, unknown>);
    const nonce = (request.headers.get("x402-nonce") || crypto.randomUUID()).trim();

    if (!sig) {
      // Trigger HTTP 402 Challenge
      const challenge = createX402Challenge(env, nonce);
      return {
        status: 402,
        headers: challenge.headers,
        response: {
          jsonrpc: "2.0",
          id: reqId,
          error: {
            code: 402,
            message: "Payment Required: Call requires 0.005 USDC on Base.",
            data: challenge.body,
          },
        },
      };
    }

    // Verify payment signature
    const settlement = await verifyAndSettlePayment(sig, nonce, env);
    if (!settlement.valid) {
      return {
        status: 403,
        response: {
          jsonrpc: "2.0",
          id: reqId,
          error: { code: 403, message: `Payment verification failed: ${settlement.error}` },
        },
      };
    }

    // --- EXECUTE TOOL ACTION ---
    const scrapeRes = await executeScrape(targetUrl, env);

    if (!scrapeRes.success) {
      return {
        status: 200,
        response: {
          jsonrpc: "2.0",
          id: reqId,
          result: {
            isError: true,
            content: [{ type: "text", text: `Scraping failed: ${scrapeRes.error}` }],
          },
        },
      };
    }

    return {
      status: 200,
      headers: {
        "PAYMENT-RESPONSE": JSON.stringify({
          status: "settled",
          txHash: settlement.txHash,
          cached: scrapeRes.cached,
        }),
      },
      response: {
        jsonrpc: "2.0",
        id: reqId,
        result: {
          content: [
            {
              type: "text",
              text: scrapeRes.markdown,
            },
          ],
        },
      },
    };
  }

  // Method not recognized
  return {
    status: 404,
    response: {
      jsonrpc: "2.0",
      id: reqId,
      error: { code: -32601, message: `Method '${rpcReq.method}' not implemented.` },
    },
  };
}
