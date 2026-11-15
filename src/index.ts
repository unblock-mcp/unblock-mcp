/**
 * Cloudflare Worker Entrypoint
 * Autonomous x402 Micropayment MCP Server
 */

import { Env } from "./config";
import { handleJsonRpc, JsonRpcRequest } from "./mcp/server";
import { createJsonResponse, createSseResponse } from "./mcp/transport";
import { MCP_TOOLS, SERVER_INFO } from "./mcp/schema";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // 1. CORS Preflight Handling
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, PAYMENT-SIGNATURE, x402-nonce, Accept",
          "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X402-Price, X402-Nonce",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // 2. Health check
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "healthy", timestamp: Date.now() }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 3. Machine Protocol Manifest: /.well-known/mcp.json
    if (url.pathname === "/.well-known/mcp.json") {
      return new Response(
        JSON.stringify({
          schema_version: "v1",
          server: SERVER_INFO,
          transport: {
            type: "http-post",
            endpoint: `${url.origin}/mcp`,
            sse_endpoint: `${url.origin}/mcp/sse`,
          },
          tools: MCP_TOOLS,
          monetization: {
            protocol: "x402",
            currency: "USDC",
            networks: ["base", "polygon", "bsc", "arbitrum", "solana"],
            price_per_call: env.PAYMENT_AMOUNT_USDC || "0.005",
            recipient_evm: env.PAYMENT_RECIPIENT_EVM,
            recipient_solana: env.PAYMENT_RECIPIENT_SOLANA || null,
          },
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=3600",
          },
        }
      );
    }

    // 4. SSE Stream endpoint: GET /mcp or GET /mcp/sse
    if (request.method === "GET" && (url.pathname === "/mcp" || url.pathname === "/mcp/sse")) {
      return new Response(
        `event: endpoint\ndata: ${JSON.stringify({ endpoint: `${url.origin}/mcp` })}\n\n`,
        {
          status: 200,
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    // 5. MCP JSON-RPC Handler: POST /mcp or POST /
    if (request.method === "POST" && (url.pathname === "/mcp" || url.pathname === "/")) {
      try {
        const body = (await request.json()) as JsonRpcRequest;
        const wantsSse = request.headers.get("Accept")?.includes("text/event-stream");

        const { response, status, headers } = await handleJsonRpc(request, body, env);

        if (wantsSse) {
          return createSseResponse(response, headers);
        }

        return createJsonResponse(response, status, headers);
      } catch (err) {
        return createJsonResponse(
          {
            jsonrpc: "2.0",
            error: { code: -32700, message: `Parse error / Invalid JSON: ${String(err)}` },
          },
          400
        );
      }
    }

    // 404 Fallback
    return new Response(JSON.stringify({ error: "Not Found", message: "Use POST /mcp for MCP JSON-RPC 2.0" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  },
};
