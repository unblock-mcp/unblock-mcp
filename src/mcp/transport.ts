/**
 * Transport Layer: Handles SSE (Server-Sent Events) and Stateless JSON-RPC
 */

import { JsonRpcResponse } from "./server";

export function formatSseEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

export function createSseResponse(data: JsonRpcResponse, customHeaders: Record<string, string> = {}): Response {
  const body = formatSseEvent("message", data);
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*",
      ...customHeaders,
    },
  });
}

export function createJsonResponse(
  data: JsonRpcResponse,
  status = 200,
  customHeaders: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      ...customHeaders,
    },
  });
}
