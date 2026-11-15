/**
 * Autonomous Agent Client Simulation Demo
 * Demonstrates the full x402 payment handshake loop over MCP
 */

async function simulateAgent() {
  const SERVER_URL = "http://localhost:8787/mcp"; // Or live deployed worker URL
  const TARGET_URL = "https://news.ycombinator.com";

  console.log(`🤖 [Agent]: Attempting to scrape '${TARGET_URL}' via MCP Tool...`);

  // 1. First attempt: call tools/call WITHOUT payment
  const unpaidPayload = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "fetch_clean_markdown",
      arguments: { url: TARGET_URL },
    },
  };

  console.log("🤖 [Agent]: Sending request without payment headers...");
  let res = await fetch(SERVER_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(unpaidPayload),
  });

  console.log(`📡 [Server Response]: HTTP Status ${res.status} (${res.statusText})`);

  if (res.status === 402) {
    console.log("💡 [Agent]: Received HTTP 402 Challenge!");
    const price = res.headers.get("X402-Price");
    const currency = res.headers.get("X402-Currency");
    const network = res.headers.get("X402-Network");
    const recipient = res.headers.get("X402-Recipient");
    const nonce = res.headers.get("X402-Nonce");

    console.log(`   Price: ${price} ${currency} on ${network}`);
    console.log(`   Recipient: ${recipient}`);
    console.log(`   Challenge Nonce: ${nonce}`);

    // 2. Autonomous Agent signs payment with its local agent-wallet
    console.log("\n🔑 [Agent Wallet]: Signing micro-payment EIP-712 authorization...");
    const simulatedSignature = "0x" + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join("");

    // 3. Second attempt: retry with PAYMENT-SIGNATURE
    console.log("🤖 [Agent]: Retrying request with signed payment proof...");
    res = await fetch(SERVER_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "PAYMENT-SIGNATURE": simulatedSignature,
        "x402-nonce": nonce || "random-nonce",
      },
      body: JSON.stringify({
        ...unpaidPayload,
        id: 2,
      }),
    });

    console.log(`📡 [Server Response]: HTTP Status ${res.status}`);
    const settlement = res.headers.get("PAYMENT-RESPONSE");
    console.log(`💳 [Settlement Header]: ${settlement}`);

    const resultJson = await res.json() as any;
    console.log("\n📄 [Extracted Markdown Preview]:");
    const markdown = resultJson.result?.content?.[0]?.text || "No content";
    console.log(markdown.slice(0, 300) + "\n...[truncated]");
  }
}

// Export for runner
export { simulateAgent };

if (import.meta.url === `file://${process.argv[1]}`) {
  simulateAgent().catch(console.error);
}
