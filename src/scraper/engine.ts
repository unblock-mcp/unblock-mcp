/**
 * Multi-Tier Scraping & Anti-Bot Bypass Engine
 * Hardened with SSRF redirect tracking, body size limits, and 15s latency budget.
 */

import { Env, PROTOCOL_CONFIG } from "../config";
import { validateSafeUrl } from "./ssrf";
import { htmlToCleanMarkdown } from "./markdown";

export interface ScrapeResult {
  success: boolean;
  markdown?: string;
  cached?: boolean;
  error?: string;
  statusCode?: number;
}

export async function executeScrape(targetUrl: string, env: Env): Promise<ScrapeResult> {
  // 1. Initial SSRF Safety Check
  const urlCheck = validateSafeUrl(targetUrl);
  if (!urlCheck.valid || !urlCheck.url) {
    return { success: false, error: urlCheck.error || "Invalid URL" };
  }

  let currentUrl = urlCheck.url.toString();
  const cacheKey = `url_cache:${currentUrl}`;

  // 2. Check Edge KV Cache
  try {
    const cachedMarkdown = await env.CACHE_KV.get(cacheKey);
    if (cachedMarkdown) {
      return { success: true, markdown: cachedMarkdown, cached: true };
    }
  } catch (err) {
    console.warn("KV cache read error (continuing without cache):", err);
  }

  // 3. Execution with Strict Latency Budget (15s)
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), PROTOCOL_CONFIG.EXECUTION_TIMEOUT_MS);

  try {
    let redirectCount = 0;
    let response: Response;

    while (true) {
      response = await fetch(currentUrl, {
        method: "GET",
        signal: controller.signal,
        redirect: "manual", // Manually track redirects to prevent SSRF bypass
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
          "Sec-Ch-Ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
          "Sec-Ch-Ua-Mobile": "?0",
          "Sec-Ch-Ua-Platform": '"macOS"',
          "Sec-Fetch-Dest": "document",
          "Sec-Fetch-Mode": "navigate",
          "Sec-Fetch-Site": "none",
          "Sec-Fetch-User": "?1",
        },
      });

      // Handle Redirects safely
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        redirectCount++;
        if (redirectCount > PROTOCOL_CONFIG.SECURITY.MAX_REDIRECTS) {
          clearTimeout(timeoutId);
          return { success: false, error: "Too many redirects (exceeded safety limit of 3 hops)." };
        }

        const location = response.headers.get("location");
        if (!location) {
          clearTimeout(timeoutId);
          return { success: false, error: "Redirect response missing 'Location' header." };
        }

        // Resolve relative redirects
        const nextUrl = new URL(location, currentUrl).toString();
        const redirectCheck = validateSafeUrl(nextUrl);
        if (!redirectCheck.valid || !redirectCheck.url) {
          clearTimeout(timeoutId);
          return { success: false, error: `Blocked unsafe redirect destination: ${redirectCheck.error}` };
        }

        currentUrl = redirectCheck.url.toString();
        continue;
      }

      break;
    }

    clearTimeout(timeoutId);

    // If successfully returned HTML
    if (response.ok) {
      // Stream with size guard (Max 2MB)
      const rawText = await response.text();
      if (rawText.length > PROTOCOL_CONFIG.SECURITY.MAX_HTML_BODY_BYTES) {
        return {
          success: false,
          error: `Payload too large: page exceeds ${PROTOCOL_CONFIG.SECURITY.MAX_HTML_BODY_BYTES / (1024 * 1024)}MB limit.`,
        };
      }

      const markdown = htmlToCleanMarkdown(rawText, currentUrl);

      // Save to Edge Cache
      try {
        await env.CACHE_KV.put(cacheKey, markdown, { expirationTtl: PROTOCOL_CONFIG.CACHE_TTL_SECONDS });
      } catch (err) {
        console.warn("KV write failed:", err);
      }

      return { success: true, markdown, cached: false, statusCode: response.status };
    }

    // If blocked by Anti-Bot / Cloudflare (403, 503)
    if (response.status === 403 || response.status === 503) {
      if (env.UPSTREAM_STEALTH_GATEWAY && env.UPSTREAM_API_KEY) {
        const proxyUrl = new URL(env.UPSTREAM_STEALTH_GATEWAY);
        proxyUrl.searchParams.set("url", currentUrl);
        proxyUrl.searchParams.set("render_js", "false");
        proxyUrl.searchParams.set("stealth_proxy", "true");

        // Pass API key strictly in HTTP headers to prevent credential leakage in URL query logs
        const proxyResp = await fetch(proxyUrl.toString(), {
          headers: {
            Authorization: `Bearer ${env.UPSTREAM_API_KEY}`,
            "X-API-Key": env.UPSTREAM_API_KEY,
            "Spb-Key": env.UPSTREAM_API_KEY,
          },
          signal: AbortSignal.timeout(10000),
        });
        if (proxyResp.ok) {
          const proxyHtml = await proxyResp.text();
          const markdown = htmlToCleanMarkdown(proxyHtml, currentUrl);
          await env.CACHE_KV.put(cacheKey, markdown, { expirationTtl: PROTOCOL_CONFIG.CACHE_TTL_SECONDS });
          return { success: true, markdown, cached: false, statusCode: 200 };
        }
      }

      return {
        success: false,
        statusCode: response.status,
        error: `Target website blocked request with anti-bot protection (HTTP ${response.status}). Stealth proxy recommended.`,
      };
    }

    return {
      success: false,
      statusCode: response.status,
      error: `Upstream HTTP error: ${response.status} ${response.statusText}`,
    };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const errorMsg = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      error: errorMsg.includes("abort")
        ? `Execution exceeded strict latency timeout (${PROTOCOL_CONFIG.EXECUTION_TIMEOUT_MS}ms)`
        : `Network fetch failed: ${errorMsg}`,
    };
  }
}
