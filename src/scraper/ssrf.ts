/**
 * Hardened SSRF (Server-Side Request Forgery) Guard
 * Blocks private IP ranges, alternative representations (hex/octal/decimal),
 * internal TLDs, non-standard ports, and loopback vectors.
 */

import { PROTOCOL_CONFIG } from "../config";

const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/, // 127.0.0.0/8
  /^10\.\d+\.\d+\.\d+$/, // 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/, // 172.16.0.0/12
  /^192\.168\.\d+\.\d+$/, // 192.168.0.0/16
  /^169\.254\.\d+\.\d+$/, // 169.254.0.0/16 (AWS / GCP metadata)
  /^0\.0\.0\.0$/,
  /^::1$/, // IPv6 loopback
  /^fc00:/i, // IPv6 Unique Local
  /^fe80:/i, // IPv6 Link-Local
  /^::ffff:/i, // IPv4-mapped IPv6
  /^0x[0-9a-f]+$/i, // Hex IP representation (e.g. 0x7f000001)
  /^\d{8,11}$/, // Decimal IP representation (e.g. 2130706433)
  /^0\d+\.\d+\.\d+\.\d+$/, // Octal IP representation
];

const BLOCKED_INTERNAL_TLDS = [
  /\.local$/i,
  /\.internal$/i,
  /\.lan$/i,
  /\.corp$/i,
  /\.home$/i,
  /\.arpa$/i,
  /\.test$/i,
  /\.invalid$/i,
  // Block common DNS rebinding & wildcard resolution services
  /\.nip\.io$/i,
  /\.sslip\.io$/i,
  /\.traefik\.me$/i,
];

export function validateSafeUrl(rawUrl: string): { valid: boolean; error?: string; url?: URL } {
  try {
    const parsed = new URL(rawUrl);

    // 1. Strict protocol validation
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { valid: false, error: `Disallowed protocol: '${parsed.protocol}'. Only http and https are permitted.` };
    }

    // 2. Strict port validation
    const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === "https:" ? 443 : 80;
    if (!PROTOCOL_CONFIG.SECURITY.ALLOWED_PORTS.includes(port)) {
      return {
        valid: false,
        error: `Disallowed port: ${port}. Scraper is restricted to standard web ports (80, 443) for security.`,
      };
    }

    const hostname = parsed.hostname.toLowerCase();

    // 3. Block private & metadata patterns
    for (const pattern of BLOCKED_HOST_PATTERNS) {
      if (pattern.test(hostname)) {
        return { valid: false, error: `Access to internal/private network destination (${hostname}) is blocked.` };
      }
    }

    // 4. Block internal TLDs
    for (const tldPattern of BLOCKED_INTERNAL_TLDS) {
      if (tldPattern.test(hostname)) {
        return { valid: false, error: `Access to internal TLD (${hostname}) is blocked.` };
      }
    }

    // 5. Userinfo check (e.g. http://user:pass@host/)
    if (parsed.username || parsed.password) {
      return { valid: false, error: "Credentials in URL are not allowed." };
    }

    return { valid: true, url: parsed };
  } catch {
    return { valid: false, error: "Malformed or invalid URL string." };
  }
}
