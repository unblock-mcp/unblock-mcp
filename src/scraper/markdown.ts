/**
 * Hardened HTML-to-Markdown & Agent Safety Sanitizer
 * Protects consuming LLMs from Indirect Prompt Injection & DoS payloads.
 */

import { PROTOCOL_CONFIG } from "../config";

export function htmlToCleanMarkdown(html: string, sourceUrl: string): string {
  let content = html;

  // 1. Remove HTML comments
  content = content.replace(/<!--[\s\S]*?-->/g, "");

  // 1b. Remove executable, noisy and structural block tags in linear time (ReDoS-immune, no backreferences)
  const STRIP_BLOCK_TAGS = [
    "script",
    "style",
    "noscript",
    "svg",
    "nav",
    "footer",
    "header",
    "aside",
    "iframe",
    "object",
    "embed",
  ];
  for (const tag of STRIP_BLOCK_TAGS) {
    const blockRegex = new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}>`, "gi");
    content = content.replace(blockRegex, "");
    // Also remove unclosed opening tags
    const openTagRegex = new RegExp(`<${tag}\\b[^>]*>`, "gi");
    content = content.replace(openTagRegex, "");
  }

  // 2. Extract Document Title
  const titleMatch = content.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : sourceUrl;

  // 3. Convert Headings
  content = content.replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, "\n\n# $1\n\n");
  content = content.replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, "\n\n## $1\n\n");
  content = content.replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, "\n\n### $1\n\n");
  content = content.replace(/<h[4-6][^>]*>([\s\S]*?)<\/h[4-6]>/gi, "\n\n#### $1\n\n");

  // 4. Convert Code Blocks & Inline Code
  content = content.replace(/<pre[^>]*><code[^>]*>([\s\S]*?)<\/code><\/pre>/gi, "\n```\n$1\n```\n");
  content = content.replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, "`$1`");

  // 5. Convert Links and Images
  content = content.replace(/<a[^>]*href=["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi, "[$2]($1)");
  content = content.replace(/<img[^>]*alt=["']([^"']*)["'][^>]*>/gi, "![$1]");

  // 6. Convert Lists
  content = content.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, "* $1\n");
  content = content.replace(/<\/?(ul|ol)[^>]*>/gi, "\n");

  // 7. Convert Paragraphs, Blockquotes, and Line Breaks
  content = content.replace(/<blockquote[^>]*>([\s\S]*?)<\/blockquote>/gi, "\n> $1\n");
  content = content.replace(/<p[^>]*>([\s\S]*?)<\/p>/gi, "\n\n$1\n\n");
  content = content.replace(/<br\s*\/?>/gi, "\n");

  // 8. Strip all remaining HTML tags
  content = content.replace(/<[^>]+>/g, "");

  // 9. Decode basic HTML entities
  content = content
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");

  // 10. Clean up duplicate newlines and whitespace
  let cleaned = content
    .split("\n")
    .map((line) => line.trim())
    .filter((line, idx, arr) => line.length > 0 || (idx > 0 && arr[idx - 1].length > 0))
    .join("\n");

  // --- 🛡️ AGENT SAFETY: INDIRECT PROMPT INJECTION MITIGATION ---
  // Neutralize common LLM prompt hijack delimiters if present in external webpage
  cleaned = cleaned
    .replace(/<\|im_start\|>/gi, "[filtered_token]")
    .replace(/<\|im_end\|>/gi, "[filtered_token]")
    .replace(/<<SYS>>/gi, "[filtered_sys]")
    .replace(/<\/SYS>/gi, "[filtered_sys]")
    .replace(/\[SYSTEM_PROMPT\]/gi, "[filtered_prompt]")
    .replace(/\[INSTRUCTION\]/gi, "[filtered_instruction]")
    .replace(/<\/?untrusted_scraped_content[^>]*>/gi, "[filtered_delimiter]");

  // 11. Enforce Max Output Length (DoS prevention)
  if (cleaned.length > PROTOCOL_CONFIG.SECURITY.MAX_MARKDOWN_CHARS) {
    cleaned =
      cleaned.slice(0, PROTOCOL_CONFIG.SECURITY.MAX_MARKDOWN_CHARS) +
      "\n\n[...Content truncated by unblock-mcp due to safety length limits...]";
  }

  // Sanitize title to prevent XML attribute injection
  const safeTitle = title.replace(/["<>\r\n]/g, " ");

  // 12. Wrap in explicit untrusted data boundary for caller LLM
  return `<untrusted_scraped_content source="${sourceUrl}" title="${safeTitle}">\n${cleaned}\n</untrusted_scraped_content>`;
}
