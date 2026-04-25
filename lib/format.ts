import type { FlagCategory } from "@/lib/types";

const TITLE_OVERRIDES: Record<string, string> = {
  CVE: "CVE",
  SQL: "SQL",
  XSS: "XSS",
  CSRF: "CSRF",
  SSRF: "SSRF",
  XXE: "XXE",
  IDOR: "IDOR",
  BOLA: "BOLA",
  JWT: "JWT",
  MD5: "MD5",
  AES: "AES",
  CBC: "CBC",
  AI: "AI",
  MCP: "MCP",
  API: "API",
  ENV: "ENV",
};

export function formatSlug(slug: string): string {
  return slug
    .split("-")
    .map((word) => {
      const upper = word.toUpperCase();
      if (TITLE_OVERRIDES[upper]) return TITLE_OVERRIDES[upper];
      return word.charAt(0).toUpperCase() + word.slice(1);
    })
    .join(" ");
}

export const CATEGORY_LABELS: Record<FlagCategory, string> = {
  INJECTION: "Injection",
  AUTHENTICATION: "Authentication",
  AUTHORIZATION: "Authorization",
  REQUEST_FORGERY: "Request Forgery",
  INFORMATION_DISCLOSURE: "Information Disclosure",
  INPUT_VALIDATION: "Input Validation",
  CRYPTOGRAPHIC: "Cryptographic",
  REMOTE_CODE_EXECUTION: "Remote Code Execution",
  OTHER: "Other",
};
