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
  INSECURE_DESIGN: "Insecure Design",
  SUPPLY_CHAIN: "Supply Chain",
  OTHER: "Other",
};

const OWASP_2021_SLUGS: Record<string, string> = {
  A01: "A01_2021-Broken_Access_Control",
  A02: "A02_2021-Cryptographic_Failures",
  A03: "A03_2021-Injection",
  A04: "A04_2021-Insecure_Design",
  A05: "A05_2021-Security_Misconfiguration",
  A06: "A06_2021-Vulnerable_and_Outdated_Components",
  A07: "A07_2021-Identification_and_Authentication_Failures",
  A08: "A08_2021-Software_and_Data_Integrity_Failures",
  A09: "A09_2021-Security_Logging_and_Monitoring_Failures",
  A10: "A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
};

const OWASP_2025_SLUGS: Record<string, string> = {
  A01: "A01_2025-Broken_Access_Control",
  A02: "A02_2025-Security_Misconfiguration",
  A03: "A03_2025-Software_Supply_Chain_Failures",
  A04: "A04_2025-Cryptographic_Failures",
  A05: "A05_2025-Injection",
  A06: "A06_2025-Insecure_Design",
  A07: "A07_2025-Authentication_Failures",
  A08: "A08_2025-Software_or_Data_Integrity_Failures",
  A09: "A09_2025-Security_Logging_and_Alerting_Failures",
  A10: "A10_2025-Mishandling_of_Exceptional_Conditions",
};

export function getCveUrl(cve: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
}

export function getCweUrl(cwe: string): string | null {
  const match = cwe.match(/^CWE-(\d+)$/i);
  if (!match) return null;
  return `https://cwe.mitre.org/data/definitions/${match[1]}.html`;
}

export function getOwaspUrl(owasp: string): string | null {
  const match = owasp.match(/^(A\d{2}):(2021|2025)$/);
  if (!match) return null;
  const [, code, year] = match;
  if (year === "2025") {
    const slug = OWASP_2025_SLUGS[code];
    if (!slug) return null;
    return `https://owasp.org/Top10/2025/${slug}/`;
  }
  const slug = OWASP_2021_SLUGS[code];
  if (!slug) return null;
  return `https://owasp.org/Top10/${slug}/`;
}
