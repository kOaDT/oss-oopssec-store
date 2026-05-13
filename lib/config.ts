export function getBaseUrl(): string {
  return process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
}

const DOCS_SITE_URL = "https://koadt.github.io/oss-oopssec-store";
export const DOCS_BASE_URL = `${DOCS_SITE_URL}/posts`;
export const DOCS_ROADMAP_URL = `${DOCS_SITE_URL}/roadmap`;
