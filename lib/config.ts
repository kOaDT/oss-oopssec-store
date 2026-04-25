export function getBaseUrl(): string {
  return process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
}

export const DOCS_BASE_URL = "https://koadt.github.io/oss-oopssec-store/posts";
