export interface Vulnerability {
  flag: string;
  slug: string;
  cve?: string;
  markdownFile: string;
}

export const vulnerabilities: Vulnerability[] = [
  {
    flag: "OSS{r3act2sh3ll}",
    slug: "react2shell",
    cve: "CVE-2025-55182",
    markdownFile: "react2shell.md",
  },
];

export function getVulnerabilityBySlug(
  slug: string
): Vulnerability | undefined {
  return vulnerabilities.find((v) => v.slug === slug);
}

export function getAllVulnerabilities(): Vulnerability[] {
  return vulnerabilities;
}
