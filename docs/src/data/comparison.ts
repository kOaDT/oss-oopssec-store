import { CURRICULUM, TOTAL_CHALLENGES } from "./roadmap";

export type Status = "yes" | "partial" | "no";

export interface Cell {
  status?: Status;
  /** Backticks mark inline code. */
  detail?: string;
}

export interface Lab {
  key: "oopssec" | "juiceShop" | "dvwa";
  name: string;
}

export interface ComparisonRow {
  criterion: string;
  cells: Record<Lab["key"], Cell>;
}

export const LABS: Lab[] = [
  { key: "oopssec", name: "OopsSec Store" },
  { key: "juiceShop", name: "Juice Shop" },
  { key: "dvwa", name: "DVWA" },
];

/** The README carries the same table and footnote, and the parity suite fails
 * when the two drift: re-verify the competitors before editing either. */
export const LAST_VERIFIED = {
  month: "November 2026",
  against: "Juice Shop v20.4 and DVWA 2.5",
  sources: [
    {
      label: "Juice Shop v20.4.0 release notes",
      url: "https://github.com/juice-shop/juice-shop/releases/tag/v20.4.0",
    },
    {
      label: "Juice Shop companion guide",
      url: "https://pwning.owasp-juice.shop/",
    },
    { label: "DVWA repository", url: "https://github.com/digininja/DVWA" },
  ],
};

export const COMPARISON: ComparisonRow[] = [
  {
    criterion: "Stack",
    cells: {
      oopssec: { detail: "Next.js · React · TypeScript · Prisma" },
      juiceShop: { detail: "Node.js · Express · Angular" },
      dvwa: { detail: "PHP · MySQL" },
    },
  },
  {
    criterion: "Setup",
    cells: {
      oopssec: { detail: "`npx create-oss-store` / Docker" },
      juiceShop: { detail: "Docker / npm" },
      dvwa: { detail: "Docker / manual LAMP" },
    },
  },
  {
    criterion: "CTF flags",
    cells: {
      oopssec: { status: "yes", detail: "Built in (static flags)" },
      juiceShop: {
        status: "yes",
        detail: "Opt-in, per-instance flags (`CTF_KEY`); CTFd/RootTheBox/FBCTF",
      },
      dvwa: { status: "no" },
    },
  },
  {
    criterion: "Guided learning roadmap",
    cells: {
      oopssec: {
        status: "yes",
        detail: `1 roadmap, ${CURRICULUM.length} chapters, ${TOTAL_CHALLENGES} flags`,
      },
      juiceShop: { status: "no", detail: "Score board only" },
      dvwa: { status: "partial", detail: "security levels" },
    },
  },
  {
    criterion: "Walkthrough for every challenge",
    cells: {
      oopssec: { status: "yes" },
      juiceShop: { status: "yes", detail: "Companion guide" },
      dvwa: { status: "partial", detail: "hints" },
    },
  },
  {
    criterion: "LLM prompt injection",
    cells: {
      oopssec: { status: "yes", detail: "Bring a Mistral API key" },
      juiceShop: {
        status: "yes",
        detail:
          "v20+, local Ollama by default or any OpenAI-compatible endpoint",
      },
      dvwa: { status: "no" },
    },
  },
  {
    criterion: "MCP tool poisoning",
    cells: {
      oopssec: { status: "yes" },
      juiceShop: { status: "no" },
      dvwa: { status: "no" },
    },
  },
  {
    criterion: "AI coding-agent backdoor (poisoned rules file)",
    cells: {
      oopssec: { status: "yes" },
      juiceShop: { status: "no" },
      dvwa: { status: "no" },
    },
  },
  {
    criterion: "Supply-chain attack chain",
    cells: {
      oopssec: {
        status: "yes",
        detail: "Simulated end to end: npm typosquat → rules backdoor",
      },
      juiceShop: { status: "partial", detail: "identification only" },
      dvwa: { status: "no" },
    },
  },
  {
    criterion: "Challenges built on real CVEs",
    cells: {
      oopssec: { status: "yes", detail: "Next.js / React framework CVEs" },
      juiceShop: { status: "partial", detail: "vulnerable npm dependencies" },
      dvwa: { status: "no" },
    },
  },
  {
    criterion: "Hall of Fame for players",
    cells: {
      oopssec: { status: "yes" },
      juiceShop: { status: "no" },
      dvwa: { status: "no" },
    },
  },
];
