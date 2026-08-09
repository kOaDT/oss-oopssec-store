import Link from "next/link";
import Header from "../components/Header";
import Footer from "../components/Footer";
import SandboxTokenPanel from "./SandboxTokenPanel";
import { getBaseUrl } from "@/lib/config";
import {
  PARTNER_DIRECTORY,
  PARTNER_TOKEN_ISSUER,
  PARTNER_TOKEN_SCOPE,
} from "@/lib/partner-directory";

export const metadata = {
  title: "Partner API — OopsSec Store",
  description:
    "Integrate your supply chain with OopsSec Store. Pull purchase orders, track fulfilment and verify signed webhooks from a documented REST API.",
};

const CAPABILITIES = [
  {
    title: "Purchase orders on tap",
    body: "Every PO we raise with you, with totals, payment terms and buyer notes, available the moment procurement signs it off.",
  },
  {
    title: "Sandbox in one click",
    body: "A demo partner account loaded with fake orders. No contract, no onboarding call, no credentials to wait for.",
  },
  {
    title: "Signed webhooks",
    body: "We push order events to your endpoint and sign every callback, so your systems can prove the payload came from us.",
  },
];

const TOKEN_EXAMPLE = `{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "6h1E…"
}
{
  "iss": "${PARTNER_TOKEN_ISSUER}",
  "sub": "SUP-SANDBOX",
  "scope": "${PARTNER_TOKEN_SCOPE}",
  "iat": 1767225600,
  "exp": 1767229200
}`;

const RESPONSE_EXAMPLE = `{
  "partnerId": "SUP-SANDBOX",
  "count": 3,
  "orders": [
    {
      "purchaseOrderId": "PO-SBX-0003",
      "total": 1310.75,
      "notes": "Sandbox fixture — not a real commitment.",
      "createdAt": "2026-01-04T09:12:00.000Z"
    }
  ]
}`;

const CHANGELOG = [
  {
    version: "v2",
    status: "Current",
    body: "Access tokens are signed with RS256. Rotating our key no longer means emailing every partner a new secret — you fetch the public half from the JWKS endpoint and cache it.",
    tone: "current" as const,
  },
  {
    version: "v1",
    status: "Deprecated",
    body: "Access tokens were signed with HS256 using a shared secret issued per supplier. The gateway still accepts them while the last integrations migrate, so the v2 rollout did not need a flag day.",
    tone: "legacy" as const,
  },
];

function SectionHeading({
  eyebrow,
  title,
  children,
}: {
  eyebrow: string;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-8 max-w-3xl">
      <p className="mb-2 text-sm font-semibold uppercase tracking-wide text-primary-600 dark:text-primary-400">
        {eyebrow}
      </p>
      <h2 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
        {title}
      </h2>
      {children && (
        <div className="mt-4 space-y-4 leading-relaxed text-slate-600 dark:text-slate-400">
          {children}
        </div>
      )}
    </div>
  );
}

function CodeBlock({ label, code }: { label: string; code: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <p className="mb-3 font-mono text-xs uppercase tracking-wide text-slate-500">
        {label}
      </p>
      <pre className="overflow-x-auto font-mono text-xs leading-relaxed text-slate-200">
        {code}
      </pre>
    </div>
  );
}

export default function PartnersPage() {
  const baseUrl = getBaseUrl();

  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <p className="mb-4 text-sm font-semibold uppercase tracking-widest text-primary-100">
                For suppliers
              </p>
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl">
                Partner API
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                Wholesale, wired in. Sync purchase orders straight into your ERP
                — no CSV exports, no portal logins, no chasing our buyers for a
                spreadsheet.
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-5xl">
            <div className="grid gap-6 md:grid-cols-3">
              {CAPABILITIES.map((capability) => (
                <div
                  key={capability.title}
                  className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800"
                >
                  <h3 className="mb-3 text-lg font-bold text-slate-900 dark:text-slate-100">
                    {capability.title}
                  </h3>
                  <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                    {capability.body}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border-t border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-800/30">
          <div className="container mx-auto px-4 py-16">
            <div className="mx-auto max-w-5xl">
              <SectionHeading eyebrow="Authentication" title="Bearer tokens">
                <p>
                  Every request carries an{" "}
                  <code className="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-sm text-slate-800 dark:bg-slate-700 dark:text-slate-200">
                    Authorization: Bearer
                  </code>{" "}
                  header. Tokens are JWTs signed by our procurement gateway and
                  valid for one hour.
                </p>
                <p>
                  The <strong>sub</strong> claim is your partner ID and decides
                  which purchase orders you can read. Endpoints take no partner
                  parameter: whoever the token says you are is who you are.
                </p>
              </SectionHeading>

              <div className="grid gap-6 lg:grid-cols-2">
                <CodeBlock label="Decoded token" code={TOKEN_EXAMPLE} />
                <div className="rounded-2xl border border-slate-200 bg-white p-6 dark:border-slate-700 dark:bg-slate-800">
                  <h3 className="mb-4 text-lg font-bold text-slate-900 dark:text-slate-100">
                    Getting production credentials
                  </h3>
                  <ol className="space-y-3 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                    <li>
                      <span className="font-semibold text-slate-900 dark:text-slate-100">
                        1.
                      </span>{" "}
                      Sign the supply agreement with our procurement team.
                    </li>
                    <li>
                      <span className="font-semibold text-slate-900 dark:text-slate-100">
                        2.
                      </span>{" "}
                      Receive your partner ID and client credentials by
                      encrypted mail.
                    </li>
                    <li>
                      <span className="font-semibold text-slate-900 dark:text-slate-100">
                        3.
                      </span>{" "}
                      Exchange them for access tokens, refreshing before the
                      hour is up.
                    </li>
                  </ol>
                  <p className="mt-4 text-sm text-slate-600 dark:text-slate-400">
                    Building against the API first?{" "}
                    <Link
                      href="/contact"
                      className="font-medium text-primary-600 hover:underline dark:text-primary-400"
                    >
                      Talk to us
                    </Link>{" "}
                    once your sandbox integration passes.
                  </p>
                </div>
              </div>

              <div className="mt-6">
                <SandboxTokenPanel />
              </div>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-5xl">
            <SectionHeading eyebrow="Reference" title="Endpoints">
              <p>
                Base URL{" "}
                <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-sm text-slate-800 dark:bg-slate-800 dark:text-slate-200">
                  {baseUrl}
                </code>
                . All responses are JSON.
              </p>
            </SectionHeading>

            <div className="overflow-x-auto rounded-2xl border border-slate-200 dark:border-slate-700">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-800">
                    <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                      Endpoint
                    </th>
                    <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                      Scope
                    </th>
                    <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                      Returns
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                  <tr>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-slate-900 dark:text-slate-100">
                      GET /api/partner/orders
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-slate-600 dark:text-slate-400">
                      {PARTNER_TOKEN_SCOPE}
                    </td>
                    <td className="px-4 py-3 text-slate-600 dark:text-slate-400">
                      Purchase orders raised with the partner named in the token
                    </td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-slate-900 dark:text-slate-100">
                      POST /api/partner/sandbox-token
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-slate-600 dark:text-slate-400">
                      public
                    </td>
                    <td className="px-4 py-3 text-slate-600 dark:text-slate-400">
                      A one-hour token for the sandbox partner account
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-6 grid items-start gap-6 lg:grid-cols-2">
              <CodeBlock
                label="Request"
                code={`curl -H "Authorization: Bearer $TOKEN" \\\n  ${baseUrl}/api/partner/orders`}
              />
              <CodeBlock label="Response" code={RESPONSE_EXAMPLE} />
            </div>
          </div>
        </section>

        <section className="border-t border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-800/30">
          <div className="container mx-auto px-4 py-16">
            <div className="mx-auto max-w-5xl">
              <SectionHeading
                eyebrow="Webhooks"
                title="Verifying our callbacks"
              >
                <p>
                  When a purchase order changes state we POST it to your
                  callback URL and sign the body with the same key pair that
                  signs access tokens. Anyone can send you a JSON payload that
                  claims to be from us; only we can produce a signature that
                  checks out against our public key.
                </p>
                <p>
                  So we publish that public key, deliberately and permanently.
                  Fetch it, cache it by{" "}
                  <code className="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-sm text-slate-800 dark:bg-slate-700 dark:text-slate-200">
                    kid
                  </code>
                  , and verify every callback before you act on it.
                </p>
              </SectionHeading>

              <div className="grid gap-4 md:grid-cols-2">
                <a
                  href="/.well-known/jwks.json"
                  className="group rounded-2xl border border-slate-200 bg-white p-6 transition-colors hover:border-primary-400 dark:border-slate-700 dark:bg-slate-800 dark:hover:border-primary-500"
                >
                  <p className="mb-2 font-mono text-sm text-primary-600 group-hover:underline dark:text-primary-400">
                    /.well-known/jwks.json
                  </p>
                  <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                    Our signing keys as a JWK Set. Select the key whose{" "}
                    <code className="font-mono">kid</code> matches the webhook
                    header.
                  </p>
                </a>
                <a
                  href="/.well-known/partner-signing-key.pem"
                  className="group rounded-2xl border border-slate-200 bg-white p-6 transition-colors hover:border-primary-400 dark:border-slate-700 dark:bg-slate-800 dark:hover:border-primary-500"
                >
                  <p className="mb-2 font-mono text-sm text-primary-600 group-hover:underline dark:text-primary-400">
                    /.well-known/partner-signing-key.pem
                  </p>
                  <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                    The same key as a raw SPKI PEM, for libraries that would
                    rather read a file than assemble one from a JWK.
                  </p>
                </a>
              </div>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-5xl">
            <SectionHeading eyebrow="Changelog" title="API versions" />
            <div className="space-y-4">
              {CHANGELOG.map((entry) => (
                <div
                  key={entry.version}
                  className="rounded-2xl border border-slate-200 bg-white p-6 dark:border-slate-700 dark:bg-slate-800"
                >
                  <div className="mb-3 flex items-center gap-3">
                    <span className="font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                      {entry.version}
                    </span>
                    <span
                      className={`rounded-full px-3 py-1 text-xs font-semibold ${
                        entry.tone === "current"
                          ? "bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300"
                          : "bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300"
                      }`}
                    >
                      {entry.status}
                    </span>
                  </div>
                  <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                    {entry.body}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border-t border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-800/30">
          <div className="container mx-auto px-4 py-16">
            <div className="mx-auto max-w-5xl">
              <SectionHeading
                eyebrow="Partner directory"
                title="Already integrated"
              >
                <p>
                  Suppliers running on the Partner API today. Partner IDs are
                  listed so shared logistics providers can reconcile shipments
                  across accounts.
                </p>
              </SectionHeading>

              <div className="overflow-x-auto rounded-2xl border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-800">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-900/50">
                      <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                        Supplier
                      </th>
                      <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                        Partner ID
                      </th>
                      <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                        Categories
                      </th>
                      <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                        Live since
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {PARTNER_DIRECTORY.map((partner) => (
                      <tr key={partner.partnerId}>
                        <td className="px-4 py-3 font-medium text-slate-900 dark:text-slate-100">
                          {partner.company}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 font-mono text-slate-600 dark:text-slate-400">
                          {partner.partnerId}
                        </td>
                        <td className="px-4 py-3 text-slate-600 dark:text-slate-400">
                          {partner.categories}
                        </td>
                        <td className="px-4 py-3 text-slate-600 dark:text-slate-400">
                          {partner.since}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <p className="mt-6 text-sm text-slate-600 dark:text-slate-400">
                Supplying us and not on this list?{" "}
                <Link
                  href="/contact"
                  className="font-medium text-primary-600 hover:underline dark:text-primary-400"
                >
                  Request onboarding
                </Link>{" "}
                and we will provision your partner ID.
              </p>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
