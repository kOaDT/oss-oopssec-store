import Header from "../components/Header";
import Footer from "../components/Footer";
import { DOCS_ROADMAP_URL } from "@/lib/config";

export default function About() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl lg:text-6xl">
                About This Project
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                Understanding the purpose and responsibility behind this
                platform
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-4xl space-y-12">
            <div className="rounded-2xl border border-amber-200 bg-amber-50 p-8 dark:border-amber-800/50 dark:bg-amber-900/20">
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/30">
                  <svg
                    className="h-6 w-6 text-amber-600 dark:text-amber-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                  Critical Warning
                </h2>
              </div>
              <div className="space-y-4 text-slate-700 dark:text-slate-300">
                <p className="text-lg font-semibold">
                  This application must never be deployed to a production
                  environment or exposed to the public internet.
                </p>
                <p className="leading-relaxed">
                  The vulnerabilities present in this application are
                  intentional and should only be accessed in isolated,
                  controlled environments such as local development setups,
                  dedicated training labs, or private networks with proper
                  access controls.
                </p>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-8 dark:border-slate-800 dark:bg-slate-800/50">
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/30">
                  <svg
                    className="h-6 w-6 text-primary-600 dark:text-primary-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
                    />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                  Learning Objectives
                </h2>
              </div>
              <div className="space-y-4 text-slate-700 dark:text-slate-300">
                <p className="leading-relaxed">
                  This platform is designed to help you learn how to identify,
                  exploit, and ultimately defend against real-world security
                  vulnerabilities — from classic web flaws to AI-, crypto-, and
                  supply-chain-specific risks. The challenges are grouped into
                  these areas:
                </p>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                    <h3 className="mb-2 font-semibold text-slate-900 dark:text-slate-100">
                      Injection
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      SQL injection (search, second-order, header-based),
                      cross-site scripting (XSS), XXE, and prompt injection
                      against the AI assistant
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                    <h3 className="mb-2 font-semibold text-slate-900 dark:text-slate-100">
                      Authentication
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Brute force without rate limiting, weak JWT secrets,
                      session fixation, and insecure password resets
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                    <h3 className="mb-2 font-semibold text-slate-900 dark:text-slate-100">
                      Authorization
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Insecure direct object references (IDOR), broken
                      object-level authorization, and middleware access-control
                      bypasses
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                    <h3 className="mb-2 font-semibold text-slate-900 dark:text-slate-100">
                      Request Forgery
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Cross-site request forgery (CSRF), including
                      profile-takeover chains, and server-side request forgery
                      (SSRF)
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                    <h3 className="mb-2 font-semibold text-slate-900 dark:text-slate-100">
                      Cryptographic Failures
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Weak MD5 hashing, an AES-CBC padding oracle, and insecure
                      randomness
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                    <h3 className="mb-2 font-semibold text-slate-900 dark:text-slate-100">
                      Information Disclosure
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Verbose API errors, plaintext passwords in logs, and
                      secrets leaked through public environment variables
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                    <h3 className="mb-2 font-semibold text-slate-900 dark:text-slate-100">
                      Input Validation
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Client-side price manipulation, mass assignment, open
                      redirects, and path traversal
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                    <h3 className="mb-2 font-semibold text-slate-900 dark:text-slate-100">
                      Supply Chain & Insecure Design
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      npm typosquatting, a malicious AI rules-file backdoor,
                      business-logic flaws, and remote code execution
                    </p>
                  </div>
                </div>
                <p className="leading-relaxed">
                  Not sure where to start? The{" "}
                  <a
                    href={DOCS_ROADMAP_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium text-primary-600 underline-offset-2 hover:underline dark:text-primary-400"
                  >
                    guided roadmap
                  </a>{" "}
                  orders these challenges into a recommended learning path, from
                  reconnaissance basics through to chained, real-world exploits.
                </p>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-8 dark:border-slate-800 dark:bg-slate-800/50">
              <div className="mb-6 flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/30">
                  <svg
                    className="h-6 w-6 text-primary-600 dark:text-primary-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                    />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                  Community & Contribution
                </h2>
              </div>
              <p className="leading-relaxed text-slate-700 dark:text-slate-300">
                This project is part of the open-source security education
                community. If you discover issues, have suggestions for
                improvements, or want to contribute additional vulnerabilities
                for educational purposes, we welcome responsible contributions
                that align with our ethical guidelines and educational mission.
              </p>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
