import Header from "../components/Header";
import Footer from "../components/Footer";
import SupportForm from "./SupportForm";
import Link from "next/link";

export default function SupportPage() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl lg:text-6xl">
                Contact Support
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                We&apos;re here to help. Submit your support request and
                we&apos;ll get back to you as soon as possible.
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-2xl">
            <div className="mb-8 rounded-xl border border-primary-200 bg-primary-50 p-6 dark:border-primary-800/50 dark:bg-primary-900/20">
              <div className="flex items-start gap-4">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-800/50">
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
                      d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
                    />
                  </svg>
                </div>
                <div className="flex-1">
                  <h3 className="mb-1 font-semibold text-primary-900 dark:text-primary-100">
                    Need instant help?
                  </h3>
                  <p className="mb-3 text-sm text-primary-700 dark:text-primary-300">
                    Try our AI-powered support assistant for immediate answers
                    to common questions about products, orders, and more.
                  </p>
                  <Link
                    href="/support/ai-assistant"
                    className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600"
                  >
                    Chat with OSSBot
                    <svg
                      className="h-4 w-4"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M13 7l5 5m0 0l-5 5m5-5H6"
                      />
                    </svg>
                  </Link>
                </div>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800">
              <SupportForm />
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
