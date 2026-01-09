import Header from "../components/Header";
import Footer from "../components/Footer";
import { getBaseUrl } from "@/lib/config";
import type { Flag } from "@/lib/types";
import FlagsClient from "./FlagsClient";

async function getFlags(): Promise<Flag[]> {
  try {
    const baseUrl = getBaseUrl();
    const response = await fetch(`${baseUrl}/api/flags`, {
      cache: "no-store",
    });

    if (!response.ok) {
      return [];
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching flags:", error);
    return [];
  }
}

export default async function Flags() {
  const flags = await getFlags();

  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-12 md:py-16">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-4 text-3xl font-bold tracking-tight text-white md:text-4xl lg:text-5xl">
                Security Flags
              </h1>
              <p className="text-lg text-white/80">
                Discover and learn about web security vulnerabilities
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-8 md:py-12">
          <div className="mx-auto max-w-6xl">
            <div className="mb-8 rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-800/50 dark:bg-amber-900/20">
              <div className="flex items-start gap-3">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/30">
                  <svg
                    className="h-4 w-4 text-amber-600 dark:text-amber-400"
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
                <p className="text-sm text-amber-800 dark:text-amber-300">
                  <strong className="font-semibold">Spoiler warning:</strong>{" "}
                  This page lists all flags hidden throughout the site. Avoid
                  consulting this page if you wish to find them on your own.
                </p>
              </div>
            </div>

            <FlagsClient flags={flags} />
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
