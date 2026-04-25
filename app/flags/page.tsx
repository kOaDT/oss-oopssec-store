import Header from "../components/Header";
import Footer from "../components/Footer";
import { getBaseUrl } from "@/lib/config";
import { prisma } from "@/lib/prisma";
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

async function getFoundFlagIds(): Promise<string[]> {
  try {
    const found = await prisma.foundFlag.findMany({
      select: { flagId: true },
    });
    return found.map((f) => f.flagId);
  } catch (error) {
    console.error("Error fetching found flags:", error);
    return [];
  }
}

export default async function Flags() {
  const [flags, foundFlagIds] = await Promise.all([
    getFlags(),
    getFoundFlagIds(),
  ]);

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
            <div className="mb-8 rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800/50">
              <div className="flex items-start gap-3">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-slate-200 dark:bg-slate-700">
                  <svg
                    className="h-4 w-4 text-slate-600 dark:text-slate-300"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                </div>
                <p className="text-sm text-slate-700 dark:text-slate-300">
                  Flag values are revealed only after you submit the correct
                  flag for each challenge. Use the flag checker (bottom right)
                  to validate your discoveries.
                </p>
              </div>
            </div>

            <FlagsClient flags={flags} foundFlagIds={foundFlagIds} />
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
