import Header from "../components/Header";
import Footer from "../components/Footer";
import { prisma } from "@/lib/prisma";
import type { Flag } from "@/lib/types";
import FlagsClient from "./FlagsClient";

// The board reflects solves as they happen. The `fetch(..., no-store)` this page
// used to make was what opted it into dynamic rendering; reading Prisma directly
// carries no such signal, so without this the board would be prerendered at
// build time and frozen on an empty progress state.
export const dynamic = "force-dynamic";

/**
 * One query, one source of truth.
 *
 * The board used to read the flag list over HTTP from its own API and the
 * solved set from Prisma separately, then let the client decide with one and
 * render the other — which could show a "Found" badge above an empty value.
 * Joining `foundFlag` here means the presence of a value *is* the solved
 * state, so the two can no longer disagree.
 */
async function getFlags(): Promise<Flag[]> {
  try {
    const rows = await prisma.flag.findMany({
      orderBy: { slug: "asc" },
      select: {
        id: true,
        flag: true,
        slug: true,
        cve: true,
        cwe: true,
        owasp: true,
        markdownFile: true,
        walkthroughSlug: true,
        category: true,
        difficulty: true,
        foundFlag: { select: { id: true } },
      },
    });

    return rows.map(({ foundFlag, flag, ...rest }) => ({
      ...rest,
      flag: foundFlag ? flag : null,
    }));
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

            <FlagsClient flags={flags} />
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
