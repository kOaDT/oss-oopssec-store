import Header from "../components/Header";
import Footer from "../components/Footer";
import Link from "next/link";

interface Flag {
  id: string;
  flag: string;
  slug: string;
  cve?: string | null;
  markdownFile: string;
}

async function getFlags(): Promise<Flag[]> {
  try {
    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
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
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl lg:text-6xl">
                OSS Flags
              </h1>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-4xl">
            <div className="mb-8 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800/50 dark:bg-amber-900/20">
              <div className="flex items-start gap-3">
                <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/30">
                  <svg
                    className="h-3 w-3 text-amber-600 dark:text-amber-400"
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
                  <strong className="font-semibold">Warning:</strong> This page
                  lists all flags hidden throughout the site. Do not consult
                  this page if you wish to find them on your own.
                </p>
              </div>
            </div>

            {flags.length === 0 ? (
              <div className="rounded-lg border border-slate-200 bg-white p-8 text-center dark:border-slate-800 dark:bg-slate-800/50">
                <p className="text-slate-600 dark:text-slate-400">
                  No flags available at this time.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {flags.map((flag) => (
                  <Link
                    key={flag.slug}
                    href={`/vulnerabilities/${flag.slug}`}
                    className="group block rounded-lg border border-slate-200 bg-white p-6 transition-all hover:border-primary-300 hover:shadow-lg dark:border-slate-800 dark:bg-slate-800/50 dark:hover:border-primary-700"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="mb-2 flex items-center gap-3">
                          <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                            {flag.flag}
                          </h2>
                          {flag.cve && (
                            <span className="rounded-full bg-red-100 px-3 py-1 text-xs font-semibold text-red-800 dark:bg-red-900/30 dark:text-red-400">
                              {flag.cve}
                            </span>
                          )}
                        </div>
                        <p className="text-sm font-medium capitalize text-slate-600 dark:text-slate-400">
                          {flag.slug.replace(/([A-Z])/g, " $1").trim()}
                        </p>
                      </div>
                      <svg
                        className="h-5 w-5 text-slate-400 transition-colors group-hover:text-primary-600 dark:text-slate-500 dark:group-hover:text-primary-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 5l7 7-7 7"
                        />
                      </svg>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
