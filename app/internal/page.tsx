import { prisma } from "@/lib/prisma";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Header from "../components/Header";
import Footer from "../components/Footer";
import FlagDisplay from "../components/FlagDisplay";

async function getFlag() {
  const flag = await prisma.flag.findUnique({
    where: { slug: "server-side-request-forgery" },
  });
  return flag;
}

export default async function InternalPage() {
  const headersList = await headers();
  const internalRequest = headersList.get("x-internal-request");

  if (internalRequest !== "true") {
    redirect("/");
  }

  const flag = await getFlag();

  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-4xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl">
                Internal System Dashboard
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                System administration and monitoring
              </p>
            </div>
          </div>
        </section>
        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-4xl">
            <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800">
              <div className="mb-6">
                <h2 className="mb-4 text-2xl font-bold text-slate-900 dark:text-slate-100">
                  System Status
                </h2>
                <div className="space-y-4">
                  <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                    <span className="text-slate-700 dark:text-slate-300">
                      Database Status
                    </span>
                    <span className="rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
                      Connected
                    </span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                    <span className="text-slate-700 dark:text-slate-300">
                      Application Status
                    </span>
                    <span className="rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
                      Running
                    </span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                    <span className="text-slate-700 dark:text-slate-300">
                      Security Status
                    </span>
                    <span className="rounded-full bg-amber-100 px-3 py-1 text-sm font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">
                      Monitoring
                    </span>
                  </div>
                </div>
              </div>
              {flag && (
                <div className="mt-8">
                  <FlagDisplay
                    flag={flag.flag}
                    title="Security Token"
                    variant="minimal"
                  />
                </div>
              )}
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
