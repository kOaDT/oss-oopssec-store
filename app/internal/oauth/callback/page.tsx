import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { prisma } from "@/lib/prisma";
import { decodeWeakJWT } from "@/lib/server-auth";
import Header from "@/app/components/Header";
import Footer from "@/app/components/Footer";
import FlagDisplay from "@/app/components/FlagDisplay";

async function getFlag() {
  const flag = await prisma.flag.findUnique({
    where: { slug: "open-redirect" },
  });
  return flag;
}

export default async function OAuthCallbackPage() {
  const cookieStore = await cookies();
  const authToken = cookieStore.get("authToken")?.value;
  const oauthCallback = cookieStore.get("oauth_callback")?.value;

  if (!authToken || !decodeWeakJWT(authToken) || !oauthCallback) {
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
                OAuth Callback Handler
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                SSO integration endpoint
              </p>
            </div>
          </div>
        </section>
        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-4xl">
            <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800">
              <div className="mb-6">
                <h2 className="mb-4 text-2xl font-bold text-slate-900 dark:text-slate-100">
                  Callback Status
                </h2>
                <div className="space-y-4">
                  <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                    <span className="text-slate-700 dark:text-slate-300">
                      OAuth Provider
                    </span>
                    <span className="rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
                      Connected
                    </span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                    <span className="text-slate-700 dark:text-slate-300">
                      Token Exchange
                    </span>
                    <span className="rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
                      Completed
                    </span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                    <span className="text-slate-700 dark:text-slate-300">
                      Session Binding
                    </span>
                    <span className="rounded-full bg-amber-100 px-3 py-1 text-sm font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">
                      Debug Mode
                    </span>
                  </div>
                </div>
              </div>
              {flag && (
                <div className="mt-8">
                  <FlagDisplay flag={flag.flag} title="Open Redirect Flag" />
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
