import { Suspense } from "react";
import Header from "../components/Header";
import Footer from "../components/Footer";
import AdminClient from "./AdminClient";

export default function AdminPage() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-4xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl">
                Admin Panel
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                Administrative dashboard
              </p>
            </div>
          </div>
        </section>
        <Suspense
          fallback={
            <section className="container mx-auto px-4 py-16">
              <div className="mx-auto max-w-4xl">
                <div className="flex items-center justify-center py-20">
                  <div className="text-center">
                    <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
                    <p className="text-slate-600 dark:text-slate-400">
                      Loading...
                    </p>
                  </div>
                </div>
              </div>
            </section>
          }
        >
          <AdminClient />
        </Suspense>
      </main>
      <Footer />
    </div>
  );
}
