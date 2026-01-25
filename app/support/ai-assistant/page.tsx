import Header from "../../components/Header";
import Footer from "../../components/Footer";
import AIAssistantChat from "./AIAssistantChat";
import Link from "next/link";

export default function AIAssistantPage() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-20">
            <div className="mx-auto max-w-3xl text-center">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full bg-white/10 px-4 py-2 text-sm text-white backdrop-blur-sm">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-green-500"></span>
                </span>
                Powered by Mistral AI
              </div>
              <h1 className="mb-4 text-4xl font-bold tracking-tight text-white md:text-5xl">
                AI Support Assistant
              </h1>
              <p className="text-lg text-primary-50">
                Get instant help with products, orders, and general inquiries.
                Our AI assistant is available 24/7.
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-12">
          <AIAssistantChat />

          <div className="mx-auto mt-8 max-w-2xl text-center">
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Need human assistance?{" "}
              <Link
                href="/support"
                className="text-primary-600 underline hover:text-primary-700 dark:text-primary-400"
              >
                Contact our support team
              </Link>
            </p>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
