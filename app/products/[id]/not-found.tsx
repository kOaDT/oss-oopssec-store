import Header from "../../components/Header";
import Footer from "../../components/Footer";
import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-2xl text-center">
            <h1 className="mb-4 text-4xl font-bold text-slate-900 dark:text-slate-100">
              Product Not Found
            </h1>
            <p className="mb-8 text-slate-600 dark:text-slate-400">
              The product you are looking for does not exist or has been
              removed.
            </p>
            <Link
              href="/"
              className="inline-block rounded-lg bg-primary-600 px-6 py-3 font-medium text-white transition-colors hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Back to Products
            </Link>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
