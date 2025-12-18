import Header from "../components/Header";
import Footer from "../components/Footer";
import CheckoutClient from "./CheckoutClient";

export default function CheckoutPage() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-4xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl">
                Checkout
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                Review your order and complete your purchase
              </p>
            </div>
          </div>
        </section>
        <CheckoutClient />
      </main>
      <Footer />
    </div>
  );
}
