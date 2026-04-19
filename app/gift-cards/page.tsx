import Header from "../components/Header";
import Footer from "../components/Footer";
import GiftCardsClient from "./GiftCardsClient";

export const metadata = {
  title: "Gift Cards — OopsSec Store",
  description:
    "Send an OopsSec Store gift card to a friend. Choose a denomination, add a personal message, and we'll deliver it by email.",
};

export default function GiftCardsPage() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl">
                Gift Cards
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                The perfect present. Pick a denomination, add a personal
                message, and we&apos;ll email it directly to the recipient.
              </p>
            </div>
          </div>
        </section>
        <GiftCardsClient />
      </main>
      <Footer />
    </div>
  );
}
