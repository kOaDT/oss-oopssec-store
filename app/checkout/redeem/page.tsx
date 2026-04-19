import Header from "../../components/Header";
import Footer from "../../components/Footer";
import RedeemClient from "./RedeemClient";

export const metadata = {
  title: "Redeem a Gift Card — OopsSec Store",
  description:
    "Enter a gift card code to credit its value to your account balance.",
};

export default function RedeemPage() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl">
                Redeem a Gift Card
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                Enter your code to add its value to your account balance.
              </p>
            </div>
          </div>
        </section>
        <RedeemClient />
      </main>
      <Footer />
    </div>
  );
}
