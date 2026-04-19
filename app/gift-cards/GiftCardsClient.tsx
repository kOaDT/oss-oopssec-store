"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api, ApiError } from "@/lib/api";

const DENOMINATIONS = [25, 50, 100, 500] as const;

type Denomination = (typeof DENOMINATIONS)[number];

interface SentGiftCard {
  id: string;
  amount: number;
  recipientEmail: string;
  status: string;
  createdAt: string;
}

export default function GiftCardsClient() {
  const { user } = useAuth();
  const router = useRouter();

  const [selected, setSelected] = useState<Denomination>(50);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [message, setMessage] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSent, setLastSent] = useState<SentGiftCard | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!user) {
      router.push("/login?redirect=/gift-cards");
      return;
    }

    setIsSubmitting(true);
    setError(null);
    setLastSent(null);

    try {
      const result = await api.post<SentGiftCard>("/api/gift-cards", {
        amount: selected,
        recipientEmail: recipientEmail.trim(),
        message: message.trim() || undefined,
      });
      setLastSent(result);
      setRecipientEmail("");
      setMessage("");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to send the gift card. Please try again.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="container mx-auto px-4 py-12 lg:py-16">
      <div className="mx-auto max-w-5xl">
        <div className="grid gap-8 lg:grid-cols-5">
          <div className="lg:col-span-3">
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800 md:p-8">
              <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
                Send a gift card
              </h2>

              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label className="mb-3 block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Choose a denomination
                  </label>
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    {DENOMINATIONS.map((amount) => (
                      <button
                        key={amount}
                        type="button"
                        onClick={() => setSelected(amount)}
                        className={`cursor-pointer rounded-xl border px-4 py-5 text-center transition-all ${
                          selected === amount
                            ? "border-primary-500 bg-primary-50 text-primary-700 shadow-sm dark:border-primary-400 dark:bg-primary-900/20 dark:text-primary-300"
                            : "border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-slate-600"
                        }`}
                      >
                        <span className="block text-2xl font-bold">
                          ${amount}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="recipientEmail"
                    className="block text-sm font-medium text-slate-700 dark:text-slate-300"
                  >
                    Recipient email
                  </label>
                  <input
                    id="recipientEmail"
                    type="email"
                    required
                    value={recipientEmail}
                    onChange={(event) => setRecipientEmail(event.target.value)}
                    placeholder="friend@example.com"
                    className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500"
                  />
                </div>

                <div>
                  <label
                    htmlFor="message"
                    className="block text-sm font-medium text-slate-700 dark:text-slate-300"
                  >
                    Personal message{" "}
                    <span className="text-slate-400">(optional)</span>
                  </label>
                  <textarea
                    id="message"
                    rows={4}
                    maxLength={500}
                    value={message}
                    onChange={(event) => setMessage(event.target.value)}
                    placeholder="Happy birthday! Enjoy a treat on me."
                    className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500"
                  />
                </div>

                {error && (
                  <div className="rounded-lg border border-red-200 bg-red-50 p-3 dark:border-red-800/50 dark:bg-red-900/20">
                    <p className="text-sm font-medium text-red-800 dark:text-red-200">
                      {error}
                    </p>
                  </div>
                )}

                {lastSent && (
                  <div className="rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800/50 dark:bg-green-900/20">
                    <p className="text-sm font-medium text-green-800 dark:text-green-200">
                      A ${lastSent.amount} gift card has been emailed to{" "}
                      {lastSent.recipientEmail}. View it in your{" "}
                      <Link
                        href="/profile/gift-cards"
                        className="underline hover:text-green-900 dark:hover:text-green-100"
                      >
                        gift card history
                      </Link>
                      .
                    </p>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isSubmitting || !user}
                  className="w-full cursor-pointer rounded-xl bg-primary-600 px-6 py-3.5 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
                >
                  {!user
                    ? "Sign in to send a gift card"
                    : isSubmitting
                      ? "Sending..."
                      : `Send $${selected} gift card`}
                </button>
              </form>
            </div>
          </div>

          <div className="space-y-6 lg:col-span-2">
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
              <h3 className="mb-3 text-lg font-semibold text-slate-900 dark:text-slate-100">
                How it works
              </h3>
              <ol className="space-y-3 text-sm text-slate-600 dark:text-slate-400">
                <li>
                  <span className="mr-2 font-semibold text-primary-600 dark:text-primary-400">
                    1.
                  </span>
                  Pick a denomination and enter the recipient&apos;s email
                  address.
                </li>
                <li>
                  <span className="mr-2 font-semibold text-primary-600 dark:text-primary-400">
                    2.
                  </span>
                  We generate a unique redemption code and deliver it by email.
                </li>
                <li>
                  <span className="mr-2 font-semibold text-primary-600 dark:text-primary-400">
                    3.
                  </span>
                  The recipient redeems the code at checkout for store credit.
                </li>
              </ol>
            </div>

            {user && (
              <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h3 className="mb-3 text-lg font-semibold text-slate-900 dark:text-slate-100">
                  Your gift card history
                </h3>
                <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">
                  Review the cards you&apos;ve sent, track their status, and
                  resend delivery emails.
                </p>
                <Link
                  href="/profile/gift-cards"
                  className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600"
                >
                  View sent gift cards
                  <svg
                    className="h-4 w-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M17 8l4 4m0 0l-4 4m4-4H3"
                    />
                  </svg>
                </Link>
              </div>
            )}

            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
              <h3 className="mb-3 text-lg font-semibold text-slate-900 dark:text-slate-100">
                Have a code?
              </h3>
              <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">
                Redeem a gift card you received and credit it to your account
                balance.
              </p>
              <Link
                href="/checkout/redeem"
                className="inline-flex items-center gap-2 rounded-lg bg-secondary-600 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-secondary-700 dark:bg-secondary-500 dark:hover:bg-secondary-600"
              >
                Redeem a gift card
                <svg
                  className="h-4 w-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M17 8l4 4m0 0l-4 4m4-4H3"
                  />
                </svg>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
