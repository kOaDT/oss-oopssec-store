"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api, ApiError } from "@/lib/api";
import FlagDisplay from "../../components/FlagDisplay";

interface RedeemResponse {
  success: true;
  amount: number;
  balance: number;
  flag?: string;
}

export default function RedeemClient() {
  const { user } = useAuth();
  const router = useRouter();

  const [code, setCode] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RedeemResponse | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!user) {
      router.push("/login?redirect=/checkout/redeem");
      return;
    }

    setIsSubmitting(true);
    setError(null);
    setResult(null);

    try {
      const response = await api.post<RedeemResponse>(
        "/api/gift-cards/redeem",
        { code: code.trim() }
      );
      setResult(response);
      setCode("");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to redeem gift card. Please try again.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="container mx-auto px-4 py-12 lg:py-16">
      <div className="mx-auto max-w-xl">
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800 md:p-8">
          <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
            Enter your gift card code
          </h2>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label
                htmlFor="giftCardCode"
                className="block text-sm font-medium text-slate-700 dark:text-slate-300"
              >
                Gift card code
              </label>
              <input
                id="giftCardCode"
                type="text"
                required
                value={code}
                onChange={(event) => setCode(event.target.value.toUpperCase())}
                placeholder="XXXX-XXXX-XXXX"
                autoComplete="off"
                className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 font-mono text-lg tracking-widest text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500"
              />
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                Codes look like ABCD-EFGH-IJKL. They are case-insensitive.
              </p>
            </div>

            {error && (
              <div className="rounded-lg border border-red-200 bg-red-50 p-3 dark:border-red-800/50 dark:bg-red-900/20">
                <p className="text-sm font-medium text-red-800 dark:text-red-200">
                  {error}
                </p>
              </div>
            )}

            {result && (
              <div className="space-y-3">
                <div className="rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800/50 dark:bg-green-900/20">
                  <p className="text-sm font-medium text-green-800 dark:text-green-200">
                    ${result.amount.toFixed(2)} credited to your account. New
                    balance:{" "}
                    <span className="font-bold">
                      ${result.balance.toFixed(2)}
                    </span>
                    .
                  </p>
                </div>
                {result.flag && (
                  <FlagDisplay flag={result.flag} variant="compact" />
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting || !user || code.trim().length === 0}
              className="w-full cursor-pointer rounded-xl bg-primary-600 px-6 py-3.5 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              {!user
                ? "Sign in to redeem"
                : isSubmitting
                  ? "Redeeming..."
                  : "Redeem gift card"}
            </button>
          </form>
        </div>
      </div>
    </section>
  );
}
