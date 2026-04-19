"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api, ApiError } from "@/lib/api";

interface GiftCardEntry {
  id: string;
  amount: number;
  recipientEmail: string;
  message: string | null;
  status: "PENDING" | "REDEEMED";
  createdAt: string;
  redeemedAt: string | null;
}

function formatCreatedAt(iso: string): string {
  const date = new Date(iso);
  return `${date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })}.${String(date.getMilliseconds()).padStart(3, "0")}`;
}

export default function ProfileGiftCardsClient() {
  const { user } = useAuth();
  const router = useRouter();
  const [giftCards, setGiftCards] = useState<GiftCardEntry[] | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [resendState, setResendState] = useState<
    Record<string, { loading: boolean; error: string | null }>
  >({});

  useEffect(() => {
    if (!user) {
      router.push("/login?redirect=/profile/gift-cards");
      return;
    }

    const fetchGiftCards = async () => {
      try {
        const data = await api.get<GiftCardEntry[]>("/api/gift-cards");
        setGiftCards(data);
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          router.push("/login?redirect=/profile/gift-cards");
          return;
        }
        setGiftCards([]);
      } finally {
        setIsLoading(false);
      }
    };

    fetchGiftCards();
  }, [user, router]);

  const handleResend = async (id: string) => {
    setResendState((prev) => ({
      ...prev,
      [id]: { loading: true, error: null },
    }));
    try {
      await api.post(`/api/gift-cards/resend`, { id });
      setResendState((prev) => ({
        ...prev,
        [id]: { loading: false, error: null },
      }));
    } catch (error) {
      const message =
        error instanceof ApiError
          ? error.message
          : "Email service temporarily unavailable. Please try again later.";
      setResendState((prev) => ({
        ...prev,
        [id]: { loading: false, error: message },
      }));
    }
  };

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">Loading...</p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (!giftCards || giftCards.length === 0) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center shadow-sm dark:border-slate-700 dark:bg-slate-800">
            <h2 className="mb-3 text-2xl font-bold text-slate-900 dark:text-slate-100">
              No gift cards sent yet
            </h2>
            <p className="mb-8 text-slate-600 dark:text-slate-400">
              Surprise someone with an OopsSec Store gift card.
            </p>
            <Link
              href="/gift-cards"
              className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Send a gift card
            </Link>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-12 lg:py-16">
      <div className="mx-auto max-w-4xl space-y-4">
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-600 dark:text-slate-400">
            {giftCards.length} gift card{giftCards.length > 1 ? "s" : ""} sent
          </p>
          <Link
            href="/gift-cards"
            className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600"
          >
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
                d="M12 4v16m8-8H4"
              />
            </svg>
            Send another
          </Link>
        </div>

        <ul className="space-y-4">
          {giftCards.map((card) => {
            const resend = resendState[card.id];
            return (
              <li
                key={card.id}
                className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800"
              >
                <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                  <div className="flex-1 space-y-2">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="text-2xl font-bold text-primary-600 dark:text-primary-400">
                        ${card.amount.toFixed(2)}
                      </span>
                      <span
                        className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${
                          card.status === "REDEEMED"
                            ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300"
                            : "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300"
                        }`}
                      >
                        {card.status === "REDEEMED" ? "Redeemed" : "Pending"}
                      </span>
                    </div>
                    <p className="text-sm text-slate-700 dark:text-slate-300">
                      <span className="text-slate-500 dark:text-slate-400">
                        Sent to:
                      </span>{" "}
                      <span className="font-medium">{card.recipientEmail}</span>
                    </p>
                    <p className="text-sm text-slate-700 dark:text-slate-300">
                      <span className="text-slate-500 dark:text-slate-400">
                        Sent on:
                      </span>{" "}
                      <time
                        dateTime={card.createdAt}
                        className="font-mono text-xs"
                      >
                        {formatCreatedAt(card.createdAt)}
                      </time>
                    </p>
                    {card.message && (
                      <p className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm italic text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400">
                        “{card.message}”
                      </p>
                    )}
                  </div>
                  <div className="flex flex-col items-start gap-2 md:items-end">
                    <button
                      type="button"
                      onClick={() => handleResend(card.id)}
                      disabled={resend?.loading || card.status === "REDEEMED"}
                      className="cursor-pointer rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:border-primary-300 hover:text-primary-600 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:border-primary-500 dark:hover:text-primary-400"
                    >
                      {resend?.loading ? "Sending..." : "Resend email"}
                    </button>
                    {resend?.error && (
                      <p className="max-w-xs text-right text-xs text-red-600 dark:text-red-400">
                        {resend.error}
                      </p>
                    )}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
