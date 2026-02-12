"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import FlagDisplay from "../../components/FlagDisplay";
import { getStoredUser } from "@/lib/client-auth";

interface AdminReview {
  id: string;
  productId: string;
  content: string;
  author: string;
  createdAt: string;
  productName: string;
}

interface ReviewsResponse {
  reviews: AdminReview[];
  authors: string[];
  flag?: string;
  message?: string;
}

export default function ReviewsClient() {
  const [data, setData] = useState<ReviewsResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAuthor, setSelectedAuthor] = useState("");
  const [isFiltering, setIsFiltering] = useState(false);
  const [flag, setFlag] = useState<string | null>(null);
  const router = useRouter();

  const fetchReviews = useCallback(
    async (author?: string) => {
      try {
        const url = author
          ? `/api/admin/reviews?author=${encodeURIComponent(author)}`
          : "/api/admin/reviews";

        const response = await fetch(url, {
          credentials: "include",
        });

        if (!response.ok) {
          if (response.status === 401) {
            router.push("/login");
            return;
          }
          if (response.status === 403) {
            const errorData = await response.json();
            setError(
              errorData.error ||
                "Forbidden: You do not have administrator privileges."
            );
            setIsLoading(false);
            setIsFiltering(false);
            return;
          }
          throw new Error("Failed to fetch reviews");
        }

        const reviewsData: ReviewsResponse = await response.json();
        setData(reviewsData);

        if (reviewsData.flag) {
          setFlag(reviewsData.flag);
        }
      } catch (err) {
        console.error("Error fetching reviews:", err);
        setError("An error occurred while fetching reviews.");
      } finally {
        setIsLoading(false);
        setIsFiltering(false);
      }
    },
    [router]
  );

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    fetchReviews();
  }, [router, fetchReviews]);

  const handleAuthorFilter = async (author: string) => {
    setSelectedAuthor(author);
    setIsFiltering(true);
    setError(null);
    await fetchReviews(author || undefined);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-6xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">
                Loading reviews...
              </p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (error && !data) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="rounded-2xl bg-white p-12 text-center shadow-sm dark:bg-slate-800">
            <div className="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30">
              <svg
                className="h-8 w-8 text-red-600 dark:text-red-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </div>
            <h2 className="mb-3 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Access Denied
            </h2>
            <p className="mb-8 text-slate-600 dark:text-slate-400">{error}</p>
            <Link
              href="/"
              className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Go to Home
            </Link>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-6xl space-y-8">
        {flag && <FlagDisplay flag={flag} variant="compact" />}

        {error && (
          <div className="rounded-xl border-2 border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
            <p className="text-center text-sm text-red-700 dark:text-red-300">
              {error}
            </p>
          </div>
        )}

        <div className="grid gap-6 md:grid-cols-2">
          <div className="rounded-2xl bg-white p-6 shadow-sm dark:bg-slate-800">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary-100 dark:bg-primary-900/30">
                <svg
                  className="h-6 w-6 text-primary-600 dark:text-primary-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z"
                  />
                </svg>
              </div>
              <div>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Total Reviews
                </p>
                <p className="text-3xl font-bold text-slate-900 dark:text-slate-100">
                  {data?.reviews.length || 0}
                </p>
              </div>
            </div>
          </div>
          <div className="rounded-2xl bg-white p-6 shadow-sm dark:bg-slate-800">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-secondary-100 dark:bg-secondary-900/30">
                <svg
                  className="h-6 w-6 text-secondary-600 dark:text-secondary-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"
                  />
                </svg>
              </div>
              <div>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Unique Authors
                </p>
                <p className="text-3xl font-bold text-slate-900 dark:text-slate-100">
                  {data?.authors.length || 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800">
          <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              All Reviews
            </h2>
            <div className="flex items-center gap-3">
              <label
                htmlFor="authorFilter"
                className="text-sm font-medium text-slate-600 dark:text-slate-400"
              >
                Filter by author:
              </label>
              <select
                id="authorFilter"
                value={selectedAuthor}
                onChange={(e) => handleAuthorFilter(e.target.value)}
                disabled={isFiltering}
                className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm text-slate-900 shadow-sm focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
              >
                <option value="">All authors</option>
                {data?.authors.map((author) => (
                  <option key={author} value={author}>
                    {author}
                  </option>
                ))}
              </select>
              {isFiltering && (
                <div className="h-5 w-5 animate-spin rounded-full border-2 border-solid border-primary-600 border-r-transparent"></div>
              )}
            </div>
          </div>

          {data?.reviews && data.reviews.length > 0 ? (
            <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700">
              <table className="w-full">
                <thead className="bg-slate-50 dark:bg-slate-900/50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                      Author
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                      Product
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                      Content
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                      Date
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 bg-white dark:divide-slate-700 dark:bg-slate-800">
                  {data.reviews.map((review, index) => (
                    <tr key={review.id || index}>
                      <td className="whitespace-nowrap px-6 py-4">
                        <span className="font-mono text-xs text-slate-900 dark:text-slate-100">
                          {review.author}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-slate-700 dark:text-slate-300">
                          {review.productName}
                        </span>
                      </td>
                      <td className="max-w-xs px-6 py-4">
                        <span className="line-clamp-2 text-sm text-slate-700 dark:text-slate-300">
                          {review.content}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <span className="text-sm text-slate-500 dark:text-slate-400">
                          {formatDate(review.createdAt)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-8 text-center dark:border-slate-700 dark:bg-slate-900/50">
              <p className="text-slate-600 dark:text-slate-400">
                {selectedAuthor
                  ? "No reviews found for this author."
                  : "No reviews found."}
              </p>
            </div>
          )}
        </div>

        <div className="flex flex-wrap justify-center gap-4">
          <Link
            href="/admin"
            className="cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
          >
            Back to Admin
          </Link>
        </div>
      </div>
    </section>
  );
}
