"use client";

import { useState, useEffect, useCallback, FormEvent, useMemo } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { getStoredUser } from "@/lib/client-auth";
import FlagDisplay from "@/app/components/FlagDisplay";

const FLAG = "OSS{x_f0rw4rd3d_f0r_sql1}";

const isValidIp = (ip: string): boolean => {
  // localhost
  if (ip === "unknown") return true;
  if (ip === "localhost") return true;
  if (ip === "::1") return true;
  // IPv4 regex
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // IPv6 regex (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  // Also accept "unknown" as valid
  if (ip === "unknown") return true;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

interface Visit {
  id: string;
  ip: string;
  userAgent: string | null;
  path: string;
  createdAt: string;
}

interface TopIp {
  ip: string;
  count: number;
}

interface AnalyticsData {
  stats: {
    totalVisits: number;
    uniqueVisitors: number;
  };
  topIps: TopIp[];
  visits: Visit[];
}

export default function AnalyticsClient() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterIp, setFilterIp] = useState("");
  const [isFiltering, setIsFiltering] = useState(false);
  const router = useRouter();

  const fetchAnalytics = useCallback(
    async (ip?: string) => {
      try {
        const url = ip
          ? `/api/admin/analytics?ip=${encodeURIComponent(ip)}`
          : "/api/admin/analytics";

        const response = await fetch(url, {
          credentials: "include",
        });

        if (!response.ok) {
          if (response.status === 401) {
            router.push("/login");
            return;
          }
          if (response.status === 403) {
            setError("Forbidden: You do not have administrator privileges.");
            setIsLoading(false);
            return;
          }
          throw new Error("Failed to fetch analytics");
        }

        const analyticsData = await response.json();
        setData(analyticsData);
      } catch (err) {
        console.error("Error fetching analytics:", err);
        setError("An error occurred while fetching analytics data.");
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

    fetchAnalytics();
  }, [router, fetchAnalytics]);

  const handleFilter = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsFiltering(true);
    await fetchAnalytics(filterIp || undefined);
  };

  const handleClearFilter = async () => {
    setFilterIp("");
    setIsFiltering(true);
    await fetchAnalytics();
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  // Check if any IP in the data is not a valid IP address (SQL injection detected)
  const hasInvalidIp = useMemo(() => {
    if (!data?.visits) return false;
    return data.visits.some((visit) => !isValidIp(visit.ip));
  }, [data?.visits]);

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-6xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">
                Loading analytics...
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
              href="/admin"
              className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Back to Admin
            </Link>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-6xl space-y-8">
        {hasInvalidIp && (
          <FlagDisplay
            flag={FLAG}
            title="SQL Injection Detected!"
            description="An invalid IP address was found in the visitor logs. This indicates a successful SQL injection attack via the X-Forwarded-For header."
            showIcon
            variant="default"
          />
        )}
        <div className="grid gap-6 md:grid-cols-2">
          <div className="rounded-2xl bg-white p-6 shadow-sm dark:bg-slate-800">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/30">
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
                    d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                  />
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                  />
                </svg>
              </div>
              <div>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Total Page Views
                </p>
                <p className="text-3xl font-bold text-slate-900 dark:text-slate-100">
                  {data?.stats.totalVisits.toLocaleString() || 0}
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-2xl bg-white p-6 shadow-sm dark:bg-slate-800">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-secondary-100 dark:bg-secondary-900/30">
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
                    d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                  />
                </svg>
              </div>
              <div>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Unique Visitors
                </p>
                <p className="text-3xl font-bold text-slate-900 dark:text-slate-100">
                  {data?.stats.uniqueVisitors.toLocaleString() || 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800">
          <h2 className="mb-6 text-xl font-bold text-slate-900 dark:text-slate-100">
            Top IP Addresses
          </h2>
          {data?.topIps && data.topIps.length > 0 ? (
            <div className="space-y-3">
              {data.topIps.map((item, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900"
                >
                  <code className="text-sm font-mono text-slate-700 dark:text-slate-300">
                    {item.ip}
                  </code>
                  <span className="rounded-full bg-primary-100 px-3 py-1 text-sm font-medium text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">
                    {item.count} visits
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-600 dark:text-slate-400">
              No visitor data yet.
            </p>
          )}
        </div>

        <div className="rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800">
          <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              Recent Visits
            </h2>
            <form onSubmit={handleFilter} className="flex gap-2">
              <input
                type="text"
                value={filterIp}
                onChange={(e) => setFilterIp(e.target.value)}
                placeholder="Filter by IP..."
                className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500"
              />
              <button
                type="submit"
                disabled={isFiltering}
                className="cursor-pointer rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isFiltering ? "..." : "Filter"}
              </button>
              {filterIp && (
                <button
                  type="button"
                  onClick={handleClearFilter}
                  disabled={isFiltering}
                  className="cursor-pointer rounded-lg bg-slate-200 px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-300 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600"
                >
                  Clear
                </button>
              )}
            </form>
          </div>

          {data?.visits && data.visits.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700">
                    <th className="px-4 py-3 font-medium text-slate-700 dark:text-slate-300">
                      Timestamp
                    </th>
                    <th className="px-4 py-3 font-medium text-slate-700 dark:text-slate-300">
                      IP Address
                    </th>
                    <th className="px-4 py-3 font-medium text-slate-700 dark:text-slate-300">
                      Path
                    </th>
                    <th className="px-4 py-3 font-medium text-slate-700 dark:text-slate-300">
                      User Agent
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.visits.map((visit, index) => (
                    <tr
                      key={visit.id || index}
                      className="border-b border-slate-100 dark:border-slate-800"
                    >
                      <td className="px-4 py-3 text-slate-900 dark:text-slate-100">
                        {formatDate(visit.createdAt)}
                      </td>
                      <td className="px-4 py-3">
                        {/* Render IP with HTML support for geo-location badges */}
                        <code
                          className="rounded bg-slate-100 px-2 py-1 text-xs text-slate-700 dark:bg-slate-700 dark:text-slate-300"
                          dangerouslySetInnerHTML={{ __html: visit.ip }}
                        />
                      </td>
                      <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                        {visit.path}
                      </td>
                      <td className="max-w-xs truncate px-4 py-3 text-slate-500 dark:text-slate-400">
                        {visit.userAgent || "N/A"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-slate-600 dark:text-slate-400">
              No visits recorded yet.
            </p>
          )}
        </div>

        <div className="flex justify-center gap-4">
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
