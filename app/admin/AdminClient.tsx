"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import CopyButton from "../login/CopyButton";

interface AdminResponse {
  message: string;
  flag?: string;
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

const getStoredUser = () => {
  if (typeof window === "undefined") return null;
  const storedUser = localStorage.getItem("user");
  if (storedUser) {
    try {
      return JSON.parse(storedUser);
    } catch {
      localStorage.removeItem("user");
      localStorage.removeItem("authToken");
      return null;
    }
  }
  return null;
};

export default function AdminClient() {
  const [data, setData] = useState<AdminResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    const fetchAdmin = async () => {
      try {
        const baseUrl =
          process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
        const token = localStorage.getItem("authToken");

        const response = await fetch(`${baseUrl}/api/admin`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
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
          throw new Error("Failed to fetch admin data");
        }

        const responseData = await response.json();
        setData(responseData);
      } catch (error) {
        console.error("Error fetching admin data:", error);
        setError("An error occurred while fetching admin data.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchAdmin();
  }, [router]);

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">
                Loading admin panel...
              </p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (error) {
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

  if (data?.flag) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800 md:p-12">
            <div className="mb-8 text-center">
              <div className="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/30">
                <svg
                  className="h-8 w-8 text-green-600 dark:text-green-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </div>
              <h2 className="mb-2 text-3xl font-bold text-slate-900 dark:text-slate-100">
                Flag Retrieved!
              </h2>
              <p className="text-slate-600 dark:text-slate-400">
                {data.message}
              </p>
            </div>

            <div className="mb-8 rounded-xl border-2 border-primary-200 bg-primary-50 p-6 dark:border-primary-800 dark:bg-primary-900/20">
              <div className="text-center">
                <p className="mb-2 text-sm font-medium text-slate-700 dark:text-slate-300">
                  Flag
                </p>
                <div className="flex items-center justify-center gap-2">
                  <p className="font-mono text-2xl font-bold text-primary-700 dark:text-primary-300">
                    {data.flag}
                  </p>
                  <CopyButton text={data.flag} label="flag" />
                </div>
              </div>
            </div>

            <div className="flex justify-center">
              <Link
                href="/"
                className="cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                Go to Home
              </Link>
            </div>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-4xl">
        <div className="rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800 md:p-12">
          <div className="mb-8 text-center">
            <div className="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/30">
              <svg
                className="h-8 w-8 text-primary-600 dark:text-primary-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <h2 className="mb-2 text-3xl font-bold text-slate-900 dark:text-slate-100">
              {data?.message || "Welcome"}
            </h2>
            {data?.user && (
              <p className="text-slate-600 dark:text-slate-400">
                Logged in as {data.user.email}
              </p>
            )}
          </div>

          {data?.user && (
            <div className="mb-8 space-y-6 rounded-xl border border-slate-200 bg-slate-50 p-6 dark:border-slate-700 dark:bg-slate-900/50">
              <div className="flex justify-between border-b border-slate-200 pb-4 dark:border-slate-700">
                <span className="font-medium text-slate-700 dark:text-slate-300">
                  User ID
                </span>
                <span className="font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {data.user.id}
                </span>
              </div>
              <div className="flex justify-between border-b border-slate-200 pb-4 dark:border-slate-700">
                <span className="font-medium text-slate-700 dark:text-slate-300">
                  Email
                </span>
                <span className="font-semibold text-slate-900 dark:text-slate-100">
                  {data.user.email}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="font-medium text-slate-700 dark:text-slate-300">
                  Role
                </span>
                <span className="rounded-full bg-primary-100 px-3 py-1 text-sm font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">
                  {data.user.role}
                </span>
              </div>
            </div>
          )}

          <div className="flex justify-center">
            <Link
              href="/"
              className="cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Go to Home
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
