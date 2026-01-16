"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

function SupportLoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const token = searchParams.get("token");

  useEffect(() => {
    if (!token) {
      return;
    }

    const performSupportLogin = async () => {
      try {
        const response = await fetch(`/api/auth/support-login?token=${token}`, {
          method: "GET",
          credentials: "include",
        });

        const data = await response.json();

        if (!response.ok) {
          setError(data.error || "Failed to authenticate");
          return;
        }

        if (data.token && data.user) {
          localStorage.setItem("authToken", data.token);
          localStorage.setItem("user", JSON.stringify(data.user));
          window.dispatchEvent(new Event("storage"));
          router.push("/profile");
          router.refresh();
        }
      } catch {
        setError("An unexpected error occurred");
      }
    };

    performSupportLogin();
  }, [token, router]);

  if (!token) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-md">
          <div className="rounded-2xl border border-red-200 bg-red-50 p-8 text-center dark:border-red-800/50 dark:bg-red-900/20">
            <h1 className="mb-4 text-xl font-bold text-red-800 dark:text-red-200">
              Support Login Failed
            </h1>
            <p className="text-red-700 dark:text-red-300">
              No support token provided
            </p>
          </div>
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-md">
          <div className="rounded-2xl border border-red-200 bg-red-50 p-8 text-center dark:border-red-800/50 dark:bg-red-900/20">
            <h1 className="mb-4 text-xl font-bold text-red-800 dark:text-red-200">
              Support Login Failed
            </h1>
            <p className="text-red-700 dark:text-red-300">{error}</p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-md">
        <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-lg dark:border-slate-800 dark:bg-slate-800">
          <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
          <h1 className="mb-2 text-xl font-bold text-slate-900 dark:text-slate-100">
            Authenticating...
          </h1>
          <p className="text-slate-600 dark:text-slate-400">
            Please wait while we verify your support access token.
          </p>
        </div>
      </div>
    </section>
  );
}

export default function SupportLoginPage() {
  return (
    <Suspense
      fallback={
        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-md">
            <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-lg dark:border-slate-800 dark:bg-slate-800">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">Loading...</p>
            </div>
          </div>
        </section>
      }
    >
      <SupportLoginContent />
    </Suspense>
  );
}
