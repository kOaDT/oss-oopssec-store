"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { getBaseUrl } from "@/lib/config";
import { getStoredUser } from "@/lib/client-auth";

interface FileContent {
  filename: string;
  content: string;
}

export default function DocumentsClient() {
  const [fileContent, setFileContent] = useState<FileContent | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [accessDenied, setAccessDenied] = useState(false);
  const [fileName, setFileName] = useState("readme.txt");
  const router = useRouter();

  const fetchFile = async (file: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const baseUrl = getBaseUrl();
      const token = localStorage.getItem("authToken");
      const response = await fetch(
        `${baseUrl}/api/files?file=${encodeURIComponent(file)}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to fetch file");
      }

      const data = await response.json();
      setFileContent(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load file");
      setFileContent(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const checkAccess = async () => {
      const user = getStoredUser();
      if (!user) {
        router.push("/login");
        return;
      }

      const baseUrl = getBaseUrl();
      const token = localStorage.getItem("authToken");

      try {
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
            setAccessDenied(true);
            setIsLoading(false);
            return;
          }
        }

        fetchFile("readme.txt");
      } catch {
        setAccessDenied(true);
        setIsLoading(false);
      }
    };

    checkAccess();
  }, [router]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchFile(fileName);
  };

  if (isLoading && !fileContent) {
    return (
      <div className="mx-auto max-w-4xl">
        <div className="flex items-center justify-center py-20">
          <div className="text-center">
            <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
            <p className="text-slate-600 dark:text-slate-400">
              Loading documents...
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (accessDenied) {
    return (
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
          <p className="mb-8 text-slate-600 dark:text-slate-400">
            You do not have administrator privileges to access this page.
          </p>
          <Link
            href="/"
            className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
          >
            Go to Home
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-8 rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800 md:p-12">
        <div className="mb-6">
          <h2 className="mb-4 text-2xl font-bold text-slate-900 dark:text-slate-100">
            Document Repository
          </h2>
          <p className="mb-6 text-slate-600 dark:text-slate-400">
            Access and view documents from the secure repository. Enter a
            filename to load its contents.
          </p>

          <form onSubmit={handleSubmit} className="mb-6">
            <div className="flex gap-2">
              <input
                type="text"
                value={fileName}
                onChange={(e) => setFileName(e.target.value)}
                placeholder="Enter filename (e.g., readme.txt)"
                className="flex-1 rounded-lg border border-slate-300 bg-white px-4 py-2 text-slate-900 shadow-sm focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:focus:border-primary-400"
              />
              <button
                type="submit"
                disabled={isLoading}
                className="rounded-lg bg-primary-600 px-6 py-2 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                {isLoading ? "Loading..." : "Load File"}
              </button>
            </div>
          </form>

          {error && (
            <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
              <p className="text-sm font-medium text-red-800 dark:text-red-400">
                Error: {error}
              </p>
            </div>
          )}

          {fileContent && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-900/50">
              <div className="border-b border-slate-200 bg-slate-100 px-4 py-2 dark:border-slate-700 dark:bg-slate-800">
                <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  File:{" "}
                  <span className="font-mono">{fileContent.filename}</span>
                </p>
              </div>
              <div className="p-4">
                <pre className="whitespace-pre-wrap break-words font-mono text-sm text-slate-800 dark:text-slate-200">
                  {fileContent.content}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
