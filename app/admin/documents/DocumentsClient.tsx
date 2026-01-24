"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { getBaseUrl } from "@/lib/config";
import { getStoredUser } from "@/lib/client-auth";

interface FileEntry {
  name: string;
  type: "file" | "directory";
  size: number;
  modified: string;
}

interface DirectoryListing {
  path: string;
  items: FileEntry[];
}

interface FileContent {
  filename: string;
  content: string;
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

export default function DocumentsClient() {
  const [directoryListing, setDirectoryListing] =
    useState<DirectoryListing | null>(null);
  const [currentPath, setCurrentPath] = useState("");
  const [fileContent, setFileContent] = useState<FileContent | null>(null);
  const [pdfUrl, setPdfUrl] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [accessDenied, setAccessDenied] = useState(false);
  const [fileName, setFileName] = useState("");
  const router = useRouter();

  const fetchDirectoryListing = async (path: string) => {
    const baseUrl = getBaseUrl();
    const token = localStorage.getItem("authToken");
    const response = await fetch(
      `${baseUrl}/api/files?list=true&path=${encodeURIComponent(path)}`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    if (!response.ok) throw new Error("Failed to fetch directory listing");
    return response.json();
  };

  const fetchFile = async (file: string) => {
    setIsLoading(true);
    setError(null);
    setPdfUrl(null);
    setFileContent(null);

    try {
      const baseUrl = getBaseUrl();
      const token = localStorage.getItem("authToken");

      if (file.toLowerCase().endsWith(".pdf")) {
        setPdfUrl(
          `${baseUrl}/api/files?file=${encodeURIComponent(file)}&token=${token}`
        );
        setIsLoading(false);
        return;
      }

      const response = await fetch(
        `${baseUrl}/api/files?file=${encodeURIComponent(file)}`,
        {
          headers: { Authorization: `Bearer ${token}` },
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
    } finally {
      setIsLoading(false);
    }
  };

  const navigateToDirectory = async (path: string) => {
    setCurrentPath(path);
    setFileContent(null);
    setPdfUrl(null);
    setError(null);
    try {
      const listing = await fetchDirectoryListing(path);
      setDirectoryListing(listing);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load directory");
    }
  };

  const handleItemClick = (item: FileEntry) => {
    if (item.type === "directory") {
      const newPath = currentPath ? `${currentPath}/${item.name}` : item.name;
      navigateToDirectory(newPath);
    } else {
      const filePath = currentPath ? `${currentPath}/${item.name}` : item.name;
      setFileName(filePath);
      fetchFile(filePath);
    }
  };

  const navigateUp = () => {
    const parts = currentPath.split("/").filter(Boolean);
    parts.pop();
    navigateToDirectory(parts.join("/"));
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

        const listing = await fetchDirectoryListing("");
        setDirectoryListing(listing);
        setIsLoading(false);
      } catch {
        setAccessDenied(true);
        setIsLoading(false);
      }
    };

    checkAccess();
  }, [router]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (fileName) {
      fetchFile(fileName);
    }
  };

  if (isLoading && !directoryListing) {
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
            filename or browse the file listing below.
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
                disabled={isLoading || !fileName}
                className="cursor-pointer rounded-lg bg-primary-600 px-6 py-2 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                {isLoading ? "Loading..." : "Load File"}
              </button>
            </div>
          </form>

          {directoryListing && (
            <div className="mb-6 rounded-lg border border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-900/50">
              <div className="flex items-center gap-2 border-b border-slate-200 bg-slate-100 px-4 py-2 dark:border-slate-700 dark:bg-slate-800">
                {currentPath && (
                  <button
                    onClick={navigateUp}
                    className="cursor-pointer rounded px-2 py-1 text-primary-600 hover:bg-slate-200 dark:text-primary-400 dark:hover:bg-slate-700"
                    title="Go up"
                  >
                    <svg
                      className="h-5 w-5"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M15 19l-7-7 7-7"
                      />
                    </svg>
                  </button>
                )}
                <span className="font-mono text-sm text-slate-700 dark:text-slate-300">
                  /{currentPath || "documents"}
                </span>
              </div>
              <ul className="divide-y divide-slate-200 dark:divide-slate-700">
                {directoryListing.items.length === 0 ? (
                  <li className="px-4 py-3 text-slate-500 dark:text-slate-400">
                    Empty directory
                  </li>
                ) : (
                  directoryListing.items.map((item) => (
                    <li
                      key={item.name}
                      onClick={() => handleItemClick(item)}
                      className="flex cursor-pointer items-center gap-3 px-4 py-3 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      {item.type === "directory" ? (
                        <svg
                          className="h-5 w-5 text-yellow-500"
                          fill="currentColor"
                          viewBox="0 0 20 20"
                        >
                          <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                        </svg>
                      ) : (
                        <svg
                          className="h-5 w-5 text-slate-400"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                          />
                        </svg>
                      )}
                      <span className="flex-1 text-slate-900 dark:text-slate-100">
                        {item.name}
                      </span>
                      <span className="text-sm text-slate-500 dark:text-slate-400">
                        {item.type === "file" ? formatFileSize(item.size) : ""}
                      </span>
                    </li>
                  ))
                )}
              </ul>
            </div>
          )}

          {error && (
            <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
              <p className="text-sm font-medium text-red-800 dark:text-red-400">
                Error: {error}
              </p>
            </div>
          )}

          {pdfUrl && (
            <div className="rounded-lg border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900">
              <div className="border-b border-slate-200 bg-slate-100 px-4 py-2 dark:border-slate-700 dark:bg-slate-800">
                <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  PDF: <span className="font-mono">{fileName}</span>
                </p>
              </div>
              <div className="p-4">
                <iframe
                  src={pdfUrl}
                  className="h-[600px] w-full rounded border border-slate-200 dark:border-slate-700"
                  title={fileName}
                />
              </div>
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
