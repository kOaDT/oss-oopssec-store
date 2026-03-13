"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";

interface ShareResponse {
  shareUrl: string;
  token: string;
}

export default function ShareOrderButton({ orderId }: { orderId: string }) {
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const handleShare = async () => {
    setError("");
    setIsLoading(true);
    try {
      const data = await api.post<ShareResponse>(
        `/api/orders/${orderId}/share`
      );
      setShareUrl(data.shareUrl);
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : "Failed to generate share link";
      setError(message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!shareUrl) return;
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Failed to copy to clipboard");
    }
  };

  return (
    <div className="w-full sm:w-auto">
      {!shareUrl ? (
        <button
          onClick={handleShare}
          disabled={isLoading}
          className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-xl border-2 border-slate-300 bg-white px-6 py-3 font-semibold text-slate-700 transition-all hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
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
              d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"
            />
          </svg>
          {isLoading ? "Generating..." : "Share Order"}
        </button>
      ) : (
        <div className="w-full space-y-2">
          <div className="flex items-center gap-2">
            <input
              data-share-url
              type="text"
              readOnly
              value={shareUrl}
              className="block w-full min-w-0 rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 text-sm text-slate-700 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300"
            />
            <button
              onClick={handleCopy}
              className="shrink-0 cursor-pointer rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition-all hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Anyone with this link can view the order details.
          </p>
        </div>
      )}
      {error && (
        <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>
      )}
    </div>
  );
}
