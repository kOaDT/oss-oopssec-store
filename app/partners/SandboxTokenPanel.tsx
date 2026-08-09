"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { getBaseUrl } from "@/lib/config";

interface SandboxToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
  partner_id: string;
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");

  // The Clipboard API is unavailable outside a secure context, which is exactly
  // how this lab gets served when it runs on a LAN address over plain HTTP.
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setStatus("copied");
    } catch {
      setStatus("failed");
    }
    setTimeout(() => setStatus("idle"), 2000);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={label}
      className="cursor-pointer rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300 transition-colors hover:bg-slate-700"
    >
      <span aria-live="polite">
        {status === "copied"
          ? "Copied"
          : status === "failed"
            ? "Failed"
            : "Copy"}
      </span>
    </button>
  );
}

export default function SandboxTokenPanel() {
  const [token, setToken] = useState<SandboxToken | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = async () => {
    setIsLoading(true);
    setError(null);

    try {
      setToken(await api.post<SandboxToken>("/api/partner/sandbox-token"));
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Could not reach the token endpoint. Please try again."
      );
    } finally {
      setIsLoading(false);
    }
  };

  const curlCommand = token
    ? `curl -H "Authorization: Bearer ${token.access_token}" \\\n  ${getBaseUrl()}/api/partner/orders`
    : "";

  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 dark:border-slate-700 dark:bg-slate-800/50 md:p-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
            Try it with a sandbox token
          </h3>
          <p className="mt-2 max-w-xl text-sm leading-relaxed text-slate-600 dark:text-slate-400">
            Sandbox tokens are scoped to a demo partner account preloaded with
            fake purchase orders. They are issued instantly, expire after an
            hour, and never touch production data.
          </p>
        </div>
        <button
          type="button"
          onClick={handleGenerate}
          disabled={isLoading}
          className="shrink-0 cursor-pointer rounded-lg bg-primary-600 px-5 py-3 text-sm font-semibold text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isLoading ? "Issuing…" : "Generate sandbox token"}
        </button>
      </div>

      {error && (
        <div className="mt-6 rounded-lg border border-red-200 bg-red-50 p-3 dark:border-red-800/50 dark:bg-red-900/20">
          <p className="text-sm font-medium text-red-800 dark:text-red-200">
            {error}
          </p>
        </div>
      )}

      {token && (
        <div className="mt-6 space-y-4">
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              ["Partner ID", token.partner_id],
              ["Type", token.token_type],
              ["Scope", token.scope],
              ["Expires in", `${token.expires_in}s`],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  {label}
                </dt>
                <dd className="mt-1 font-mono text-sm text-slate-900 dark:text-slate-100">
                  {value}
                </dd>
              </div>
            ))}
          </dl>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <div className="mb-2 flex items-center justify-between gap-4">
              <span className="font-mono text-xs uppercase tracking-wide text-slate-500">
                access_token
              </span>
              <CopyButton
                value={token.access_token}
                label="Copy access token"
              />
            </div>
            <p className="break-all font-mono text-xs leading-relaxed text-primary-300">
              {token.access_token}
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <div className="mb-2 flex items-center justify-between gap-4">
              <span className="font-mono text-xs uppercase tracking-wide text-slate-500">
                First call
              </span>
              <CopyButton value={curlCommand} label="Copy curl command" />
            </div>
            <pre className="overflow-x-auto font-mono text-xs leading-relaxed text-slate-200">
              {curlCommand}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
