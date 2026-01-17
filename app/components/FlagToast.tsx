"use client";

import { useState } from "react";
import CopyButton from "../login/CopyButton";

export default function FlagToast() {
  const [flag, setFlag] = useState<string | null>(() => {
    if (typeof window !== "undefined") {
      const pendingFlag = localStorage.getItem("pendingFlag");
      if (pendingFlag) {
        localStorage.removeItem("pendingFlag");
        return pendingFlag;
      }
    }
    return null;
  });
  const [isVisible, setIsVisible] = useState(!!flag);

  const handleDismiss = () => {
    setIsVisible(false);
    setTimeout(() => setFlag(null), 300);
  };

  if (!flag || !isVisible) return null;

  return (
    <div className="fixed left-1/2 top-20 z-50 w-full max-w-md -translate-x-1/2 px-4 animate-fade-in-up">
      <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-xl dark:border-slate-700 dark:bg-slate-800">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <svg
              className="h-6 w-6 text-yellow-500 dark:text-yellow-400"
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
            <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
              Flag Retrieved!
            </h3>
          </div>
          <button
            onClick={handleDismiss}
            className="text-slate-400 transition-colors hover:text-slate-600 dark:hover:text-slate-300"
            aria-label="Dismiss"
          >
            <svg
              className="h-6 w-6"
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
          </button>
        </div>

        <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">
          Congratulations! You successfully brute-forced the login.
        </p>

        <div className="flex items-center gap-2">
          <code className="flex-1 rounded bg-slate-100 px-3 py-2 font-mono text-sm font-bold text-slate-900 dark:bg-slate-700 dark:text-slate-100">
            {flag}
          </code>
          <CopyButton text={flag} label="flag" />
        </div>
      </div>
    </div>
  );
}
