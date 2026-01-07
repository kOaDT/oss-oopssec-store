"use client";

import CopyButton from "../login/CopyButton";

interface FlagDisplayProps {
  flag: string;
  title?: string;
  description?: string;
  showIcon?: boolean;
  variant?: "default" | "compact" | "minimal";
  className?: string;
}

export default function FlagDisplay({
  flag,
  title = "Flag Retrieved!",
  description,
  showIcon = false,
  variant = "default",
  className = "",
}: FlagDisplayProps) {
  const baseClasses =
    "rounded-xl border-2 border-primary-200 bg-primary-50 p-6 dark:border-primary-800 dark:bg-primary-900/20";
  const containerClasses = variant === "compact" ? "mb-6" : "mb-8";

  if (variant === "minimal") {
    return (
      <div className={`${baseClasses} ${containerClasses} ${className}`}>
        <h3 className="mb-4 text-lg font-semibold text-primary-900 dark:text-primary-100">
          {title}
        </h3>
        <p className="font-mono text-xl font-bold text-slate-900 dark:text-slate-100">
          {flag}
        </p>
      </div>
    );
  }

  return (
    <div className={`${baseClasses} ${containerClasses} ${className}`}>
      <div className="text-center">
        {showIcon && (
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
        )}
        {title && (
          <h3
            className={`mb-2 font-bold text-slate-900 dark:text-slate-100 ${
              variant === "compact" ? "text-lg" : "text-2xl"
            }`}
          >
            {title}
          </h3>
        )}
        {description && (
          <p className="mb-4 text-slate-600 dark:text-slate-400">
            {description}
          </p>
        )}
        <div className="flex items-center justify-center gap-2">
          <p
            className={`font-mono font-bold text-primary-700 dark:text-primary-300 ${
              variant === "compact" ? "text-lg" : "text-2xl"
            }`}
          >
            {flag}
          </p>
          <CopyButton text={flag} label="flag" />
        </div>
      </div>
    </div>
  );
}
