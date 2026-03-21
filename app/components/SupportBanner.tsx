"use client";

import { useState, useEffect } from "react";

const STORAGE_KEY = "oss_support_dismissed";
const FLAG_BANNER_PREFIX = "oss_support_shown_";

const ACCROCHE_MESSAGES = [
  "Nice catch! If this project helps you learn, a star on GitHub really counts.",
  "Well played! Enjoying the challenge? A GitHub star helps others find it too.",
  "Flag captured! If OopsSec Store is useful to you, consider starring the repo.",
  "Nailed it! A quick star on GitHub helps the project grow.",
  "Great find! Like what you see? A star goes a long way.",
];

function getRandomMessage(): string {
  return ACCROCHE_MESSAGES[
    Math.floor(Math.random() * ACCROCHE_MESSAGES.length)
  ];
}

interface SupportBannerProps {
  flagSlug: string;
  onClose: () => void;
}

export function shouldShowSupportBanner(flagSlug: string): boolean {
  if (typeof window === "undefined") return false;
  if (localStorage.getItem(STORAGE_KEY) === "1") return false;
  if (localStorage.getItem(`${FLAG_BANNER_PREFIX}${flagSlug}`)) return false;
  return true;
}

export function markBannerShownForFlag(flagSlug: string): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(`${FLAG_BANNER_PREFIX}${flagSlug}`, "1");
}

export default function SupportBanner({
  flagSlug,
  onClose,
}: SupportBannerProps) {
  const [isVisible, setIsVisible] = useState(false);
  const [message] = useState(getRandomMessage);

  useEffect(() => {
    markBannerShownForFlag(flagSlug);
    const timer = setTimeout(() => setIsVisible(true), 300);
    return () => clearTimeout(timer);
  }, [flagSlug]);

  const handleClose = () => {
    setIsVisible(false);
    setTimeout(onClose, 300);
  };

  const handleDontShowAgain = () => {
    localStorage.setItem(STORAGE_KEY, "1");
    handleClose();
  };

  return (
    <div
      role="dialog"
      aria-label="Support this project"
      className={`fixed bottom-6 left-1/2 z-40 w-full max-w-lg -translate-x-1/2 px-4 transition-all duration-300 ${
        isVisible ? "translate-y-0 opacity-100" : "translate-y-4 opacity-0"
      }`}
    >
      <div className="animated-border rounded-xl p-5 shadow-2xl">
        <div className="mb-3 flex items-start justify-between gap-3">
          <p className="text-sm leading-relaxed text-slate-700 dark:text-slate-300">
            {message}
          </p>
          <button
            onClick={handleClose}
            className="shrink-0 cursor-pointer text-slate-400 transition-colors hover:text-slate-600 dark:hover:text-slate-300"
            aria-label="Close"
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
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        <div className="mb-3 flex flex-wrap items-center gap-2">
          <a
            href="https://github.com/kOaDT/oss-oopssec-store"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-200"
          >
            <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
            </svg>
            Star on GitHub
          </a>
          <a
            href="https://github.com/users/kOaDT/projects/3/views/6"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-700"
          >
            Contribute
          </a>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
            <a
              href="https://github.com/kOaDT/oss-oopssec-store/fork"
              target="_blank"
              rel="noopener noreferrer"
              className="transition-colors hover:text-slate-700 dark:hover:text-slate-300"
            >
              Fork
            </a>
            <span className="text-slate-300 dark:text-slate-600">|</span>
            <a
              href="https://github.com/kOaDT/oss-oopssec-store/blob/main/hall-of-fame/data.json"
              target="_blank"
              rel="noopener noreferrer"
              className="transition-colors hover:text-slate-700 dark:hover:text-slate-300"
            >
              Hall of Fame
            </a>
          </div>
          <button
            onClick={handleDontShowAgain}
            className="cursor-pointer text-xs text-slate-400 transition-colors hover:text-slate-600 dark:hover:text-slate-300"
          >
            Don&apos;t show again
          </button>
        </div>
      </div>
    </div>
  );
}
