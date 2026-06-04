"use client";

import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import Link from "next/link";
import { DOCS_ROADMAP_URL, GITHUB_REPO, TUTORIAL_FLAG } from "@/lib/config";

const STORAGE_KEY = "oss_onboarding_seen";
const SEEN_EVENT = "oss:onboarding-seen";

const CODE_CHIP =
  "rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-primary-700 dark:bg-slate-700 dark:text-primary-300";

// External store for the "already onboarded" flag. Reading via
// useSyncExternalStore keeps SSR and the client in sync (the strip never
// renders on the server) without setState-in-effect.
function subscribeSeen(callback: () => void) {
  window.addEventListener("storage", callback);
  window.addEventListener(SEEN_EVENT, callback);
  return () => {
    window.removeEventListener("storage", callback);
    window.removeEventListener(SEEN_EVENT, callback);
  };
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])';

function useFocusTrap<T extends HTMLElement>(active: boolean) {
  const ref = useRef<T>(null);

  useEffect(() => {
    if (!active) return;
    const container = ref.current;
    if (!container) return;

    const previouslyFocused = document.activeElement as HTMLElement | null;

    const handleKey = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const focusable = Array.from(
        container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
      );
      if (focusable.length === 0) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    container.addEventListener("keydown", handleKey);
    return () => {
      container.removeEventListener("keydown", handleKey);
      previouslyFocused?.focus?.();
    };
  }, [active]);

  return ref;
}

export default function OnboardingGuide() {
  const [showGuide, setShowGuide] = useState(false);
  const [showSendoff, setShowSendoff] = useState(false);
  const guideRef = useFocusTrap<HTMLDivElement>(showGuide);
  const sendoffRef = useFocusTrap<HTMLDivElement>(showSendoff);

  const seen = useSyncExternalStore(
    subscribeSeen,
    () => localStorage.getItem(STORAGE_KEY) !== null,
    () => true
  );
  const showStrip = !seen;

  // The closing moment fires once the player validates their practice flag on
  // the real checker (see FlagChecker's tutorial branch).
  useEffect(() => {
    const handleValidated = () => setShowSendoff(true);
    window.addEventListener("oss:tutorial-validated", handleValidated);
    return () =>
      window.removeEventListener("oss:tutorial-validated", handleValidated);
  }, []);

  useEffect(() => {
    if (!showGuide && !showSendoff) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setShowGuide(false);
        setShowSendoff(false);
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [showGuide, showSendoff]);

  const markSeen = () => {
    localStorage.setItem(STORAGE_KEY, "1");
    window.dispatchEvent(new Event(SEEN_EVENT));
  };

  const openGuide = () => {
    markSeen();
    setShowGuide(true);
  };

  // Hand the player their first flag and drop it straight into the real
  // checker, pre-filled, so they only have to hit Verify.
  const startTutorial = () => {
    setShowGuide(false);
    window.dispatchEvent(
      new CustomEvent("oss:open-flag-checker", {
        detail: { prefill: TUTORIAL_FLAG },
      })
    );
  };

  const renderStep = (n: number, title: string, body: React.ReactNode) => (
    <li className="flex gap-3">
      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary-100 text-sm font-bold text-primary-700 dark:bg-primary-900/40 dark:text-primary-300">
        {n}
      </span>
      <div>
        <p className="font-semibold text-slate-900 dark:text-slate-100">
          {title}
        </p>
        <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-400">
          {body}
        </p>
      </div>
    </li>
  );

  const closeIcon = (
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
  );

  const checkIcon = (
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
        d="M4.5 12.75l6 6 9-13.5"
      />
    </svg>
  );

  return (
    <>
      {/* Persistent entry point, subordinate to the flag checker it sits above */}
      <button
        onClick={openGuide}
        aria-label="How it works"
        className="group fixed bottom-24 right-6 z-40 flex h-10 w-10 cursor-pointer items-center justify-center rounded-full border border-slate-200 bg-white/90 text-slate-500 shadow-md backdrop-blur-sm transition-all hover:bg-white hover:text-slate-900 hover:shadow-lg dark:border-slate-700 dark:bg-slate-800/90 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white"
      >
        <svg
          className="h-5 w-5 shrink-0"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <span className="pointer-events-none absolute right-12 top-1/2 -translate-y-1/2 whitespace-nowrap rounded-lg bg-slate-900/90 px-2.5 py-1 text-xs font-medium text-white opacity-0 shadow-lg backdrop-blur-sm transition-opacity duration-200 group-hover:opacity-100 dark:bg-slate-100/90 dark:text-slate-900">
          How it works
        </span>
      </button>

      {/* First-visit welcome strip */}
      {showStrip && (
        <div
          className="fixed right-6 top-24 z-50 w-[calc(100vw-3rem)] max-w-sm"
          style={{ animation: "fade-in-up 0.4s ease-out" }}
        >
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xl dark:border-slate-700 dark:bg-slate-800">
            <div className="flex items-start gap-3">
              <span className="text-2xl leading-none">👋</span>
              <div className="flex-1">
                <p className="text-sm text-slate-700 dark:text-slate-300">
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    New here?
                  </span>{" "}
                  This isn&apos;t a real shop. It hides security flags to
                  capture.
                </p>
                <div className="mt-3 flex items-center gap-2">
                  <button
                    onClick={openGuide}
                    className="cursor-pointer rounded-lg bg-primary-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600"
                  >
                    Take the tour →
                  </button>
                  <button
                    onClick={markSeen}
                    className="cursor-pointer rounded-lg px-3 py-1.5 text-sm font-medium text-slate-500 transition-colors hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
              <button
                onClick={markSeen}
                aria-label="Dismiss"
                className="cursor-pointer text-slate-400 transition-colors hover:text-slate-600 dark:hover:text-slate-300"
              >
                {closeIcon}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Steps modal */}
      {showGuide && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={() => setShowGuide(false)}
        >
          <div
            ref={guideRef}
            role="dialog"
            aria-modal="true"
            aria-label="How it works"
            className="max-h-[85vh] w-full max-w-lg overflow-y-auto rounded-lg border border-slate-200 bg-white p-6 shadow-xl dark:border-slate-700 dark:bg-slate-800"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-5 flex items-start justify-between gap-4">
              <div>
                <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                  How it works
                </h2>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                  This looks like a normal grocery store. It&apos;s actually a
                  deliberately vulnerable app. Break it and capture the hidden
                  flags.
                </p>
              </div>
              <button
                onClick={() => setShowGuide(false)}
                aria-label="Close"
                className="shrink-0 cursor-pointer text-slate-400 transition-colors hover:text-slate-600 dark:hover:text-slate-300"
              >
                {closeIcon}
              </button>
            </div>

            <ol className="space-y-4">
              {renderStep(
                1,
                "Explore & poke around",
                "Every page may hide a vulnerability: broken auth, injections, logic flaws."
              )}
              {renderStep(
                2,
                "Capture a flag",
                <>
                  Exploit one and you&apos;ll uncover a flag like{" "}
                  <code className={CODE_CHIP}>{"OSS{...}"}</code>.
                </>
              )}
              {renderStep(
                3,
                "Validate it",
                <>
                  Here&apos;s your first one:{" "}
                  <code className={CODE_CHIP}>{TUTORIAL_FLAG}</code>. Hit the
                  button below and we&apos;ll load it straight into the checker.
                </>
              )}
              {renderStep(
                4,
                "Follow the roadmap",
                <>
                  New to AppSec? The{" "}
                  <a
                    href={DOCS_ROADMAP_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium text-primary-600 hover:underline dark:text-primary-400"
                  >
                    roadmap
                  </a>{" "}
                  orders challenges from easy to hard.
                </>
              )}
            </ol>

            <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-4 text-sm">
                <Link
                  href="/flags"
                  onClick={() => setShowGuide(false)}
                  className="font-medium text-primary-600 hover:underline dark:text-primary-400"
                >
                  Browse challenges
                </Link>
              </div>
              <button
                onClick={startTutorial}
                autoFocus
                className="cursor-pointer rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                Validate my first flag →
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Closing send-off */}
      {showSendoff && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={() => setShowSendoff(false)}
        >
          <div
            ref={sendoffRef}
            role="dialog"
            aria-modal="true"
            aria-label="You're all set"
            className="w-full max-w-md rounded-lg border border-slate-200 bg-white p-6 text-center shadow-xl dark:border-slate-700 dark:bg-slate-800"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-primary-100 text-primary-600 dark:bg-primary-900/40 dark:text-primary-400">
              {checkIcon}
            </div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              You&apos;re all set
            </h2>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
              Practice flag captured. That&apos;s the exact loop. Real flags are
              hidden across the store, so go break things. Good luck!
            </p>
            <p className="mt-4 text-sm text-slate-600 dark:text-slate-400">
              Enjoying OSS? A ⭐ on GitHub keeps it growing.
            </p>
            <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:justify-center">
              <a
                href={GITHUB_REPO}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100"
              >
                Star on GitHub
              </a>
              <button
                onClick={() => setShowSendoff(false)}
                autoFocus
                className="cursor-pointer rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
              >
                Start hacking
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
