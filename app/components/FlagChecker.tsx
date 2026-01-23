"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import confetti from "canvas-confetti";

function formatSlugToTitle(slug: string): string {
  return slug
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

const INITIAL_ANIMATION_DURATION = 10000;

interface FlagCheckerProps {
  totalFlags: number;
}

export default function FlagChecker({ totalFlags }: FlagCheckerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [flagInput, setFlagInput] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [foundFlags, setFoundFlags] = useState<string[]>([]);
  const [isInitialAnimation, setIsInitialAnimation] = useState(true);
  const fetchProgress = useCallback(async () => {
    try {
      const response = await fetch("/api/flags/progress");
      if (response.ok) {
        const data = await response.json();
        setFoundFlags(data.foundFlags.map((f: { slug: string }) => f.slug));
      }
    } catch (error) {
      console.error("Error fetching progress:", error);
    }
  }, []);

  useEffect(() => {
    fetchProgress();
  }, [fetchProgress]);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsInitialAnimation(false);
    }, INITIAL_ANIMATION_DURATION);

    return () => clearTimeout(timer);
  }, []);

  const triggerConfetti = () => {
    const duration = 3000;
    const animationEnd = Date.now() + duration;
    const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 0 };

    function randomInRange(min: number, max: number) {
      return Math.random() * (max - min) + min;
    }

    const interval = setInterval(function () {
      const timeLeft = animationEnd - Date.now();

      if (timeLeft <= 0) {
        return clearInterval(interval);
      }

      const particleCount = 50 * (timeLeft / duration);

      confetti({
        ...defaults,
        particleCount,
        origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 },
      });
      confetti({
        ...defaults,
        particleCount,
        origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 },
      });
    }, 250);
  };

  const triggerVictoryCelebration = () => {
    confetti({
      particleCount: 100,
      spread: 70,
      origin: { y: 0.6 },
    });
  };

  const allFlagsFound = foundFlags.length === totalFlags && totalFlags > 0;

  const handleVerify = async () => {
    if (!flagInput.trim()) {
      return;
    }

    setIsVerifying(true);
    setMessage(null);

    try {
      const response = await fetch("/api/flags/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ flag: flagInput.trim() }),
      });

      const data = await response.json();

      if (data.valid) {
        if (data.alreadyFound) {
          setMessage("Flag already found!");
        } else {
          const newFoundFlags = [...foundFlags, data.slug];
          setFoundFlags(newFoundFlags);

          if (newFoundFlags.length === totalFlags) {
            triggerVictoryCelebration();
            setMessage("Congratulations! You found all flags!");
            setTimeout(() => {
              setMessage(null);
            }, 3000);
          } else {
            triggerConfetti();
            setMessage(
              `Congrats! ${newFoundFlags.length}/${totalFlags} flags already found`
            );
            setTimeout(() => {
              setMessage(null);
            }, 2000);
          }
        }
        setFlagInput("");
      } else {
        setMessage("Invalid flag. Try again!");
        setTimeout(() => setMessage(null), 3000);
      }
    } catch (error) {
      console.error("Error verifying flag:", error);
      setMessage("Error verifying flag. Please try again.");
      setTimeout(() => setMessage(null), 3000);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !isVerifying) {
      handleVerify();
    }
  };

  return (
    <>
      <div
        className="fixed bottom-6 right-6 z-50 flex flex-col items-end gap-3 max-w-[calc(100vw-3rem)]"
        onMouseEnter={() => setIsInitialAnimation(false)}
      >
        {isInitialAnimation && (
          <span
            className="whitespace-nowrap rounded-lg bg-slate-900/90 px-3 py-1.5 text-sm font-medium text-white shadow-lg backdrop-blur-sm dark:bg-slate-100/90 dark:text-slate-900"
            style={{
              animation: "fade-in-up 0.5s ease-out",
            }}
          >
            Found a flag? Check it here!
          </span>
        )}
        <div className="relative flex items-center justify-end">
          {isInitialAnimation && (
            <>
              <div
                className="absolute right-0 top-1/2 h-14 w-14 -translate-y-1/2 rounded-full border-2 border-primary-400"
                style={{
                  animation: "ripple-1 2s ease-out infinite",
                }}
              />
              <div
                className="absolute right-0 top-1/2 h-14 w-14 -translate-y-1/2 rounded-full border-2 border-primary-300"
                style={{
                  animation: "ripple-2 2s ease-out infinite 0.3s",
                }}
              />
              <div
                className="absolute right-0 top-1/2 h-14 w-14 -translate-y-1/2 rounded-full border-2 border-primary-200"
                style={{
                  animation: "ripple-3 2s ease-out infinite 0.6s",
                }}
              />
            </>
          )}
          <button
            onClick={() => setIsOpen(true)}
            className="group relative z-10 flex h-14 w-14 cursor-pointer items-center gap-3 overflow-hidden rounded-full bg-primary-600 px-4 text-white shadow-lg transition-all duration-300 hover:w-auto hover:bg-primary-700 hover:shadow-xl focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:bg-primary-500 dark:hover:bg-primary-600"
            style={
              isInitialAnimation
                ? {
                    animation: "button-glow 2s ease-in-out infinite",
                  }
                : undefined
            }
            aria-label="Check flag"
          >
            {allFlagsFound ? (
              <svg
                className="h-6 w-6 shrink-0"
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
            ) : (
              <svg
                className="h-6 w-6 shrink-0"
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
            )}
            {!isInitialAnimation && (
              <span className="whitespace-nowrap text-sm font-medium opacity-0 transition-opacity duration-300 group-hover:opacity-100">
                {allFlagsFound
                  ? "All flags found!"
                  : "Found a flag? Check it here!"}
              </span>
            )}
          </button>
        </div>
      </div>

      {isOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={() => {
            if (!isVerifying) {
              setIsOpen(false);
              setFlagInput("");
              setMessage(null);
            }
          }}
        >
          <div
            className="w-full max-w-md rounded-lg border border-slate-200 bg-white p-6 shadow-xl dark:border-slate-700 dark:bg-slate-800"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <h2
                className={`text-xl font-bold ${
                  allFlagsFound
                    ? "text-yellow-600 dark:text-yellow-400"
                    : "text-slate-900 dark:text-slate-100"
                }`}
              >
                {allFlagsFound ? "All Flags Found" : "Verify Flag"}
              </h2>
              <button
                onClick={() => {
                  if (!isVerifying) {
                    setIsOpen(false);
                    setFlagInput("");
                    setMessage(null);
                  }
                }}
                className="text-slate-400 transition-colors hover:text-slate-600 dark:hover:text-slate-300"
                disabled={isVerifying}
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

            {!allFlagsFound && (
              <div className="mb-4">
                <label
                  htmlFor="flag-input"
                  className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300"
                >
                  Enter flag
                </label>
                <input
                  id="flag-input"
                  type="text"
                  value={flagInput}
                  onChange={(e) => setFlagInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="OSS{...}"
                  className="w-full rounded-lg border border-slate-300 bg-white px-4 py-2 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-primary-400 dark:focus:ring-primary-400"
                  disabled={isVerifying}
                  autoFocus
                />
              </div>
            )}

            {message && (
              <div
                className={`mb-4 rounded-lg p-3 text-sm ${
                  message.includes("all flags")
                    ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400"
                    : message.includes("Congrats")
                      ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
                      : message.includes("already found")
                        ? "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400"
                        : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400"
                }`}
              >
                {message}
              </div>
            )}

            {foundFlags.length > 0 && (
              <div className="mb-4">
                <h3 className="mb-2 text-sm font-medium text-slate-700 dark:text-slate-300">
                  Found flags
                </h3>
                <ul className="max-h-40 overflow-y-auto rounded-lg border border-slate-200 bg-slate-50 dark:border-slate-600 dark:bg-slate-700/50">
                  {foundFlags.map((slug) => (
                    <li
                      key={slug}
                      className="border-b border-slate-200 last:border-b-0 dark:border-slate-600"
                    >
                      <Link
                        href={`/vulnerabilities/${slug}`}
                        className="flex items-center gap-2 px-3 py-2 text-sm text-primary-600 transition-colors hover:bg-slate-100 dark:text-primary-400 dark:hover:bg-slate-600/50"
                        onClick={() => setIsOpen(false)}
                      >
                        <svg
                          className="h-4 w-4 shrink-0 text-green-500"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        <span className="truncate">
                          {formatSlugToTitle(slug)}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {allFlagsFound && (
              <div className="mb-4 rounded-lg border border-yellow-200 bg-yellow-50 p-4 dark:border-yellow-800/50 dark:bg-yellow-900/20">
                <div className="flex items-start gap-3">
                  <svg
                    className="h-5 w-5 shrink-0 text-yellow-600 dark:text-yellow-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                    />
                  </svg>
                  <div className="flex-1">
                    <p className="mb-2 text-sm font-medium text-yellow-800 dark:text-yellow-300">
                      Join the Hall of Fame!
                    </p>
                    <p className="mb-3 text-sm text-yellow-700 dark:text-yellow-400">
                      Add your profile to the Hall of Fame by submitting a Pull
                      Request on GitHub.
                    </p>
                    <a
                      href="https://github.com/kOaDT/oss-oopssec-store/blob/main/hall-of-fame/data.json"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 rounded-lg bg-yellow-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-yellow-700 dark:bg-yellow-500 dark:hover:bg-yellow-600"
                    >
                      <svg
                        className="h-4 w-4"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                        />
                      </svg>
                      Submit PR on GitHub
                    </a>
                  </div>
                </div>
              </div>
            )}

            <div className="flex items-center justify-between">
              <p
                className={`text-sm ${
                  allFlagsFound
                    ? "text-yellow-600 dark:text-yellow-400"
                    : "text-slate-600 dark:text-slate-400"
                }`}
              >
                {foundFlags.length}/{totalFlags} flags found
                {allFlagsFound && " ✓"}
              </p>
              {!allFlagsFound && (
                <button
                  onClick={handleVerify}
                  disabled={isVerifying || !flagInput.trim()}
                  className="rounded-lg cursor-pointer bg-primary-600 px-4 py-2 text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
                >
                  {isVerifying ? "Verifying..." : "Verify"}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
