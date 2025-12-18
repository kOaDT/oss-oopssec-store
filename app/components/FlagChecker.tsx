"use client";

import { useState, useEffect } from "react";
import confetti from "canvas-confetti";

const STORAGE_KEY = "oss_found_flags";
const TOTAL_FLAGS_KEY = "oss_total_flags";

interface FlagCheckerProps {
  totalFlags: number;
}

export default function FlagChecker({ totalFlags }: FlagCheckerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [flagInput, setFlagInput] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [foundFlags, setFoundFlags] = useState<string[]>([]);

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const flags = JSON.parse(stored);
        setFoundFlags(Array.isArray(flags) ? flags : []);
      } catch {
        setFoundFlags([]);
      }
    }

    localStorage.setItem(TOTAL_FLAGS_KEY, totalFlags.toString());
  }, [totalFlags]);

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
        const newFoundFlags = [...foundFlags];
        if (!newFoundFlags.includes(data.slug)) {
          newFoundFlags.push(data.slug);
          setFoundFlags(newFoundFlags);
          localStorage.setItem(STORAGE_KEY, JSON.stringify(newFoundFlags));
          triggerConfetti();
          setMessage(
            `Congrats! ${newFoundFlags.length}/${totalFlags} flags already found`
          );
        } else {
          setMessage("Flag already found!");
        }
        setFlagInput("");
        setTimeout(() => {
          setIsOpen(false);
          setMessage(null);
        }, 2000);
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
      <button
        onClick={() => setIsOpen(true)}
        className="group fixed cursor-pointer bottom-6 right-6 z-50 flex h-14 items-center gap-3 overflow-hidden rounded-full bg-primary-600 px-4 text-white shadow-lg transition-all duration-300 hover:w-auto hover:bg-primary-700 hover:shadow-xl focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:bg-primary-500 dark:hover:bg-primary-600 w-14"
        aria-label="Check flag"
      >
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
        <span className="whitespace-nowrap text-sm font-medium opacity-0 transition-opacity duration-300 group-hover:opacity-100">
          Found a flag? Check it here!
        </span>
      </button>

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
              <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                Verify Flag
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

            {message && (
              <div
                className={`mb-4 rounded-lg p-3 text-sm ${
                  message.includes("Congrats")
                    ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
                    : message.includes("already found")
                      ? "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400"
                      : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400"
                }`}
              >
                {message}
              </div>
            )}

            <div className="flex items-center justify-between">
              <p className="text-sm text-slate-600 dark:text-slate-400">
                {foundFlags.length}/{totalFlags} flags found
              </p>
              <button
                onClick={handleVerify}
                disabled={isVerifying || !flagInput.trim()}
                className="rounded-lg cursor-pointer bg-primary-600 px-4 py-2 text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                {isVerifying ? "Verifying..." : "Verify"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
