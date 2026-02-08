"use client";

import { useState, useCallback } from "react";
import type { HintState, RevealedHint } from "@/lib/types";

function formatSlugToTitle(slug: string): string {
  return slug
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

const DIFFICULTY_COLORS = {
  EASY: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400",
  MEDIUM:
    "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400",
  HARD: "bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-400",
} as const;

interface HintPanelProps {
  initialState: HintState;
}

export default function HintPanel({ initialState }: HintPanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [hintState, setHintState] = useState<HintState>(initialState);
  const [isRevealing, setIsRevealing] = useState(false);

  const refreshHintState = useCallback(async () => {
    try {
      const response = await fetch("/api/hints/current");
      if (response.ok) {
        setHintState(await response.json());
      }
    } catch (error) {
      console.error("Error fetching hint state:", error);
    }
  }, []);

  const handleRevealHint = async () => {
    setIsRevealing(true);
    try {
      const response = await fetch("/api/hints/reveal", { method: "POST" });
      if (response.ok) {
        const data = await response.json();
        setHintState((prev) => ({
          ...prev,
          revealedHints: [...prev.revealedHints, data.hint as RevealedHint],
          nextHintLevel: data.nextHintLevel,
        }));
      }
    } catch (error) {
      console.error("Error revealing hint:", error);
    } finally {
      setIsRevealing(false);
    }
  };

  const handleOpen = () => {
    refreshHintState();
    setIsOpen(true);
  };

  return (
    <>
      <div className="fixed bottom-6 left-6 z-50">
        <button
          onClick={handleOpen}
          className="group relative z-10 flex h-14 w-14 cursor-pointer items-center gap-3 overflow-hidden rounded-full bg-amber-500 px-4 text-white shadow-lg transition-all duration-300 hover:w-auto hover:bg-amber-600 hover:shadow-xl focus:outline-none focus:ring-2 focus:ring-amber-400 focus:ring-offset-2 dark:bg-amber-600 dark:hover:bg-amber-700"
          aria-label="Get a hint"
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
              d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5.002 5.002 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
            />
          </svg>
          <span className="whitespace-nowrap text-sm font-medium opacity-0 transition-opacity duration-300 group-hover:opacity-100">
            {hintState.allFlagsFound ? "All done!" : "Need a hint?"}
          </span>
        </button>
      </div>

      {isOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={() => setIsOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-lg border border-slate-200 bg-white p-6 shadow-xl dark:border-slate-700 dark:bg-slate-800"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                {hintState.allFlagsFound ? "All Flags Found!" : "Hints"}
              </h2>
              <button
                onClick={() => setIsOpen(false)}
                className="cursor-pointer text-slate-400 transition-colors hover:text-slate-600 dark:hover:text-slate-300"
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

            {hintState.allFlagsFound ? (
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800 dark:border-emerald-800/50 dark:bg-emerald-900/20 dark:text-emerald-400">
                Congratulations! You found all the flags. No more hints needed!
              </div>
            ) : hintState.activeFlag ? (
              <>
                <div className="mb-4 flex items-center gap-2">
                  <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                    {formatSlugToTitle(hintState.activeFlag.slug)}
                  </span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-medium ${DIFFICULTY_COLORS[hintState.activeFlag.difficulty]}`}
                  >
                    {hintState.activeFlag.difficulty}
                  </span>
                </div>

                {hintState.revealedHints.length > 0 ? (
                  <div className="mb-4 space-y-3">
                    {hintState.revealedHints.map((hint) => (
                      <div
                        key={hint.level}
                        className="rounded-lg border border-amber-200 bg-amber-50 p-3 dark:border-amber-800/50 dark:bg-amber-900/20"
                      >
                        <div className="mb-1 flex items-center gap-2">
                          <span className="text-xs font-semibold text-amber-600 dark:text-amber-400">
                            Hint {hint.level}
                          </span>
                          <div className="flex gap-0.5">
                            {[1, 2, 3].map((i) => (
                              <div
                                key={i}
                                className={`h-1.5 w-3 rounded-full ${
                                  i <= hint.level
                                    ? "bg-amber-400 dark:bg-amber-500"
                                    : "bg-amber-200 dark:bg-amber-800"
                                }`}
                              />
                            ))}
                          </div>
                        </div>
                        <p className="text-sm text-amber-800 dark:text-amber-300">
                          {hint.content}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">
                    No hints revealed yet. Click below to get your first hint!
                  </p>
                )}

                <div className="flex items-center justify-between">
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    {hintState.revealedHints.length}/3 hints used
                  </p>
                  {hintState.nextHintLevel ? (
                    <button
                      onClick={handleRevealHint}
                      disabled={isRevealing}
                      className="cursor-pointer rounded-lg bg-amber-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-amber-600 focus:outline-none focus:ring-2 focus:ring-amber-400 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-amber-600 dark:hover:bg-amber-700"
                    >
                      {isRevealing
                        ? "Revealing..."
                        : `Reveal hint ${hintState.nextHintLevel}`}
                    </button>
                  ) : (
                    <span className="text-sm text-slate-400 dark:text-slate-500">
                      All hints revealed
                    </span>
                  )}
                </div>
              </>
            ) : null}
          </div>
        </div>
      )}
    </>
  );
}
