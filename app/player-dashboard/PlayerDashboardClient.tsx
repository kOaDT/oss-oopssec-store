"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";

const DOCS_BASE_URL = "https://koadt.github.io/oss-oopssec-store/posts";
const GITHUB_REPO = "https://github.com/kOaDT/oss-oopssec-store";

interface FoundFlag {
  slug: string;
  category: string;
  difficulty: string;
  cve: string | null;
  walkthroughSlug: string | null;
  foundAt: string;
}

interface ProgressData {
  foundFlags: FoundFlag[];
  initializedAt: string | null;
  totalFlags: number;
  statsByCategory: Record<string, number>;
  statsByDifficulty: Record<string, number>;
}

const DIFFICULTY_CONFIG: Record<
  string,
  { label: string; color: string; barColor: string }
> = {
  EASY: {
    label: "EASY",
    color: "text-emerald-400",
    barColor: "bg-emerald-500",
  },
  MEDIUM: {
    label: "MEDIUM",
    color: "text-amber-400",
    barColor: "bg-amber-500",
  },
  HARD: {
    label: "HARD",
    color: "text-rose-400",
    barColor: "bg-rose-500",
  },
};

const CATEGORY_LABELS: Record<string, string> = {
  INJECTION: "INJECTION",
  AUTHENTICATION: "AUTH",
  AUTHORIZATION: "AUTHZ",
  REQUEST_FORGERY: "FORGERY",
  INFORMATION_DISCLOSURE: "INFO_LEAK",
  INPUT_VALIDATION: "INPUT_VAL",
  CRYPTOGRAPHIC: "CRYPTO",
  REMOTE_CODE_EXECUTION: "RCE",
  OTHER: "OTHER",
};

function formatSlug(slug: string): string {
  return slug
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) {
    const remainingHours = hours % 24;
    return remainingHours > 0 ? `${days}d ${remainingHours}h` : `${days}d`;
  }
  if (hours > 0) {
    const remainingMinutes = minutes % 60;
    return remainingMinutes > 0
      ? `${hours}h ${remainingMinutes}m`
      : `${hours}h`;
  }
  if (minutes > 0) {
    return `${minutes}m`;
  }
  return `${seconds}s`;
}

function TerminalBox({
  title,
  children,
  className = "",
}: {
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`overflow-hidden rounded-lg border border-emerald-900/50 bg-slate-900/80 ${className}`}
    >
      <div className="flex items-center gap-2 border-b border-emerald-900/50 bg-slate-900 px-4 py-2">
        <div className="flex gap-1.5">
          <div className="h-3 w-3 rounded-full bg-rose-500/80" />
          <div className="h-3 w-3 rounded-full bg-amber-500/80" />
          <div className="h-3 w-3 rounded-full bg-emerald-500/80" />
        </div>
        <span className="font-mono text-xs text-slate-500">{title}</span>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function CyberProgressRing({
  progress,
  found,
  total,
}: {
  progress: number;
  found: number;
  total: number;
}) {
  const size = 140;
  const strokeWidth = 6;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (progress / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="rotate-[-90deg]" width={size} height={size}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-slate-800"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="text-emerald-500 transition-all duration-1000 ease-out"
            style={{
              filter: "drop-shadow(0 0 6px rgba(16, 185, 129, 0.5))",
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-3xl font-bold text-emerald-400">
            {Math.round(progress)}%
          </span>
        </div>
      </div>
      <div className="mt-4 text-center font-mono">
        <div className="text-2xl font-bold text-white">
          {found}
          <span className="text-slate-600">/</span>
          <span className="text-slate-400">{total}</span>
        </div>
        <div className="text-xs text-slate-500">FLAGS CAPTURED</div>
      </div>
    </div>
  );
}

function StatBar({
  label,
  found,
  total,
  color,
  barColor,
}: {
  label: string;
  found: number;
  total: number;
  color: string;
  barColor: string;
}) {
  const percentage = total > 0 ? (found / total) * 100 : 0;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between font-mono text-xs">
        <span className={color}>{label}</span>
        <span className="text-slate-400">
          {found}/{total}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{
            width: `${percentage}%`,
            boxShadow:
              percentage > 0
                ? `0 0 8px ${barColor.includes("emerald") ? "rgba(16, 185, 129, 0.5)" : barColor.includes("amber") ? "rgba(245, 158, 11, 0.5)" : "rgba(244, 63, 94, 0.5)"}`
                : "none",
          }}
        />
      </div>
    </div>
  );
}

function ExternalLinkIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
      />
    </svg>
  );
}

function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      fill="currentColor"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path
        fillRule="evenodd"
        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
        clipRule="evenodd"
      />
    </svg>
  );
}

export default function PlayerDashboardClient() {
  const [data, setData] = useState<ProgressData | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchProgress = useCallback(async () => {
    try {
      const response = await fetch("/api/flags/progress");
      if (response.ok) {
        const progressData = await response.json();
        setData(progressData);
      }
    } catch (error) {
      console.error("Error fetching progress:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProgress();
  }, [fetchProgress]);

  if (isLoading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
          <span className="font-mono text-sm text-emerald-500">
            LOADING DATA...
          </span>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <TerminalBox title="error.log">
        <div className="font-mono text-rose-400">
          <span className="text-slate-500">[ERROR]</span> Failed to load
          progress data. Connection terminated.
        </div>
      </TerminalBox>
    );
  }

  const { foundFlags, initializedAt, totalFlags, statsByDifficulty } = data;
  const progress = totalFlags > 0 ? (foundFlags.length / totalFlags) * 100 : 0;
  const allFlagsFound = foundFlags.length === totalFlags && totalFlags > 0;

  const foundByDifficulty = foundFlags.reduce(
    (acc, flag) => {
      acc[flag.difficulty] = (acc[flag.difficulty] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const foundByCategory = foundFlags.reduce(
    (acc, flag) => {
      acc[flag.category] = (acc[flag.category] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-3">
        <TerminalBox title="progress.stat" className="lg:col-span-1">
          <CyberProgressRing
            progress={progress}
            found={foundFlags.length}
            total={totalFlags}
          />
          {initializedAt && (
            <div className="mt-4 border-t border-slate-800 pt-4 text-center font-mono text-xs text-slate-500">
              <span className="text-emerald-600">INIT:</span>{" "}
              {new Date(initializedAt).toLocaleDateString("en-US", {
                month: "short",
                day: "numeric",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })}
            </div>
          )}
        </TerminalBox>

        <TerminalBox title="difficulty.breakdown" className="lg:col-span-2">
          <div className="mb-4 font-mono text-xs text-slate-500">
            <span className="text-emerald-500">$</span> cat /var/log/difficulty
          </div>
          <div className="space-y-4">
            {(["EASY", "MEDIUM", "HARD"] as const).map((difficulty) => (
              <StatBar
                key={difficulty}
                label={DIFFICULTY_CONFIG[difficulty].label}
                found={foundByDifficulty[difficulty] || 0}
                total={statsByDifficulty[difficulty] || 0}
                color={DIFFICULTY_CONFIG[difficulty].color}
                barColor={DIFFICULTY_CONFIG[difficulty].barColor}
              />
            ))}
          </div>

          <div className="mt-6 border-t border-slate-800 pt-4">
            <div className="mb-3 font-mono text-xs text-slate-500">
              <span className="text-emerald-500">$</span> cat /var/log/category
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {Object.entries(data.statsByCategory).map(([category, total]) => (
                <StatBar
                  key={category}
                  label={CATEGORY_LABELS[category] || category}
                  found={foundByCategory[category] || 0}
                  total={total}
                  color="text-cyan-400"
                  barColor="bg-cyan-500"
                />
              ))}
            </div>
          </div>
        </TerminalBox>
      </div>

      {foundFlags.length > 0 && (
        <TerminalBox title="captured_flags.log">
          <div className="overflow-x-auto">
            <table className="w-full font-mono text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left text-xs text-slate-500">
                  <th className="pb-3 pr-4">STATUS</th>
                  <th className="pb-3 pr-4">VULNERABILITY</th>
                  <th className="hidden pb-3 pr-4 sm:table-cell">CAT</th>
                  <th className="hidden pb-3 pr-4 md:table-cell">LVL</th>
                  <th className="pb-3 pr-4">T+</th>
                  <th className="pb-3 text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {foundFlags.map((flag, index) => {
                  const timeToFind = initializedAt
                    ? new Date(flag.foundAt).getTime() -
                      new Date(initializedAt).getTime()
                    : 0;
                  const difficultyConfig =
                    DIFFICULTY_CONFIG[flag.difficulty] ||
                    DIFFICULTY_CONFIG.MEDIUM;

                  return (
                    <tr
                      key={flag.slug}
                      className="transition-colors hover:bg-emerald-950/20"
                    >
                      <td className="py-3 pr-4">
                        <span className="inline-flex items-center gap-1.5 text-emerald-400">
                          <span className="inline-block h-2 w-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                          <span className="text-xs">
                            #{String(index + 1).padStart(2, "0")}
                          </span>
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <div>
                          <span className="text-slate-200">
                            {formatSlug(flag.slug)}
                          </span>
                          {flag.cve && (
                            <span className="ml-2 rounded bg-rose-950 px-1.5 py-0.5 text-xs text-rose-400">
                              {flag.cve}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="hidden py-3 pr-4 sm:table-cell">
                        <span className="text-xs text-cyan-400">
                          {CATEGORY_LABELS[flag.category] || flag.category}
                        </span>
                      </td>
                      <td className="hidden py-3 pr-4 md:table-cell">
                        <span className={`text-xs ${difficultyConfig.color}`}>
                          {difficultyConfig.label}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className="text-slate-400">
                          {timeToFind > 0 ? formatDuration(timeToFind) : "—"}
                        </span>
                      </td>
                      <td className="py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <Link
                            href={`/flags/${flag.slug}`}
                            className="rounded border border-emerald-900 px-2 py-1 text-xs text-emerald-400 transition-colors hover:bg-emerald-950"
                          >
                            DOCS
                          </Link>
                          {flag.walkthroughSlug && (
                            <a
                              href={`${DOCS_BASE_URL}/${flag.walkthroughSlug}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 transition-colors hover:bg-slate-800"
                            >
                              WALKTHROUGH
                              <ExternalLinkIcon className="h-3 w-3" />
                            </a>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </TerminalBox>
      )}

      {foundFlags.length === 0 && (
        <TerminalBox title="status.log">
          <div className="py-8 text-center">
            <div className="font-mono">
              <p className="mb-2 text-amber-400">
                [ALERT] No flags captured yet
              </p>
              <p className="mb-6 text-sm text-slate-500">
                Start exploring vulnerabilities to capture your first flag
              </p>
              <Link
                href="/flags"
                className="inline-flex items-center gap-2 rounded border border-emerald-700 bg-emerald-950/50 px-6 py-2 text-sm text-emerald-400 transition-colors hover:bg-emerald-900/50"
              >
                <span className="text-emerald-500">$</span>
                ./start
              </Link>
            </div>
          </div>
        </TerminalBox>
      )}

      {allFlagsFound && (
        <div className="relative overflow-hidden rounded-lg border border-amber-700/50 bg-gradient-to-br from-amber-950/50 to-slate-900 p-6 md:p-8">
          <div className="absolute right-0 top-0 h-32 w-32 bg-[radial-gradient(circle_at_center,rgba(245,158,11,0.15),transparent_70%)]" />

          <div className="relative flex flex-col items-center gap-6 text-center md:flex-row md:items-start md:text-left">
            <pre className="shrink-0 text-amber-500/80 text-[8px] leading-tight">
              {`
   ___________
  |  _______  |
  | |       | |
  | | ELITE | |
  | |_______| |
  |___________|
      |   |
    __|   |__
   |_________|
              `}
            </pre>
            <div className="flex-1">
              <div className="mb-2 font-mono text-xs text-amber-600">
                [MISSION COMPLETE]
              </div>
              <h3 className="mb-2 font-mono text-xl font-bold text-amber-400">
                ALL FLAGS CAPTURED
              </h3>
              <p className="mb-6 font-mono text-sm text-slate-400">
                You have successfully exploited all vulnerabilities. Submit a PR
                to add your name to the Hall of Fame.
              </p>
              <div className="flex flex-wrap justify-center gap-4 md:justify-start">
                <a
                  href={`${GITHUB_REPO}/blob/main/hall-of-fame/data.json`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded border border-amber-700 bg-amber-950/50 px-6 py-2 font-mono text-sm text-amber-400 transition-colors hover:bg-amber-900/50"
                >
                  <GitHubIcon className="h-4 w-4" />
                  JOIN HALL_OF_FAME
                </a>
                <Link
                  href="/hall-of-fame"
                  className="inline-flex items-center gap-2 rounded border border-slate-700 px-6 py-2 font-mono text-sm text-slate-400 transition-colors hover:bg-slate-800"
                >
                  VIEW HALL_OF_FAME
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}

      {!allFlagsFound && foundFlags.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <div className="flex flex-col items-center gap-3 text-center font-mono text-sm sm:flex-row sm:text-left">
            <span className="text-slate-500">[INFO]</span>
            <span className="text-slate-400">
              Capture all {totalFlags} flags to unlock the{" "}
              <Link
                href="/hall-of-fame"
                className="text-emerald-400 hover:underline"
              >
                HALL_OF_FAME
              </Link>{" "}
              and prove your skills.
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
