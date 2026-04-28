"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import type { Flag, FlagCategory, FlagDifficulty } from "@/lib/types";
import {
  formatSlug,
  CATEGORY_LABELS,
  getCveUrl,
  getCweUrl,
  getOwaspUrl,
} from "@/lib/format";

interface FlagsClientProps {
  flags: Flag[];
  foundFlagIds: string[];
}

function LockIcon() {
  return (
    <svg
      className="h-3.5 w-3.5"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75M6.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"
      />
    </svg>
  );
}

function LockedFlag() {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2 py-1 font-mono text-xs text-slate-500 dark:bg-slate-700/50 dark:text-slate-400">
      <LockIcon />
      Locked — solve to reveal
    </span>
  );
}

const DIFFICULTY_CONFIG: Record<
  FlagDifficulty,
  { label: string; color: string; bgColor: string; icon: string }
> = {
  EASY: {
    label: "Easy",
    color: "text-emerald-700 dark:text-emerald-400",
    bgColor: "bg-emerald-100 dark:bg-emerald-900/30",
    icon: "○",
  },
  MEDIUM: {
    label: "Medium",
    color: "text-amber-700 dark:text-amber-400",
    bgColor: "bg-amber-100 dark:bg-amber-900/30",
    icon: "◐",
  },
  HARD: {
    label: "Hard",
    color: "text-rose-700 dark:text-rose-400",
    bgColor: "bg-rose-100 dark:bg-rose-900/30",
    icon: "●",
  },
};

function DifficultyBadge({ difficulty }: { difficulty: FlagDifficulty }) {
  const config = DIFFICULTY_CONFIG[difficulty];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${config.bgColor} ${config.color}`}
    >
      <span className="text-[10px]">{config.icon}</span>
      {config.label}
    </span>
  );
}

function CategoryBadge({ category }: { category: FlagCategory }) {
  return (
    <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 dark:bg-slate-700 dark:text-slate-300">
      {CATEGORY_LABELS[category]}
    </span>
  );
}

function SearchIcon() {
  return (
    <svg
      className="h-5 w-5 text-slate-400"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
      />
    </svg>
  );
}

function GridIcon({ active }: { active: boolean }) {
  return (
    <svg
      className={`h-5 w-5 ${active ? "text-primary-600 dark:text-primary-400" : "text-slate-400"}`}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
      />
    </svg>
  );
}

function ListIcon({ active }: { active: boolean }) {
  return (
    <svg
      className={`h-5 w-5 ${active ? "text-primary-600 dark:text-primary-400" : "text-slate-400"}`}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M4 6h16M4 10h16M4 14h16M4 18h16"
      />
    </svg>
  );
}

function FoundBadge() {
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400">
      <svg
        className="h-3 w-3"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={3}
          d="M5 13l4 4L19 7"
        />
      </svg>
      Found
    </span>
  );
}

const BADGE_SIZE_COMPACT = "px-2 py-0.5 text-[10px]";
const BADGE_SIZE_REGULAR = "px-2.5 py-1 text-xs";

function CveBadge({ cve, compact }: { cve: string; compact: boolean }) {
  return (
    <a
      href={getCveUrl(cve)}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      aria-label={`View ${cve} details on NVD (opens in new tab)`}
      className={`relative z-10 rounded-full bg-red-100 font-semibold text-red-700 transition-colors hover:bg-red-200 dark:bg-red-900/30 dark:text-red-400 dark:hover:bg-red-900/50 ${compact ? BADGE_SIZE_COMPACT : BADGE_SIZE_REGULAR}`}
    >
      {cve}
    </a>
  );
}

function CweBadge({ cwe, compact }: { cwe: string; compact: boolean }) {
  const url = getCweUrl(cwe);
  const sizeClass = compact ? BADGE_SIZE_COMPACT : BADGE_SIZE_REGULAR;
  const baseClass = `rounded-full bg-amber-100 font-semibold text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 ${sizeClass}`;
  if (!url) {
    return <span className={baseClass}>{cwe}</span>;
  }
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      aria-label={`View ${cwe} on MITRE (opens in new tab)`}
      className={`relative z-10 transition-colors hover:bg-amber-200 dark:hover:bg-amber-900/50 ${baseClass}`}
    >
      {cwe}
    </a>
  );
}

function OwaspBadge({ owasp, compact }: { owasp: string; compact: boolean }) {
  const url = getOwaspUrl(owasp);
  const sizeClass = compact ? BADGE_SIZE_COMPACT : BADGE_SIZE_REGULAR;
  const baseClass = `rounded-full bg-indigo-100 font-semibold text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300 ${sizeClass}`;
  if (!url) {
    return <span className={baseClass}>OWASP {owasp}</span>;
  }
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      aria-label={`View OWASP ${owasp} on owasp.org (opens in new tab)`}
      className={`relative z-10 transition-colors hover:bg-indigo-200 dark:hover:bg-indigo-900/50 ${baseClass}`}
    >
      OWASP {owasp}
    </a>
  );
}

function FlagCardGrid({ flag, found }: { flag: Flag; found: boolean }) {
  return (
    <div className="group relative flex flex-col rounded-xl border border-slate-200 bg-white p-5 transition-all duration-200 hover:border-primary-300 hover:shadow-xl hover:shadow-primary-500/10 dark:border-slate-700 dark:bg-slate-800/50 dark:hover:border-primary-600">
      <div className="mb-3 flex items-start justify-between gap-2">
        <DifficultyBadge difficulty={flag.difficulty} />
        <div className="flex flex-wrap items-center justify-end gap-1.5">
          {found && <FoundBadge />}
          {flag.cve && <CveBadge cve={flag.cve} compact />}
          {flag.cwe && <CweBadge cwe={flag.cwe} compact />}
          {flag.owasp && <OwaspBadge owasp={flag.owasp} compact />}
        </div>
      </div>

      <h3 className="mb-2 text-base font-bold text-slate-900 transition-colors group-hover:text-primary-600 dark:text-slate-100 dark:group-hover:text-primary-400">
        <Link
          href={`/vulnerabilities/${flag.slug}`}
          className="after:absolute after:inset-0 after:content-['']"
        >
          {formatSlug(flag.slug)}
        </Link>
      </h3>

      <div className="mb-4">
        {found ? (
          <p className="break-all font-mono text-sm text-slate-600 dark:text-slate-400">
            {flag.flag}
          </p>
        ) : (
          <LockedFlag />
        )}
      </div>

      <div className="mt-auto">
        <CategoryBadge category={flag.category} />
      </div>
    </div>
  );
}

function FlagCardList({ flag, found }: { flag: Flag; found: boolean }) {
  return (
    <div className="group relative flex items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 transition-all duration-200 hover:border-primary-300 hover:shadow-lg hover:shadow-primary-500/10 dark:border-slate-700 dark:bg-slate-800/50 dark:hover:border-primary-600 sm:gap-6 sm:p-5">
      <div className="hidden shrink-0 sm:block">
        <DifficultyBadge difficulty={flag.difficulty} />
      </div>

      <div className="min-w-0 flex-1">
        <div className="mb-1 flex items-center gap-2 sm:hidden">
          <DifficultyBadge difficulty={flag.difficulty} />
        </div>
        <h3 className="truncate text-sm font-bold text-slate-900 transition-colors group-hover:text-primary-600 dark:text-slate-100 dark:group-hover:text-primary-400 sm:text-base">
          <Link
            href={`/vulnerabilities/${flag.slug}`}
            className="after:absolute after:inset-0 after:content-['']"
          >
            {formatSlug(flag.slug)}
          </Link>
        </h3>
        {found ? (
          <p className="truncate font-mono text-sm text-slate-600 dark:text-slate-400">
            {flag.flag}
          </p>
        ) : (
          <div className="mt-1">
            <LockedFlag />
          </div>
        )}
      </div>

      <div className="hidden flex-wrap items-center justify-end gap-2 md:flex">
        {found && <FoundBadge />}
        <CategoryBadge category={flag.category} />
        {flag.cve && <CveBadge cve={flag.cve} compact={false} />}
        {flag.cwe && <CweBadge cwe={flag.cwe} compact={false} />}
        {flag.owasp && <OwaspBadge owasp={flag.owasp} compact={false} />}
      </div>

      <svg
        className="h-5 w-5 shrink-0 text-slate-400 transition-transform group-hover:translate-x-1 group-hover:text-primary-600 dark:text-slate-500 dark:group-hover:text-primary-400"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M9 5l7 7-7 7"
        />
      </svg>
    </div>
  );
}

export default function FlagsClient({ flags, foundFlagIds }: FlagsClientProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [difficultyFilter, setDifficultyFilter] = useState<
    FlagDifficulty | "ALL"
  >("ALL");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");

  const foundSet = useMemo(() => new Set(foundFlagIds), [foundFlagIds]);

  const filteredFlags = useMemo(() => {
    return flags.filter((flag) => {
      const isFound = foundSet.has(flag.id);
      const query = searchQuery.toLowerCase();
      const matchesSearch =
        searchQuery === "" ||
        (isFound && flag.flag.toLowerCase().includes(query)) ||
        flag.slug.toLowerCase().includes(query) ||
        (flag.cve?.toLowerCase().includes(query) ?? false) ||
        (flag.cwe?.toLowerCase().includes(query) ?? false) ||
        (flag.owasp?.toLowerCase().includes(query) ?? false);

      const matchesDifficulty =
        difficultyFilter === "ALL" || flag.difficulty === difficultyFilter;

      return matchesSearch && matchesDifficulty;
    });
  }, [flags, searchQuery, difficultyFilter, foundSet]);

  const stats = useMemo(() => {
    const byDifficulty = {
      EASY: flags.filter((f) => f.difficulty === "EASY").length,
      MEDIUM: flags.filter((f) => f.difficulty === "MEDIUM").length,
      HARD: flags.filter((f) => f.difficulty === "HARD").length,
    };
    return { total: flags.length, byDifficulty };
  }, [flags]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-medium text-slate-700 dark:text-slate-300">
            {stats.total} flags
          </span>
          <span className="text-slate-300 dark:text-slate-600">•</span>
          <span className="text-emerald-600 dark:text-emerald-400">
            {stats.byDifficulty.EASY} easy
          </span>
          <span className="text-slate-300 dark:text-slate-600">•</span>
          <span className="text-amber-600 dark:text-amber-400">
            {stats.byDifficulty.MEDIUM} medium
          </span>
          <span className="text-slate-300 dark:text-slate-600">•</span>
          <span className="text-rose-600 dark:text-rose-400">
            {stats.byDifficulty.HARD} hard
          </span>
        </div>
      </div>

      <div className="flex flex-col gap-4 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800/50 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
            <SearchIcon />
          </div>
          <input
            type="text"
            placeholder="Search flags, vulnerabilities, CVEs, CWEs, or OWASP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-slate-50 py-2.5 pl-10 pr-4 text-sm text-slate-900 placeholder-slate-400 transition-colors focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/20 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-primary-400"
          />
        </div>

        <div className="flex items-center gap-3">
          <select
            value={difficultyFilter}
            onChange={(e) =>
              setDifficultyFilter(e.target.value as FlagDifficulty | "ALL")
            }
            aria-label="Filter by difficulty"
            className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm text-slate-900 transition-colors focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/20 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
          >
            <option value="ALL">All difficulties</option>
            <option value="EASY">Easy</option>
            <option value="MEDIUM">Medium</option>
            <option value="HARD">Hard</option>
          </select>

          <div className="flex rounded-lg border border-slate-200 bg-slate-50 p-1 dark:border-slate-600 dark:bg-slate-700">
            <button
              onClick={() => setViewMode("grid")}
              className={`rounded-md p-2 transition-colors ${
                viewMode === "grid"
                  ? "bg-white shadow-sm dark:bg-slate-600"
                  : "hover:bg-slate-100 dark:hover:bg-slate-600"
              }`}
              aria-label="Grid view"
            >
              <GridIcon active={viewMode === "grid"} />
            </button>
            <button
              onClick={() => setViewMode("list")}
              className={`rounded-md p-2 transition-colors ${
                viewMode === "list"
                  ? "bg-white shadow-sm dark:bg-slate-600"
                  : "hover:bg-slate-100 dark:hover:bg-slate-600"
              }`}
              aria-label="List view"
            >
              <ListIcon active={viewMode === "list"} />
            </button>
          </div>
        </div>
      </div>

      {filteredFlags.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-12 text-center dark:border-slate-700 dark:bg-slate-800/50">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-700">
            <svg
              className="h-6 w-6 text-slate-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>
          <p className="text-slate-600 dark:text-slate-400">
            No flags found matching your criteria.
          </p>
          <button
            onClick={() => {
              setSearchQuery("");
              setDifficultyFilter("ALL");
            }}
            className="mt-4 text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
          >
            Clear filters
          </button>
        </div>
      ) : viewMode === "grid" ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filteredFlags.map((flag) => (
            <FlagCardGrid
              key={flag.id}
              flag={flag}
              found={foundSet.has(flag.id)}
            />
          ))}
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFlags.map((flag) => (
            <FlagCardList
              key={flag.id}
              flag={flag}
              found={foundSet.has(flag.id)}
            />
          ))}
        </div>
      )}

      {filteredFlags.length > 0 && filteredFlags.length !== flags.length && (
        <p className="text-center text-sm text-slate-500 dark:text-slate-400">
          Showing {filteredFlags.length} of {flags.length} flags
        </p>
      )}
    </div>
  );
}
