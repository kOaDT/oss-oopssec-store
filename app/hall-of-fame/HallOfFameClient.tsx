"use client";

import { useState, useMemo } from "react";
import Image from "next/image";
import type { HallOfFameEntry } from "@/lib/types";
import { getCountryFlag } from "@/app/hall-of-fame/constants";

function TrophyIcon({ className }: { className?: string }) {
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
        d="M5 3h14a2 2 0 012 2v2a4 4 0 01-4 4h-1v2a4 4 0 01-4 4 4 4 0 01-4-4v-2H7a4 4 0 01-4-4V5a2 2 0 012-2zm7 14v4m-4 0h8"
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

function formatDate(dateString: string): string {
  try {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return dateString;
  }
}

function HallOfFameCard({ entry }: { entry: HallOfFameEntry }) {
  return (
    <article
      className="group relative bg-white shadow-md transition-all duration-300 hover:shadow-2xl dark:bg-slate-800"
      style={{
        borderRadius: "8px",
        animation: "fade-in-up 0.5s ease-out backwards",
      }}
    >
      <div className="flex flex-col items-center px-6 pb-8 pt-12">
        <div className="relative mb-6">
          <div
            className="absolute -inset-1 bg-gradient-to-br from-primary-400 to-secondary-500 opacity-0 blur transition-opacity duration-300 group-hover:opacity-20"
            style={{ borderRadius: "50%" }}
          />
          <Image
            src={entry.avatarUrl}
            alt={`${entry.username}'s avatar`}
            width={120}
            height={120}
            className="relative h-30 w-30 rounded-full border-2 border-white object-cover shadow-lg dark:border-slate-800"
          />
        </div>

        <h3 className="mb-2 text-2xl font-semibold text-slate-900 dark:text-slate-100">
          {entry.username}
        </h3>

        {entry.country && (
          <div className="mb-4 flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
            <span className="text-xl">{getCountryFlag(entry.country)}</span>
            <span>{entry.country}</span>
          </div>
        )}

        <div className="mb-6 text-xs text-slate-500 dark:text-slate-500">
          Joined {formatDate(entry.date)}
        </div>

        <a
          href={entry.githubUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 bg-slate-900 px-6 py-3 text-sm font-medium text-white shadow-md transition-all duration-200 hover:bg-slate-800 hover:shadow-lg dark:bg-slate-700 dark:hover:bg-slate-600"
          style={{ borderRadius: "4px" }}
        >
          <GitHubIcon className="h-4 w-4" />
          View Profile
        </a>
      </div>
    </article>
  );
}

function EmptyState() {
  return (
    <div
      className="border-2 border-dashed border-slate-300 bg-slate-50 p-16 text-center dark:border-slate-700 dark:bg-slate-800/50"
      style={{ borderRadius: "8px" }}
    >
      <div
        className="mx-auto mb-6 flex h-20 w-20 items-center justify-center bg-primary-100 dark:bg-primary-900/30"
        style={{ borderRadius: "8px" }}
      >
        <TrophyIcon className="h-10 w-10 text-primary-600 dark:text-primary-400" />
      </div>
      <h3 className="mb-3 text-2xl font-semibold text-slate-900 dark:text-slate-100">
        No players found
      </h3>
      <p className="mb-8 text-slate-600 dark:text-slate-400">
        Try adjusting your filters to see more results.
      </p>
    </div>
  );
}

interface HallOfFameClientProps {
  entries: HallOfFameEntry[];
}

export default function HallOfFameClient({ entries }: HallOfFameClientProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCountry, setSelectedCountry] = useState<string>("");
  const [sortBy, setSortBy] = useState<"date" | "date-oldest" | "name">("date");

  const countries = useMemo(() => {
    const uniqueCountries = Array.from(
      new Set(entries.map((entry) => entry.country).filter(Boolean) as string[])
    ).sort((a, b) => a.localeCompare(b));
    return uniqueCountries;
  }, [entries]);

  const filteredAndSortedEntries = useMemo(() => {
    const filtered = entries.filter((entry) => {
      const matchesSearch =
        searchQuery === "" ||
        entry.username.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesCountry =
        selectedCountry === "" ||
        (selectedCountry === "No country" && !entry.country) ||
        entry.country === selectedCountry;
      return matchesSearch && matchesCountry;
    });

    if (sortBy === "date") {
      filtered.sort((a, b) => {
        const dateA = new Date(a.date).getTime();
        const dateB = new Date(b.date).getTime();
        return dateB - dateA;
      });
    } else if (sortBy === "date-oldest") {
      filtered.sort((a, b) => {
        const dateA = new Date(a.date).getTime();
        const dateB = new Date(b.date).getTime();
        return dateA - dateB;
      });
    } else {
      filtered.sort((a, b) => a.username.localeCompare(b.username));
    }

    return filtered;
  }, [entries, searchQuery, selectedCountry, sortBy]);

  return (
    <>
      <div
        className="mb-12 bg-white p-6 shadow-md dark:bg-slate-800"
        style={{ borderRadius: "8px" }}
      >
        <div className="grid gap-4 md:grid-cols-3">
          <div>
            <label
              htmlFor="search"
              className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300"
            >
              Search by username
            </label>
            <input
              id="search"
              type="text"
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full border border-slate-300 bg-white px-4 py-2 text-slate-900 shadow-sm transition-colors focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
              style={{ borderRadius: "4px" }}
            />
          </div>

          <div>
            <label
              htmlFor="country"
              className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300"
            >
              Filter by country
            </label>
            <select
              id="country"
              value={selectedCountry}
              onChange={(e) => setSelectedCountry(e.target.value)}
              className="w-full border border-slate-300 bg-white px-4 py-2 text-slate-900 shadow-sm transition-colors focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
              style={{ borderRadius: "4px" }}
            >
              <option value="">All countries</option>
              {entries.some((entry) => !entry.country) && (
                <option value="No country">No country</option>
              )}
              {countries.map((country) => (
                <option key={country} value={country}>
                  {getCountryFlag(country)} {country}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label
              htmlFor="sort"
              className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300"
            >
              Sort by
            </label>
            <select
              id="sort"
              value={sortBy}
              onChange={(e) =>
                setSortBy(e.target.value as "date" | "date-oldest" | "name")
              }
              className="w-full border border-slate-300 bg-white px-4 py-2 text-slate-900 shadow-sm transition-colors focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
              style={{ borderRadius: "4px" }}
            >
              <option value="date">Date added (newest first)</option>
              <option value="date-oldest">Date added (oldest first)</option>
              <option value="name">Name (A-Z)</option>
            </select>
          </div>
        </div>

        {(searchQuery || selectedCountry) && (
          <div className="mt-4 flex items-center gap-2">
            <span className="text-sm text-slate-600 dark:text-slate-400">
              Showing {filteredAndSortedEntries.length} of {entries.length}{" "}
              {entries.length === 1 ? "player" : "players"}
            </span>
            {(searchQuery || selectedCountry) && (
              <button
                onClick={() => {
                  setSearchQuery("");
                  setSelectedCountry("");
                }}
                className="cursor-pointer text-sm text-primary-600 underline hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
              >
                Clear filters
              </button>
            )}
          </div>
        )}
      </div>

      {filteredAndSortedEntries.length > 0 ? (
        <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-3">
          {filteredAndSortedEntries.map((entry) => (
            <HallOfFameCard key={entry.username} entry={entry} />
          ))}
        </div>
      ) : (
        <EmptyState />
      )}
    </>
  );
}
