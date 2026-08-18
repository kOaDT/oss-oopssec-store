"use client";

import { useId, useState } from "react";
import CopyButton from "@/app/login/CopyButton";
import { badgeUrls, GITHUB_REPO } from "@/lib/config";

const BADGE_LINK = `${GITHUB_REPO}#hall-of-fame`;
const BADGE_ALT = "OopsSec Store Hall of Fame";

const FORMATS = ["Markdown", "HTML", "URL"] as const;
type Format = (typeof FORMATS)[number];

const ASSETS = ["Badge", "Social card"] as const;
type Asset = (typeof ASSETS)[number];

/** The pill is sized to sit inline in a line of README badges, so its snippet
 * pins the height; the social card is a full-width image and must not be. */
function snippet(format: Format, url: string, asset: Asset): string {
  switch (format) {
    case "Markdown":
      return `[![${BADGE_ALT}](${url})](${BADGE_LINK})`;
    case "HTML": {
      const size = asset === "Badge" ? ' height="24"' : ' width="600"';
      return `<a href="${BADGE_LINK}"><img src="${url}" alt="${BADGE_ALT}"${size}></a>`;
    }
    case "URL":
      return url;
  }
}

interface BadgePanelProps {
  username: string;
}

/**
 * Hands a Hall of Fame member the embed code for their badge. The badge itself
 * is a static file built from `hall-of-fame/data.json` on the docs deploy, so
 * an entry only added locally points at a URL that does not exist yet — that
 * is the point, the merged pull request is what makes the badge real. The
 * preview hides itself in that case rather than showing a broken image.
 */
export default function BadgePanel({ username }: BadgePanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [format, setFormat] = useState<Format>("Markdown");
  const [asset, setAsset] = useState<Asset>("Badge");
  const [hasPreview, setHasPreview] = useState(true);
  const panelId = useId();

  const { pill, card } = badgeUrls(username);
  const url = asset === "Badge" ? pill : card;
  const code = snippet(format, url, asset);

  return (
    <div className="mt-6 w-full border-t border-slate-200 pt-4 dark:border-slate-700">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-controls={panelId}
        className="mx-auto flex cursor-pointer items-center gap-1.5 text-sm font-medium text-primary-600 transition-colors hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
      >
        {isOpen ? "Hide badge" : "Show badge"}
        <svg
          className={`h-4 w-4 transition-transform ${isOpen ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>

      {/* Always mounted so `aria-controls` resolves; `hidden` keeps it out of
          the accessibility tree and the tab order while collapsed. */}
      <div id={panelId} hidden={!isOpen} className="mt-4 space-y-3 text-left">
        {/* An external SVG badge: the one case next/image cannot serve, since
            optimising it would mean turning on dangerouslyAllowSVG. */}
        {hasPreview && (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={pill}
            alt={BADGE_ALT}
            height={24}
            className="mx-auto block h-6"
            onError={() => setHasPreview(false)}
          />
        )}

        <div
          className="flex gap-1 bg-slate-100 p-1 dark:bg-slate-900"
          style={{ borderRadius: "4px" }}
          role="radiogroup"
          aria-label="Badge asset"
        >
          {ASSETS.map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              onClick={() => setAsset(option)}
              aria-checked={asset === option}
              className={`flex-1 cursor-pointer px-2 py-1 text-xs font-medium transition-colors ${
                asset === option
                  ? "bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100"
                  : "text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
              }`}
              style={{ borderRadius: "4px" }}
            >
              {option}
            </button>
          ))}
        </div>

        <div
          className="flex gap-1 bg-slate-100 p-1 dark:bg-slate-900"
          style={{ borderRadius: "4px" }}
          role="radiogroup"
          aria-label="Badge embed format"
        >
          {FORMATS.map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              onClick={() => setFormat(option)}
              aria-checked={format === option}
              className={`flex-1 cursor-pointer px-2 py-1 text-xs font-medium transition-colors ${
                format === option
                  ? "bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100"
                  : "text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
              }`}
              style={{ borderRadius: "4px" }}
            >
              {option}
            </button>
          ))}
        </div>

        <div
          className="flex items-start gap-2 bg-slate-50 p-2 dark:bg-slate-900"
          style={{ borderRadius: "4px" }}
        >
          <code className="flex-1 overflow-x-auto whitespace-pre text-xs text-slate-600 dark:text-slate-400">
            {code}
          </code>
          <CopyButton text={code} label="badge snippet" />
        </div>

        <a
          href={card}
          target="_blank"
          rel="noopener noreferrer"
          className="block text-center text-xs text-slate-500 underline transition-colors hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
        >
          Open the social card (1200×630)
        </a>
      </div>
    </div>
  );
}
