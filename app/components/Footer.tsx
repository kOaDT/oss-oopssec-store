import Link from "next/link";
import packageJson from "../../package.json";
import {
  DEV_TO_URL,
  DOCS_ROADMAP_URL,
  GITHUB_REPO,
  MEDIUM_URL,
  THM_ROOM_URL,
} from "@/lib/config";

const GITHUB_ISSUES = `${GITHUB_REPO}/issues`;
const GITHUB_DISCUSSIONS = `${GITHUB_REPO}/discussions`;
const WALKTHROUGHS_URL = "https://koadt.github.io/oss-oopssec-store/";

type FooterLink = {
  label: string;
  href: string;
  external?: boolean;
};

/** In-app pages that double as challenge entry points. */
const ATTACK_SURFACE: FooterLink[] = [
  { label: "All Products", href: "/" },
  { label: "Contact Support", href: "/support" },
  { label: "AI Assistant", href: "/support/ai-assistant" },
  { label: "News", href: "/news" },
  { label: "Live Stream", href: "/live" },
  { label: "Partner API", href: "/partners" },
  { label: "Admin", href: "/admin" },
];

const PROGRESS: FooterLink[] = [
  { label: "Roadmap", href: DOCS_ROADMAP_URL, external: true },
  { label: "Flags", href: "/flags" },
  { label: "Player Dashboard", href: "/player-dashboard" },
  { label: "Hall of Fame", href: "/hall-of-fame" },
];

const COMMUNITY: FooterLink[] = [
  { label: "TryHackMe room", href: THM_ROOM_URL, external: true },
  { label: "Walkthroughs", href: WALKTHROUGHS_URL, external: true },
  { label: "Issues", href: GITHUB_ISSUES, external: true },
  { label: "Discussions", href: GITHUB_DISCUSSIONS, external: true },
];

const LINK_CLASS =
  "text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400";

function FooterColumn({
  title,
  links,
}: {
  title: string;
  links: FooterLink[];
}) {
  return (
    <div>
      <h4 className="mb-4 font-semibold text-slate-900 dark:text-slate-100">
        {title}
      </h4>
      <ul className="space-y-3 text-sm">
        {links.map(({ label, href, external }) => (
          <li key={href}>
            {external ? (
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className={LINK_CLASS}
              >
                {label}
              </a>
            ) : (
              <Link href={href} className={LINK_CLASS}>
                {label}
              </Link>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function Footer() {
  return (
    <footer className="border-t border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <h3 className="mb-4 text-xl font-bold text-primary-600 dark:text-primary-400">
              OSS – OopsSec Store
            </h3>
            <p className="mb-6 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
              A vulnerable e-commerce application designed for modern web
              security training and educational purposes.
            </p>
            <div className="flex gap-4">
              <a
                href={GITHUB_REPO}
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 transition-colors hover:text-primary-600 dark:hover:text-primary-400"
                aria-label="GitHub Repository"
              >
                <svg
                  className="h-6 w-6"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    fillRule="evenodd"
                    d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                    clipRule="evenodd"
                  />
                </svg>
              </a>
              <a
                href={DEV_TO_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 transition-colors hover:text-primary-600 dark:hover:text-primary-400"
                aria-label="DEV Community Profile"
              >
                <svg
                  className="h-6 w-6"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M7.826 10.083a.784.784 0 0 0-.468-.175h-.701v4.198h.701a.786.786 0 0 0 .469-.175c.155-.117.233-.292.233-.525v-2.798c.001-.233-.079-.408-.234-.525zM19.236 3H4.764C3.79 3 3.001 3.787 3 4.76v14.48c.001.973.79 1.76 1.764 1.76h14.473c.974 0 1.762-.787 1.763-1.76V4.76A1.765 1.765 0 0 0 19.236 3zM9.195 13.414c0 .755-.466 1.901-1.942 1.898H5.389V8.665h1.903c1.424 0 1.902 1.144 1.903 1.899v2.85zm4.045-3.562H11.1v1.544h1.309v1.188H11.1v1.543h2.142v1.188h-2.498a.813.813 0 0 1-.833-.792V9.497a.813.813 0 0 1 .792-.832h2.539l-.002 1.187zm4.165 4.632c-.531 1.235-1.481.99-1.906 0l-1.548-5.818h1.309l1.193 4.569 1.188-4.569h1.31l-1.546 5.818z" />
                </svg>
              </a>
              <a
                href={MEDIUM_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 transition-colors hover:text-primary-600 dark:hover:text-primary-400"
                aria-label="Medium Profile"
              >
                <svg
                  className="h-6 w-6"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M13.54 12a6.8 6.8 0 0 1-6.77 6.82A6.8 6.8 0 0 1 0 12a6.8 6.8 0 0 1 6.77-6.82A6.8 6.8 0 0 1 13.54 12zm7.42 0c0 3.54-1.51 6.42-3.38 6.42-1.87 0-3.39-2.88-3.39-6.42s1.52-6.42 3.39-6.42 3.38 2.88 3.38 6.42zM24 12c0 3.17-.53 5.75-1.19 5.75-.66 0-1.19-2.58-1.19-5.75s.53-5.75 1.19-5.75C23.47 6.25 24 8.83 24 12z" />
                </svg>
              </a>
            </div>
          </div>

          <FooterColumn title="Attack surface" links={ATTACK_SURFACE} />
          <FooterColumn title="Your progress" links={PROGRESS} />
          <FooterColumn title="Learn & community" links={COMMUNITY} />
        </div>

        <div className="mt-8 border-t border-slate-200 pt-8 dark:border-slate-800">
          <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              {new Date().getFullYear()} OSS – OopsSec Store.
              <span className="ml-2 text-xs text-slate-500 dark:text-slate-500">
                v{packageJson.version}
              </span>
            </p>
            <div className="flex gap-6 text-sm">
              <a
                href={`${GITHUB_REPO}/releases`}
                target="_blank"
                rel="noopener noreferrer"
                className={LINK_CLASS}
              >
                Changelog
              </a>
              <Link href="/terms" className={LINK_CLASS}>
                Terms of Service
              </Link>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
