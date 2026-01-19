import Link from "next/link";
import packageJson from "../../package.json";

const GITHUB_REPO = "https://github.com/kOaDT/oss-oopssec-store";
const GITHUB_ISSUES = `${GITHUB_REPO}/issues`;
const GITHUB_DISCUSSIONS = `${GITHUB_REPO}/discussions`;
const GITHUB_ROADMAP = "https://github.com/users/kOaDT/projects/3";

export default function Footer() {
  return (
    <footer className="border-t border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
          <div className="md:col-span-1">
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
                  className="h-5 w-5"
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
            </div>
          </div>

          <div className="md:col-span-1">
            <h4 className="mb-4 font-semibold text-slate-900 dark:text-slate-100">
              Navigation
            </h4>
            <ul className="space-y-3 text-sm">
              <li>
                <Link
                  href="/"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  All Products
                </Link>
              </li>
              <li>
                <Link
                  href="/support"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  Contact Support
                </Link>
              </li>
              <li>
                <Link
                  href="/news"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  News
                </Link>
              </li>
              <li>
                <Link
                  href="/admin"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  Admin
                </Link>
              </li>
            </ul>
          </div>

          <div className="md:col-span-1">
            <h4 className="mb-4 font-semibold text-slate-900 dark:text-slate-100">
              Community
            </h4>
            <ul className="space-y-3 text-sm">
              <li>
                <a
                  href={GITHUB_REPO}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  GitHub
                </a>
              </li>
              <li>
                <a
                  href={GITHUB_ISSUES}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  Issues
                </a>
              </li>
              <li>
                <a
                  href={GITHUB_DISCUSSIONS}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  Discussions
                </a>
              </li>
              <li>
                <Link
                  href="https://koadt.github.io/oss-oopssec-store/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  Walkthroughs
                </Link>
              </li>
              <li>
                <a
                  href={GITHUB_ROADMAP}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
                >
                  Roadmap
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-8 border-t border-slate-200 pt-8 dark:border-slate-800">
          <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              {new Date().getFullYear()} OSS – OopsSec Store.
              <span className="ml-2 text-xs text-slate-500 dark:text-slate-500">
                v{packageJson.version}
              </span>
            </p>
            <div className="flex gap-6 text-sm text-slate-600 dark:text-slate-400">
              <Link
                href="/flags"
                className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
              >
                Flags
              </Link>
              <Link
                href="/hall-of-fame"
                className="text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
              >
                Hall of Fame
              </Link>
              <a
                href={`${GITHUB_REPO}/releases`}
                target="_blank"
                rel="noopener noreferrer"
                className="transition-colors hover:text-primary-600 dark:hover:text-primary-400"
              >
                Changelog
              </a>
              <Link
                href="/terms"
                className="transition-colors hover:text-primary-600 dark:hover:text-primary-400"
              >
                Terms of Service
              </Link>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
