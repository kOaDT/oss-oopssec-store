import Header from "../components/Header";
import Footer from "../components/Footer";
import type { HallOfFameEntry } from "@/lib/types";
import hallOfFameData from "@/hall-of-fame/data.json";
import HallOfFameClient from "./HallOfFameClient";

const GITHUB_REPO = "https://github.com/kOaDT/oss-oopssec-store";

export const metadata = {
  title: "Hall of Fame – OopsSec Store",
  description:
    "Players who have discovered all security flags in OopsSec Store",
};

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

export default function HallOfFame() {
  const entries = hallOfFameData as HallOfFameEntry[];

  return (
    <div className="flex min-h-screen flex-col bg-slate-50 dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section
          className="relative overflow-hidden border-b border-slate-200 bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 dark:border-slate-800"
          style={{ borderRadius: "0 0 8px 8px" }}
        >
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(255,255,255,0.05),transparent_70%)]" />
          <div className="container relative mx-auto px-4 py-16 md:py-18">
            <div className="mx-auto max-w-4xl text-center">
              <div
                className="mb-8 inline-flex items-center justify-center bg-white/10 p-5 backdrop-blur-sm"
                style={{ borderRadius: "8px" }}
              >
                <TrophyIcon className="h-14 w-14 text-amber-400" />
              </div>
              <h1 className="mb-6 text-5xl font-light tracking-tight text-white md:text-6xl lg:text-7xl">
                Hall of Fame
              </h1>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16 md:py-20">
          <div className="mx-auto max-w-6xl">
            <div className="mb-12 text-center">
              <div
                className="inline-flex items-center gap-3 bg-white px-6 py-3 shadow-sm dark:bg-slate-800"
                style={{ borderRadius: "8px" }}
              >
                <TrophyIcon className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                <p className="text-slate-700 dark:text-slate-300">
                  <span className="font-semibold text-primary-600 dark:text-primary-400">
                    {entries.length}
                  </span>{" "}
                  {entries.length === 1 ? "player has" : "players have"}{" "}
                  completed all challenges
                </p>
              </div>
            </div>

            <HallOfFameClient entries={entries} />

            <div
              className="mt-20 bg-white p-10 shadow-lg dark:bg-slate-800 md:p-12"
              style={{ borderRadius: "8px" }}
            >
              <div className="flex flex-col items-center gap-8 text-center md:flex-row md:items-start md:text-left">
                <div
                  className="flex h-20 w-20 shrink-0 items-center justify-center bg-primary-100 shadow-sm dark:bg-primary-900/30"
                  style={{ borderRadius: "8px" }}
                >
                  <svg
                    className="h-10 w-10 text-primary-600 dark:text-primary-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 6v6m0 0v6m0-6h6m-6 0H6"
                    />
                  </svg>
                </div>
                <div className="flex-1">
                  <h2 className="mb-4 text-3xl font-light text-slate-900 dark:text-slate-100">
                    Join the Hall of Fame
                  </h2>
                  <p className="mb-4 text-lg leading-relaxed text-slate-600 dark:text-slate-400">
                    Found all the flags? Add your name to the Hall of Fame by
                    submitting a Pull Request to the repository. Simply add your
                    profile to the{" "}
                    <code
                      className="bg-slate-100 px-2 py-1 text-sm dark:bg-slate-700"
                      style={{ borderRadius: "4px" }}
                    >
                      /hall-of-fame/data.json
                    </code>{" "}
                    file.
                  </p>
                  <p className="mb-8 text-lg font-medium text-slate-700 dark:text-slate-300">
                    This is an excellent way to showcase your security expertise
                    and put your profile in the spotlight.
                  </p>
                  <div className="flex flex-wrap justify-center gap-4 md:justify-start">
                    <a
                      href={`${GITHUB_REPO}/blob/main/hall-of-fame/data.json`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 bg-primary-600 px-8 py-3 font-medium text-white shadow-md transition-all duration-200 hover:bg-primary-700 hover:shadow-lg"
                      style={{ borderRadius: "4px" }}
                    >
                      <GitHubIcon className="h-5 w-5" />
                      Submit Your Entry
                    </a>
                    <a
                      href={`${GITHUB_REPO}/blob/main/CONTRIBUTING.md`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 border border-slate-300 bg-white px-8 py-3 font-medium text-slate-700 shadow-sm transition-all duration-200 hover:bg-slate-50 hover:shadow-md dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
                      style={{ borderRadius: "4px" }}
                    >
                      Learn More
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
