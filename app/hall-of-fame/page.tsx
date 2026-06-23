import Header from "../components/Header";
import Footer from "../components/Footer";
import type { HallOfFameEntry } from "@/lib/types";
import hallOfFameData from "@/hall-of-fame/data.json";
import HallOfFameClient from "./HallOfFameClient";
import ContributorsSection from "./ContributorsSection";
import { TrophyIcon, GitHubIcon } from "./icons";
import { fetchContributors } from "@/lib/github";
import { GITHUB_REPO } from "@/lib/config";

// Next.js requires a statically-analyzable literal here; keep in sync with
// CONTRIBUTORS_REVALIDATE_SECONDS in lib/config.ts (24h).
export const revalidate = 86400;

export const metadata = {
  title: "Hall of Fame – OopsSec Store",
  description:
    "Players who have discovered all security flags in OopsSec Store",
};

export default async function HallOfFame() {
  const entries = hallOfFameData as HallOfFameEntry[];
  const contributors = await fetchContributors();

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

        <ContributorsSection contributors={contributors} />
      </main>
      <Footer />
    </div>
  );
}
