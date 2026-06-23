import Image from "next/image";
import type { Contributor } from "@/lib/types";
import { CodeIcon, GitHubIcon } from "./icons";

interface ContributorsSectionProps {
  contributors: Contributor[];
}

export default function ContributorsSection({
  contributors,
}: ContributorsSectionProps) {
  if (contributors.length === 0) {
    return null;
  }

  return (
    <section className="container mx-auto px-4 pb-16 md:pb-20">
      <div className="mx-auto max-w-6xl">
        <div className="mb-12 text-center">
          <div
            className="mb-6 inline-flex items-center justify-center bg-primary-100 p-4 dark:bg-primary-900/30"
            style={{ borderRadius: "8px" }}
          >
            <CodeIcon className="h-8 w-8 text-primary-600 dark:text-primary-400" />
          </div>
          <h2 className="mb-3 text-4xl font-light tracking-tight text-slate-900 dark:text-slate-100 md:text-5xl">
            Contributors
          </h2>
          <p className="mx-auto max-w-2xl text-lg text-slate-600 dark:text-slate-400">
            The people building and improving OopsSec Store.
          </p>
        </div>

        <ul className="grid grid-cols-2 gap-4 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5">
          {contributors.map((contributor) => (
            <li key={contributor.username}>
              <a
                href={contributor.githubUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="group flex h-full flex-col items-center gap-3 bg-white p-6 shadow-md transition-all duration-300 hover:shadow-2xl dark:bg-slate-800"
                style={{ borderRadius: "8px" }}
              >
                <div className="relative">
                  <Image
                    src={contributor.avatarUrl}
                    alt={`${contributor.username}'s avatar`}
                    width={72}
                    height={72}
                    className="h-[72px] w-[72px] rounded-full border-2 border-white object-cover shadow-md dark:border-slate-700"
                  />
                  <span
                    className="absolute -bottom-1 -right-1 flex h-7 w-7 items-center justify-center bg-slate-900 text-white shadow-md transition-colors group-hover:bg-primary-600 dark:bg-slate-700"
                    style={{ borderRadius: "50%" }}
                  >
                    <GitHubIcon className="h-4 w-4" />
                  </span>
                </div>
                <span className="text-center text-sm font-medium text-slate-900 dark:text-slate-100">
                  {contributor.username}
                </span>
                <span className="text-xs text-slate-500 dark:text-slate-500">
                  {contributor.contributions}{" "}
                  {contributor.contributions === 1
                    ? "contribution"
                    : "contributions"}
                </span>
              </a>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
