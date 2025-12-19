import Header from "../components/Header";
import Footer from "../components/Footer";
import Link from "next/link";

interface ChangelogEntry {
  version: string;
  date: string;
  changes: {
    type: "added" | "changed" | "fixed" | "security" | "removed";
    description: string;
  }[];
}

const changelog: ChangelogEntry[] = [
  {
    version: "1.2.0",
    date: "2025-12-19",
    changes: [
      {
        type: "added",
        description: "Added a new flag: Client Side Price Manipulation",
      },
    ],
  },
  {
    version: "1.1.0",
    date: "2025-12-18",
    changes: [
      {
        type: "added",
        description: "Added a new flag: Weak JWT None Algorithm",
      },
    ],
  },
  {
    version: "1.0.0",
    date: "2025-12-17",
    changes: [
      {
        type: "added",
        description: "Launch of the OSS – OopsSec Store",
      },
    ],
  },
];

const typeColors = {
  added: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
  changed: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  fixed:
    "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  security: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  removed:
    "bg-slate-100 text-slate-800 dark:bg-slate-800/50 dark:text-slate-400",
};

const typeLabels = {
  added: "Added",
  changed: "Changed",
  fixed: "Fixed",
  security: "Security",
  removed: "Removed",
};

export default function Changelog() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-16 md:py-24">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="mb-6 text-4xl font-bold tracking-tight text-white md:text-5xl lg:text-6xl">
                Changelog
              </h1>
              <p className="text-lg text-primary-50 md:text-xl">
                Track all changes and updates to OSS – OopsSec Store
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-16">
          <div className="mx-auto max-w-4xl">
            <div className="mb-8 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-800/50">
              <p className="text-sm text-slate-600 dark:text-slate-400">
                This changelog tracks all notable changes to the project. For
                the full history, see the{" "}
                <Link
                  href="https://github.com/kOaDT/oss-oopssec-store/commits"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-primary-600 transition-colors hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
                >
                  commit history on GitHub
                </Link>
                .
              </p>
            </div>

            <div className="space-y-8">
              {changelog.map((entry, index) => (
                <div
                  key={entry.version}
                  className="rounded-lg border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-800/50"
                >
                  <div className="mb-4 flex items-center justify-between border-b border-slate-200 pb-4 dark:border-slate-700">
                    <div>
                      <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                        Version {entry.version}
                      </h2>
                      <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                        {new Date(entry.date).toLocaleDateString("en-US", {
                          year: "numeric",
                          month: "long",
                          day: "numeric",
                        })}
                      </p>
                    </div>
                    {index === 0 && (
                      <span className="rounded-full bg-primary-100 px-3 py-1 text-xs font-semibold text-primary-800 dark:bg-primary-900/30 dark:text-primary-400">
                        Latest
                      </span>
                    )}
                  </div>

                  <ul className="space-y-3">
                    {entry.changes.map((change, changeIndex) => (
                      <li
                        key={changeIndex}
                        className="flex items-start gap-3 text-sm"
                      >
                        <span
                          className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${typeColors[change.type]}`}
                        >
                          {typeLabels[change.type]}
                        </span>
                        <span className="flex-1 text-slate-700 dark:text-slate-300">
                          {change.description}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
