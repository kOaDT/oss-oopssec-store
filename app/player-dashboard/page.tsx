import Header from "../components/Header";
import Footer from "../components/Footer";
import PlayerDashboardClient from "./PlayerDashboardClient";
import { version } from "../../package.json";

export const metadata = {
  title: "Player Dashboard – OopsSec Store",
  description: "Track your progress in finding security vulnerabilities",
};

const ASCII_BANNER = `
   ____  ____ ____     ____                  ____            ____  _
  / __ \\/ __// __/    / __ \\ ___   ___  ___ / __/ ___  ____ / __/ / /_ ___   ____ ___
 / /_/ /\\ \\ _\\ \\     / /_/ // _ \\ / _ \\(_-<_\\ \\  / -_)/ __/_\\ \\  / __// _ \\ / __// -_)
 \\____/___//___/     \\____/ \\___// .__/___/___/  \\__/ \\__//___/  \\__/ \\___//_/   \\__/
                                /_/
`;

const ASCII_DUCK = `
     __
   >(o )___
    ( ._> /
     \`---'
`;

export default function PlayerDashboard() {
  return (
    <div className="flex min-h-screen flex-col bg-slate-950">
      <Header />
      <main className="flex-1">
        <section className="relative overflow-hidden border-b border-emerald-900/50 bg-slate-950">
          <div className="absolute inset-0 bg-[linear-gradient(transparent_50%,rgba(0,0,0,0.5)_50%)] bg-[length:100%_4px] opacity-10" />
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(16,185,129,0.15),transparent_70%)]" />

          <div className="container relative mx-auto px-4 py-8 md:py-12">
            <div className="mx-auto max-w-5xl">
              <div className="mb-6 flex items-center gap-2 font-mono text-xs text-emerald-500/70">
                <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-emerald-500" />
                <span className="text-slate-600">|</span>
                <span className="text-slate-500">
                  {new Date().toISOString()}
                </span>
              </div>

              <div className="flex flex-col items-center gap-6 lg:flex-row lg:items-start lg:gap-8">
                <div className="hidden shrink-0 lg:block">
                  <pre
                    className="text-emerald-500/80 text-sm leading-tight xl:text-base"
                    aria-hidden="true"
                  >
                    {ASCII_DUCK}
                  </pre>
                </div>

                <div className="flex-1 text-center lg:text-left">
                  <pre
                    className="mb-4 hidden overflow-x-auto font-mono text-[6px] leading-tight text-emerald-400 sm:text-[8px] md:block md:text-[10px] lg:text-xs"
                    aria-hidden="true"
                  >
                    {ASCII_BANNER}
                  </pre>
                  <h1 className="mb-2 font-mono text-2xl font-bold text-emerald-400 md:hidden">
                    Player&apos;s Dashboard
                  </h1>

                  <p className="font-mono text-sm text-slate-400">
                    <span className="text-emerald-500">[INFO]</span> Track your
                    progress and review discovered vulnerabilities
                  </p>
                </div>
              </div>

              <div className="mt-6 border-t border-emerald-900/30 pt-4 font-mono text-xs text-slate-600">
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                  <span>
                    <span className="text-slate-400">
                      {`OopsSec Store v${version}`}
                    </span>
                  </span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-8 md:py-12">
          <div className="mx-auto max-w-6xl">
            <PlayerDashboardClient />
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
