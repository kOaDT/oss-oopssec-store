import Header from "../components/Header";
import Footer from "../components/Footer";
import FlagDisplay from "../components/FlagDisplay";
import { prisma } from "@/lib/prisma";
import { STREAM_DEFAULTS, BFLA_FLAG_SLUG } from "@/lib/live-stream";

export const dynamic = "force-dynamic";

export default async function LivePage() {
  const stored = await prisma.streamConfig.findFirst();
  const config = {
    title: stored?.title ?? STREAM_DEFAULTS.title,
    liveVideoId: stored?.liveVideoId ?? STREAM_DEFAULTS.liveVideoId,
    // The flag only surfaces when a NON-admin rewrote the broadcast. That is
    // exactly what the `hijacked` column records (see POST /api/live/stream) —
    // an admin changing the video through the UI never sets it.
    hijacked: stored?.hijacked ?? false,
  };

  const flag = config.hijacked
    ? (await prisma.flag.findUnique({ where: { slug: BFLA_FLAG_SLUG } }))?.flag
    : null;

  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-slate-900">
      <Header />
      <main className="flex-1">
        <section className="border-b border-slate-200 bg-gradient-to-br from-primary-500 via-primary-600 to-secondary-600 dark:border-slate-800">
          <div className="container mx-auto px-4 py-12 md:py-16">
            <div className="mx-auto max-w-4xl text-center">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full bg-red-600 px-3 py-1 text-sm font-semibold text-white">
                <span className="h-2 w-2 animate-pulse rounded-full bg-white"></span>
                LIVE
              </div>
              <h1 className="mb-4 text-3xl font-bold tracking-tight text-white md:text-4xl">
                {config.title}
              </h1>
              <p className="text-lg text-primary-50">
                Tune in to our live shopping stream for real-time product demos
                and exclusive drops.
              </p>
            </div>
          </div>
        </section>

        <section className="container mx-auto px-4 py-12">
          <div className="mx-auto max-w-4xl">
            {flag && (
              <FlagDisplay flag={flag} title="Broadcast Hijacked!" showIcon />
            )}
            <div className="aspect-video w-full overflow-hidden rounded-xl border border-slate-200 bg-black shadow-lg dark:border-slate-800">
              <iframe
                className="h-full w-full"
                src={`https://www.youtube.com/embed/${config.liveVideoId}`}
                title={config.title}
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                allowFullScreen
              ></iframe>
            </div>
            <p className="mt-4 text-center text-sm text-slate-500 dark:text-slate-400">
              Now streaming · OopsSec Live productions
            </p>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
