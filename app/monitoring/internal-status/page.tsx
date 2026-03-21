import { prisma } from "@/lib/prisma";
import FlagDisplay from "@/app/components/FlagDisplay";

export const dynamic = "force-dynamic";

async function getFlag() {
  const flag = await prisma.flag.findUnique({
    where: { slug: "middleware-authorization-bypass" },
  });
  return flag;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

export default async function InternalStatusPage() {
  const flag = await getFlag();
  const uptime = process.uptime();

  const diagnostics = {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    uptime: formatUptime(uptime),
    memoryUsage: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`,
    pid: process.pid,
    env: process.env.NODE_ENV || "development",
  };

  return (
    <div className="min-h-screen bg-[#0a0e17] text-slate-200">
      <header className="border-b border-slate-700/50 bg-[#111827]">
        <div className="flex items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <svg
              className="h-6 w-6 text-cyan-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={1.5}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z"
              />
            </svg>
            <h1 className="font-mono text-lg font-bold text-cyan-400">
              Internal Status
            </h1>
            <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-500">
              RESTRICTED
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-green-400" />
            <span className="font-mono text-xs text-slate-500">HEALTHY</span>
          </div>
        </div>
      </header>

      <div className="px-6 py-6">
        <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="rounded-lg border border-slate-700/50 bg-[#111827] p-4">
            <div className="mb-1 font-mono text-xs text-slate-500">
              Node Version
            </div>
            <div className="font-mono text-lg text-cyan-400">
              {diagnostics.nodeVersion}
            </div>
          </div>
          <div className="rounded-lg border border-slate-700/50 bg-[#111827] p-4">
            <div className="mb-1 font-mono text-xs text-slate-500">Uptime</div>
            <div className="font-mono text-lg text-cyan-400">
              {diagnostics.uptime}
            </div>
          </div>
          <div className="rounded-lg border border-slate-700/50 bg-[#111827] p-4">
            <div className="mb-1 font-mono text-xs text-slate-500">
              Memory Usage
            </div>
            <div className="font-mono text-lg text-cyan-400">
              {diagnostics.memoryUsage}
            </div>
          </div>
        </div>

        <div className="mb-6 rounded-lg border border-slate-700/50 bg-[#111827] p-6">
          <h2 className="mb-4 font-mono text-sm font-bold text-slate-400">
            System Diagnostics
          </h2>
          <div className="space-y-3">
            {Object.entries(diagnostics).map(([key, value]) => (
              <div
                key={key}
                className="flex items-center justify-between border-b border-slate-800/50 pb-2"
              >
                <span className="font-mono text-xs text-slate-500">{key}</span>
                <span className="font-mono text-sm text-slate-300">
                  {value}
                </span>
              </div>
            ))}
          </div>
        </div>

        {flag && (
          <FlagDisplay
            flag={flag.flag}
            title="Internal Validation Token"
            description="Used for automated health check verification. Do not share externally."
            variant="compact"
          />
        )}
      </div>
    </div>
  );
}
