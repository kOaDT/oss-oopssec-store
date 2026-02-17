"use client";

import { useState, useEffect, useCallback } from "react";

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
}

function LoginForm({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/monitoring/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (res.ok) {
        onLogin();
      } else {
        setError("Invalid credentials");
      }
    } catch {
      setError("Connection failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0a0e17]">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="mb-2 flex items-center justify-center gap-2">
            <svg
              className="h-8 w-8 text-cyan-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={1.5}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
              />
            </svg>
            <h1 className="font-mono text-xl font-bold text-cyan-400">
              SIEM Console
            </h1>
          </div>
          <p className="font-mono text-sm text-slate-500">
            Internal Monitoring System
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-lg border border-slate-700/50 bg-[#111827] p-6"
        >
          <div className="mb-4">
            <label className="mb-1 block font-mono text-xs text-slate-400">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded border border-slate-600 bg-[#0a0e17] px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyan-500"
              autoComplete="off"
            />
          </div>
          <div className="mb-4">
            <label className="mb-1 block font-mono text-xs text-slate-400">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded border border-slate-600 bg-[#0a0e17] px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-cyan-500"
            />
          </div>
          {error && (
            <p className="mb-3 font-mono text-xs text-red-400">{error}</p>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded bg-cyan-600 py-2 font-mono text-sm font-medium text-white transition-colors hover:bg-cyan-500 disabled:opacity-50"
          >
            {loading ? "Authenticating..." : "Log In"}
          </button>
        </form>
      </div>
    </div>
  );
}

const LEVEL_STYLES: Record<string, string> = {
  error: "text-red-400",
  warn: "text-yellow-400",
  info: "text-blue-400",
  log: "text-slate-300",
};

const LEVEL_BADGE_STYLES: Record<string, string> = {
  error: "bg-red-900/40 text-red-400 border-red-800/50",
  warn: "bg-yellow-900/40 text-yellow-400 border-yellow-800/50",
  info: "bg-blue-900/40 text-blue-400 border-blue-800/50",
  log: "bg-slate-800/40 text-slate-400 border-slate-700/50",
};

function Dashboard() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchLogs = useCallback(async () => {
    try {
      const res = await fetch("/api/monitoring/logs");
      if (res.ok) {
        const data = await res.json();
        setLogs(data.logs || []);
      }
    } catch {
      // Silently handle fetch errors
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchLogs]);

  const filteredLogs = logs.filter((log) => {
    if (levelFilter !== "all" && log.level !== levelFilter) return false;
    if (filter && !log.message.toLowerCase().includes(filter.toLowerCase()))
      return false;
    return true;
  });

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
                d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
              />
            </svg>
            <h1 className="font-mono text-lg font-bold text-cyan-400">
              SIEM Console
            </h1>
            <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-500">
              v1.0.0
            </span>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span
                className={`h-2 w-2 rounded-full ${autoRefresh ? "bg-green-400" : "bg-slate-600"}`}
              />
              <span className="font-mono text-xs text-slate-500">
                {autoRefresh ? "LIVE" : "PAUSED"}
              </span>
            </div>
            <span className="font-mono text-xs text-slate-600">
              {logs.length} entries
            </span>
          </div>
        </div>
      </header>

      <div className="border-b border-slate-700/50 bg-[#0d1321] px-6 py-3">
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Search logs..."
            className="w-64 rounded border border-slate-700 bg-[#0a0e17] px-3 py-1.5 font-mono text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-600"
          />
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="rounded border border-slate-700 bg-[#0a0e17] px-3 py-1.5 font-mono text-sm text-slate-200 outline-none focus:border-cyan-600"
          >
            <option value="all">All Levels</option>
            <option value="log">LOG</option>
            <option value="info">INFO</option>
            <option value="warn">WARN</option>
            <option value="error">ERROR</option>
          </select>
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`rounded border px-3 py-1.5 font-mono text-xs transition-colors ${
              autoRefresh
                ? "border-green-800 bg-green-900/30 text-green-400 hover:bg-green-900/50"
                : "border-slate-700 bg-slate-800 text-slate-400 hover:bg-slate-700"
            }`}
          >
            {autoRefresh ? "Auto-Refresh ON" : "Auto-Refresh OFF"}
          </button>
          <button
            onClick={fetchLogs}
            className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 font-mono text-xs text-slate-400 transition-colors hover:bg-slate-700"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="px-6 py-4">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="font-mono text-sm text-slate-600">
              Loading logs...
            </div>
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="flex items-center justify-center py-20">
            <div className="font-mono text-sm text-slate-600">
              No log entries found
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full font-mono text-sm">
              <thead>
                <tr className="border-b border-slate-700/50 text-left">
                  <th className="px-3 py-2 text-xs font-medium text-slate-500">
                    Timestamp
                  </th>
                  <th className="px-3 py-2 text-xs font-medium text-slate-500">
                    Level
                  </th>
                  <th className="px-3 py-2 text-xs font-medium text-slate-500">
                    Message
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log, i) => (
                  <tr
                    key={i}
                    className="border-b border-slate-800/50 transition-colors hover:bg-slate-800/30"
                  >
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-500">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`inline-block rounded border px-2 py-0.5 text-xs font-medium uppercase ${LEVEL_BADGE_STYLES[log.level] || LEVEL_BADGE_STYLES.log}`}
                      >
                        {log.level}
                      </span>
                    </td>
                    <td
                      className={`max-w-2xl break-all px-3 py-2 text-xs ${LEVEL_STYLES[log.level] || LEVEL_STYLES.log}`}
                    >
                      {log.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default function SiemPage() {
  const [authenticated, setAuthenticated] = useState(false);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    fetch("/api/monitoring/logs")
      .then((res) => {
        if (res.ok) setAuthenticated(true);
      })
      .catch(() => {})
      .finally(() => setChecking(false));
  }, []);

  if (checking) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#0a0e17]">
        <div className="font-mono text-sm text-slate-600">Loading...</div>
      </div>
    );
  }

  if (!authenticated) {
    return <LoginForm onLogin={() => setAuthenticated(true)} />;
  }

  return <Dashboard />;
}
