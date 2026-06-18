"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import FlagDisplay from "../../components/FlagDisplay";
import { getStoredUser } from "@/lib/client-auth";

interface StreamConfig {
  id: number;
  title: string;
  liveVideoId: string;
  rtmpUrl: string;
  streamKey: string;
  isLive: boolean;
  hijacked: boolean;
}

interface UpdateResponse {
  ok?: boolean;
  message?: string;
  config?: StreamConfig;
  flag?: string;
  error?: string;
}

export default function LiveManagementClient() {
  const [config, setConfig] = useState<StreamConfig | null>(null);
  const [videoId, setVideoId] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [flag, setFlag] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }
    // Cosmetic, client-side-only gating. The API does NOT enforce this.
    setIsAdmin(user.role === "ADMIN");

    const fetchConfig = async () => {
      try {
        const response = await fetch("/api/live/stream", {
          credentials: "include",
        });
        if (response.status === 401) {
          router.push("/login");
          return;
        }
        if (!response.ok) {
          throw new Error("Failed to load stream config");
        }
        const data: StreamConfig = await response.json();
        setConfig(data);
        setVideoId(data.liveVideoId);
      } catch {
        setError("An error occurred while loading the stream.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchConfig();
  }, [router]);

  const handleUpdate = async () => {
    setError(null);
    setMessage(null);
    try {
      const response = await fetch("/api/live/stream", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ liveVideoId: videoId }),
      });
      const data: UpdateResponse = await response.json();
      if (!response.ok) {
        setError(data.error || "Failed to update stream.");
        return;
      }
      if (data.config) setConfig(data.config);
      if (data.flag) setFlag(data.flag);
      setMessage(data.message || "Broadcast updated.");
    } catch {
      setError("An error occurred while updating the stream.");
    }
  };

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-3xl text-center text-slate-600 dark:text-slate-400">
          Loading stream...
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-12">
      <div className="mx-auto max-w-3xl">
        {flag && (
          <FlagDisplay
            flag={flag}
            title="Broadcast Hijacked!"
            description="You rewrote the public OopsSec Live stream without admin rights."
            showIcon
          />
        )}

        {error && (
          <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
            {error}
          </div>
        )}
        {message && !flag && (
          <div className="mb-6 rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-300">
            {message}
          </div>
        )}

        {config && (
          <div className="space-y-6 rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-700 dark:bg-slate-800/50">
            <div>
              <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
                {config.title}
              </h2>
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                Currently broadcasting video{" "}
                <code className="font-mono">{config.liveVideoId}</code>
              </p>
            </div>

            <dl className="grid grid-cols-1 gap-3 rounded-lg bg-slate-50 p-4 text-sm dark:bg-slate-900/40">
              <div className="flex flex-col">
                <dt className="font-medium text-slate-500 dark:text-slate-400">
                  RTMP ingest URL
                </dt>
                <dd className="font-mono text-slate-900 dark:text-slate-100">
                  {config.rtmpUrl}
                </dd>
              </div>
              <div className="flex flex-col">
                <dt className="font-medium text-slate-500 dark:text-slate-400">
                  Stream key
                </dt>
                <dd className="font-mono text-slate-900 dark:text-slate-100">
                  {config.streamKey}
                </dd>
              </div>
            </dl>

            <div>
              <label
                htmlFor="videoId"
                className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300"
              >
                Featured YouTube video ID
              </label>
              <input
                id="videoId"
                type="text"
                value={videoId}
                onChange={(e) => setVideoId(e.target.value)}
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-slate-900 focus:border-primary-500 focus:outline-none dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
              />
            </div>

            {isAdmin ? (
              <button
                onClick={handleUpdate}
                className="rounded-lg bg-primary-600 px-5 py-2.5 font-medium text-white transition-colors hover:bg-primary-700"
              >
                Update stream
              </button>
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Only administrators can update the broadcast.
              </p>
            )}
          </div>
        )}

        <div className="mt-6">
          <Link
            href="/live"
            className="text-sm font-medium text-primary-600 hover:underline dark:text-primary-400"
          >
            View public stream →
          </Link>
        </div>
      </div>
    </section>
  );
}
