"use client";

import Link from "next/link";

export default function Error() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-4 py-8">
      <div className="w-full max-w-3xl">
        <div className="text-center">
          <h1 className="mb-2 text-6xl font-black text-red-500 sm:text-8xl">
            Error 500
          </h1>
        </div>

        <div className="mb-8 overflow-hidden rounded border border-slate-700 bg-slate-900 shadow-2xl shadow-red-500/10">
          <div className="aspect-video w-full">
            <iframe
              className="h-full w-full"
              src="https://www.youtube-nocookie.com/embed/d-diB65scQU?rel=0"
              title="Don't worry be happy"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
              allowFullScreen
            />
          </div>
        </div>

        <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-600 px-6 py-3 font-medium text-slate-300 transition-all hover:border-slate-500 hover:text-slate-100"
          >
            <svg
              className="h-5 w-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
              />
            </svg>
            Go to Home
          </Link>
        </div>
      </div>
    </div>
  );
}
