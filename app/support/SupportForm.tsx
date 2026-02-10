"use client";

import { useState, FormEvent } from "react";
import { api, ApiError } from "@/lib/api";

export default function SupportForm() {
  const [email, setEmail] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [screenshotUrl, setScreenshotUrl] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [submittedData, setSubmittedData] = useState<{
    email: string;
    title: string;
    description: string;
    screenshotContent?: string;
  } | null>(null);

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);
    setSubmittedData(null);

    try {
      const data = await api.post<{
        success: boolean;
        data: {
          email: string;
          title: string;
          description: string;
          screenshotContent?: string;
        };
      }>("/api/support", {
        email,
        title,
        description,
        screenshotUrl: screenshotUrl || undefined,
      });

      setSubmittedData(data.data);
      setIsLoading(false);
    } catch (error) {
      const errorMessage =
        error instanceof ApiError
          ? error.message
          : "An error occurred. Please try again.";
      setError(errorMessage);
      setIsLoading(false);
    }
  };

  if (submittedData) {
    return (
      <div className="space-y-6">
        <div className="rounded-lg border border-green-200 bg-green-50 p-6 dark:border-green-800/50 dark:bg-green-900/20">
          <h3 className="mb-2 text-lg font-semibold text-green-800 dark:text-green-200">
            Support Request Submitted Successfully
          </h3>
          <p className="text-sm text-green-700 dark:text-green-300">
            Thank you for contacting us. We have received your request and will
            get back to you soon.
          </p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-6 dark:border-slate-700 dark:bg-slate-800">
          <h4 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">
            Request Summary
          </h4>
          <div className="space-y-3 text-sm">
            <div>
              <span className="font-medium text-slate-700 dark:text-slate-300">
                Email:
              </span>{" "}
              <span className="text-slate-900 dark:text-slate-100">
                {submittedData.email}
              </span>
            </div>
            <div>
              <span className="font-medium text-slate-700 dark:text-slate-300">
                Title:
              </span>{" "}
              <span className="text-slate-900 dark:text-slate-100">
                {submittedData.title}
              </span>
            </div>
            <div>
              <span className="font-medium text-slate-700 dark:text-slate-300">
                Description:
              </span>{" "}
              <span className="text-slate-900 dark:text-slate-100">
                {submittedData.description}
              </span>
            </div>
            {submittedData.screenshotContent && (
              <div>
                <span className="font-medium text-slate-700 dark:text-slate-300">
                  Screenshot Content:
                </span>
                <div className="mt-2 rounded border border-slate-300 bg-white p-4 dark:border-slate-600 dark:bg-slate-900">
                  <div
                    className="prose prose-sm max-w-none dark:prose-invert"
                    dangerouslySetInnerHTML={{
                      __html: submittedData.screenshotContent,
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        </div>
        <button
          onClick={() => {
            setSubmittedData(null);
            setEmail("");
            setTitle("");
            setDescription("");
            setScreenshotUrl("");
          }}
          className="w-full cursor-pointer rounded-lg bg-primary-600 px-4 py-3 font-semibold text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:bg-primary-500 dark:hover:bg-primary-600"
        >
          Submit Another Request
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div>
        <label
          htmlFor="email"
          className="block text-sm font-medium text-slate-700 dark:text-slate-300"
        >
          Email
        </label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-primary-400 dark:focus:ring-primary-400"
          placeholder="your@email.com"
        />
      </div>

      <div>
        <label
          htmlFor="title"
          className="block text-sm font-medium text-slate-700 dark:text-slate-300"
        >
          Title
        </label>
        <input
          id="title"
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          required
          className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-primary-400 dark:focus:ring-primary-400"
          placeholder="Brief description of your issue"
        />
      </div>

      <div>
        <label
          htmlFor="description"
          className="block text-sm font-medium text-slate-700 dark:text-slate-300"
        >
          Description
        </label>
        <textarea
          id="description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          required
          rows={6}
          className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-primary-400 dark:focus:ring-primary-400"
          placeholder="Please provide detailed information about your issue..."
        />
      </div>

      <div>
        <label
          htmlFor="screenshotUrl"
          className="block text-sm font-medium text-slate-700 dark:text-slate-300"
        >
          Screenshot URL (Optional)
        </label>
        <input
          id="screenshotUrl"
          type="url"
          value={screenshotUrl}
          onChange={(e) => setScreenshotUrl(e.target.value)}
          className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-primary-400 dark:focus:ring-primary-400"
          placeholder="https://example.com/screenshot.png"
        />
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Provide a URL to a screenshot or image that helps illustrate your
          issue
        </p>
      </div>

      <div>
        <label
          htmlFor="screenshotFile"
          className="block text-sm font-medium text-slate-700 dark:text-slate-300"
        >
          Or Upload Screenshot (Optional)
        </label>
        <input
          id="screenshotFile"
          type="file"
          accept="image/*"
          className="mt-2 block w-full text-sm text-slate-500 file:mr-4 file:rounded-lg file:border-0 file:bg-primary-50 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-primary-700 hover:file:bg-primary-100 dark:text-slate-400 dark:file:bg-primary-900/30 dark:file:text-primary-300"
        />
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Upload a screenshot file (not currently processed)
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800/50 dark:bg-red-900/20">
          <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
        </div>
      )}

      <button
        type="submit"
        disabled={isLoading}
        className="w-full cursor-pointer rounded-lg bg-primary-600 px-4 py-3 font-semibold text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
      >
        {isLoading ? "Submitting..." : "Submit Support Request"}
      </button>
    </form>
  );
}
