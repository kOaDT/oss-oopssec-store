"use client";

import { useState, useEffect, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api, ApiError } from "@/lib/api";

interface UserProfile {
  id: string;
  email: string;
  role: string;
  address: {
    street: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
  } | null;
}

interface ExportResponse {
  data?: Record<string, unknown> | string;
  error?: string;
  details?: string;
  format?: string;
}

interface SupportToken {
  id: string;
  token: string;
  email: string;
  expiresAt: string;
  createdAt: string;
  revoked: boolean;
}

export default function ProfileClient() {
  const { user, logout } = useAuth();
  const router = useRouter();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<
    "profile" | "privacy" | "data" | "support"
  >("profile");

  const [exportFormat, setExportFormat] = useState("json");
  const [exportFields, setExportFields] = useState("id,email,role");
  const [exportResult, setExportResult] = useState<ExportResponse | null>(null);
  const [isExporting, setIsExporting] = useState(false);

  const [supportToken, setSupportToken] = useState<SupportToken | null>(null);
  const [isSupportLoading, setIsSupportLoading] = useState(false);
  const [supportError, setSupportError] = useState<string | null>(null);
  const [supportSuccess, setSupportSuccess] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    if (!user) {
      router.push("/login?redirect=/profile");
      return;
    }

    const fetchProfile = async () => {
      try {
        const data = await api.get<UserProfile>("/api/user");
        setProfile(data);
      } catch {
        router.push("/login?redirect=/profile");
      } finally {
        setIsLoading(false);
      }
    };

    fetchProfile();
  }, [user, router]);

  const handleExportData = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsExporting(true);
    setExportResult(null);

    try {
      const response = await fetch("/api/user/export", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          format: exportFormat,
          fields: exportFields,
        }),
      });

      const contentType = response.headers.get("content-type");

      if (!response.ok) {
        const errorData = await response.json();
        setExportResult({
          error: errorData.error || "Export failed",
          details: JSON.stringify(errorData, null, 2),
        });
        return;
      }

      if (contentType?.includes("text/csv")) {
        const csvData = await response.text();
        setExportResult({ data: csvData, format: "csv" });
      } else {
        const jsonData = await response.json();
        setExportResult({ data: jsonData.data, format: "json" });
      }
    } catch (error) {
      if (error instanceof ApiError) {
        setExportResult({
          error: error.message,
          details:
            typeof error.data === "object" && error.data !== null
              ? JSON.stringify(error.data, null, 2)
              : String(error.data),
        });
      } else {
        setExportResult({ error: "An unexpected error occurred" });
      }
    } finally {
      setIsExporting(false);
    }
  };

  const handleLogout = () => {
    logout();
    router.push("/login?redirect=/profile");
  };

  const fetchSupportToken = async () => {
    try {
      const response = await fetch("/api/user/support-access", {
        credentials: "include",
      });
      const data = await response.json();
      if (data.supportToken) {
        setSupportToken(data.supportToken);
      }
    } catch {
      // Token doesn't exist yet
    }
  };

  const handleGenerateSupportToken = async () => {
    setIsSupportLoading(true);
    setSupportError(null);
    setSupportSuccess(null);

    try {
      const response = await fetch("/api/user/support-access", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      });

      const data = await response.json();

      if (!response.ok) {
        setSupportError(data.error || "Failed to generate support token");
        return;
      }

      setSupportToken(data.supportToken);
      setSupportSuccess("Support access token generated successfully");
    } catch {
      setSupportError("An unexpected error occurred");
    } finally {
      setIsSupportLoading(false);
    }
  };

  const handleRevokeSupportToken = async () => {
    setIsSupportLoading(true);
    setSupportError(null);
    setSupportSuccess(null);

    try {
      const response = await fetch("/api/user/support-access", {
        method: "DELETE",
        credentials: "include",
      });

      if (!response.ok) {
        const data = await response.json();
        setSupportError(data.error || "Failed to revoke support access");
        return;
      }

      setSupportToken(null);
      setSupportSuccess("Support access has been revoked");
    } catch {
      setSupportError("An unexpected error occurred");
    } finally {
      setIsSupportLoading(false);
    }
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  useEffect(() => {
    if (activeTab === "support" && user) {
      fetchSupportToken();
    }
  }, [activeTab, user]);

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">Loading...</p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (!profile) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl text-center">
          <p className="text-slate-600 dark:text-slate-400">
            Please log in to view your profile.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-4xl">
        <div className="mb-8 flex flex-wrap gap-2 border-b border-slate-200 dark:border-slate-700">
          <button
            onClick={() => setActiveTab("profile")}
            className={`px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === "profile"
                ? "border-b-2 border-primary-600 text-primary-600 dark:border-primary-400 dark:text-primary-400"
                : "cursor-pointer text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
            }`}
          >
            Profile
          </button>
          <button
            onClick={() => setActiveTab("privacy")}
            className={`px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === "privacy"
                ? "border-b-2 border-primary-600 text-primary-600 dark:border-primary-400 dark:text-primary-400"
                : "cursor-pointer text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
            }`}
          >
            Privacy
          </button>
          <button
            onClick={() => setActiveTab("data")}
            className={`px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === "data"
                ? "border-b-2 border-primary-600 text-primary-600 dark:border-primary-400 dark:text-primary-400"
                : "cursor-pointer text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
            }`}
          >
            Data Export
          </button>
          <button
            onClick={() => setActiveTab("support")}
            className={`px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === "support"
                ? "border-b-2 border-primary-600 text-primary-600 dark:border-primary-400 dark:text-primary-400"
                : "cursor-pointer text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
            }`}
          >
            Support Access
          </button>
        </div>

        {activeTab === "profile" && (
          <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800">
            <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Profile Information
            </h2>

            <div className="space-y-6">
              <div className="grid gap-6 md:grid-cols-2">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Email
                  </label>
                  <p className="mt-2 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100">
                    {profile.email}
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Role
                  </label>
                  <p className="mt-2 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100">
                    {profile.role}
                  </p>
                </div>
              </div>

              {profile.address && (
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                    Address
                  </label>
                  <p className="mt-2 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100">
                    {profile.address.street}, {profile.address.city},{" "}
                    {profile.address.state} {profile.address.zipCode},{" "}
                    {profile.address.country}
                  </p>
                </div>
              )}

              <div className="pt-6">
                <button
                  onClick={handleLogout}
                  className="cursor-pointer rounded-lg bg-red-600 px-6 py-3 font-semibold text-white transition-colors hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
                >
                  Log Out
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === "privacy" && (
          <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800">
            <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Privacy Settings
            </h2>

            <div className="space-y-6">
              <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                <div>
                  <p className="font-medium text-slate-900 dark:text-slate-100">
                    Marketing Emails
                  </p>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Receive updates about new products and offers
                  </p>
                </div>
                <label className="relative inline-flex cursor-pointer items-center">
                  <input type="checkbox" className="peer sr-only" />
                  <div className="peer h-6 w-11 rounded-full bg-slate-300 after:absolute after:left-[2px] after:top-[2px] after:h-5 after:w-5 after:rounded-full after:border after:border-slate-300 after:bg-white after:transition-all after:content-[''] peer-checked:bg-primary-600 peer-checked:after:translate-x-full peer-checked:after:border-white peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:border-slate-600 dark:bg-slate-700 dark:peer-focus:ring-primary-800"></div>
                </label>
              </div>

              <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                <div>
                  <p className="font-medium text-slate-900 dark:text-slate-100">
                    Order Notifications
                  </p>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Get notified about your order status
                  </p>
                </div>
                <label className="relative inline-flex cursor-pointer items-center">
                  <input
                    type="checkbox"
                    className="peer sr-only"
                    defaultChecked
                  />
                  <div className="peer h-6 w-11 rounded-full bg-slate-300 after:absolute after:left-[2px] after:top-[2px] after:h-5 after:w-5 after:rounded-full after:border after:border-slate-300 after:bg-white after:transition-all after:content-[''] peer-checked:bg-primary-600 peer-checked:after:translate-x-full peer-checked:after:border-white peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:border-slate-600 dark:bg-slate-700 dark:peer-focus:ring-primary-800"></div>
                </label>
              </div>

              <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                <div>
                  <p className="font-medium text-slate-900 dark:text-slate-100">
                    Data Analytics
                  </p>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Help us improve by sharing usage data
                  </p>
                </div>
                <label className="relative inline-flex cursor-pointer items-center">
                  <input
                    type="checkbox"
                    className="peer sr-only"
                    defaultChecked
                  />
                  <div className="peer h-6 w-11 rounded-full bg-slate-300 after:absolute after:left-[2px] after:top-[2px] after:h-5 after:w-5 after:rounded-full after:border after:border-slate-300 after:bg-white after:transition-all after:content-[''] peer-checked:bg-primary-600 peer-checked:after:translate-x-full peer-checked:after:border-white peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:border-slate-600 dark:bg-slate-700 dark:peer-focus:ring-primary-800"></div>
                </label>
              </div>
            </div>
          </div>
        )}

        {activeTab === "data" && (
          <div className="space-y-8">
            <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800">
              <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
                Export Your Data
              </h2>
              <p className="mb-6 text-slate-600 dark:text-slate-400">
                In compliance with GDPR and privacy regulations, you can export
                your personal data. Select the fields you want to include in
                your export.
              </p>

              <form onSubmit={handleExportData} className="space-y-6">
                <div>
                  <label
                    htmlFor="exportFormat"
                    className="block text-sm font-medium text-slate-700 dark:text-slate-300"
                  >
                    Export Format
                  </label>
                  <select
                    id="exportFormat"
                    value={exportFormat}
                    onChange={(e) => setExportFormat(e.target.value)}
                    className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                  >
                    <option value="json">JSON</option>
                    <option value="csv">CSV</option>
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="exportFields"
                    className="block text-sm font-medium text-slate-700 dark:text-slate-300"
                  >
                    Fields to Export
                  </label>
                  <input
                    id="exportFields"
                    type="text"
                    value={exportFields}
                    onChange={(e) => setExportFields(e.target.value)}
                    placeholder="id,email,role"
                    className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-4 py-3 text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-500"
                  />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                    Enter comma-separated field names (e.g., id,email,role)
                  </p>
                </div>

                <button
                  type="submit"
                  disabled={isExporting}
                  className="cursor-pointer rounded-lg bg-primary-600 px-6 py-3 font-semibold text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {isExporting ? "Exporting..." : "Export Data"}
                </button>
              </form>
            </div>

            {exportResult && (
              <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800">
                <h3 className="mb-4 text-xl font-bold text-slate-900 dark:text-slate-100">
                  Export Result
                </h3>
                {exportResult.error ? (
                  <div className="space-y-4">
                    <div className="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800/50 dark:bg-red-900/20">
                      <p className="font-medium text-red-800 dark:text-red-200">
                        {exportResult.error}
                      </p>
                    </div>
                    {exportResult.details && (
                      <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                        <p className="mb-2 text-sm font-medium text-slate-700 dark:text-slate-300">
                          Debug Information:
                        </p>
                        <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs text-slate-600 dark:text-slate-400">
                          {exportResult.details}
                        </pre>
                      </div>
                    )}
                  </div>
                ) : (
                  <pre className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100">
                    {exportResult.format === "csv"
                      ? String(exportResult.data)
                      : JSON.stringify(exportResult.data, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === "support" && (
          <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800">
            <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Support Access
            </h2>
            <p className="mb-6 text-slate-600 dark:text-slate-400">
              Grant temporary access to our customer support team to help
              troubleshoot issues with your account. The support team will be
              able to view your account details and assist you with any
              problems.
            </p>

            {supportError && (
              <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800/50 dark:bg-red-900/20">
                <p className="font-medium text-red-800 dark:text-red-200">
                  {supportError}
                </p>
              </div>
            )}

            {supportSuccess && (
              <div className="mb-6 rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800/50 dark:bg-green-900/20">
                <p className="font-medium text-green-800 dark:text-green-200">
                  {supportSuccess}
                </p>
              </div>
            )}

            {supportToken ? (
              <div className="space-y-6">
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
                  <div className="mb-4 flex items-center justify-between">
                    <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                      Active Support Token
                    </span>
                    <span className="rounded-full bg-green-100 px-2 py-1 text-xs font-semibold text-green-700 dark:bg-green-900/30 dark:text-green-300">
                      Active
                    </span>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <label className="block text-xs text-slate-500 dark:text-slate-400">
                        Token
                      </label>
                      <div className="mt-1 flex items-center gap-2">
                        <code className="flex-1 rounded bg-slate-100 px-3 py-2 text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">
                          {supportToken.token.substring(0, 20)}...
                        </code>
                        <button
                          onClick={() =>
                            copyToClipboard(supportToken.token, "token")
                          }
                          className="cursor-pointer rounded bg-primary-100 px-3 py-2 text-xs font-medium text-primary-700 transition-colors hover:bg-primary-200 dark:bg-primary-900/30 dark:text-primary-300 dark:hover:bg-primary-900/50"
                        >
                          {copiedField === "token" ? "Copied!" : "Copy"}
                        </button>
                      </div>
                    </div>

                    <div>
                      <label className="block text-xs text-slate-500 dark:text-slate-400">
                        Support Login URL
                      </label>
                      <div className="mt-1 flex items-center gap-2">
                        <code className="flex-1 overflow-hidden text-ellipsis rounded bg-slate-100 px-3 py-2 text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">
                          {`${typeof window !== "undefined" ? window.location.origin : ""}/support-login?token=${supportToken.token.substring(0, 10)}...`}
                        </code>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              `${window.location.origin}/support-login?token=${supportToken.token}`,
                              "url"
                            )
                          }
                          className="cursor-pointer rounded bg-primary-100 px-3 py-2 text-xs font-medium text-primary-700 transition-colors hover:bg-primary-200 dark:bg-primary-900/30 dark:text-primary-300 dark:hover:bg-primary-900/50"
                        >
                          {copiedField === "url" ? "Copied!" : "Copy URL"}
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs text-slate-500 dark:text-slate-400">
                          Created
                        </label>
                        <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">
                          {new Date(
                            supportToken.createdAt
                          ).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                <button
                  onClick={handleRevokeSupportToken}
                  disabled={isSupportLoading}
                  className="cursor-pointer rounded-lg bg-red-600 px-6 py-3 font-semibold text-white transition-colors hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {isSupportLoading ? "Revoking..." : "Revoke Support Access"}
                </button>
              </div>
            ) : (
              <div className="space-y-6">
                <button
                  onClick={handleGenerateSupportToken}
                  disabled={isSupportLoading}
                  className="cursor-pointer rounded-lg bg-primary-600 px-6 py-3 font-semibold text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {isSupportLoading
                    ? "Generating..."
                    : "Generate Support Access Token"}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
