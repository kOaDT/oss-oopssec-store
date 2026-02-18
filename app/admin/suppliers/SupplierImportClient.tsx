"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { getBaseUrl } from "@/lib/config";
import { getStoredUser } from "@/lib/client-auth";

const EXAMPLE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<order>
  <supplierId>SUP-001</supplierId>
  <orderId>PO-2026-0042</orderId>
  <total>1250.00</total>
  <notes>Standard delivery — net 30 terms</notes>
</order>`;

interface ImportedOrder {
  id: string;
  supplierId: string;
  orderId: string;
  total: number;
  notes: string | null;
  createdAt: string;
}

export default function SupplierImportClient() {
  const [xmlInput, setXmlInput] = useState(EXAMPLE_XML);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportedOrder | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [orders, setOrders] = useState<ImportedOrder[]>([]);
  const router = useRouter();

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    const loadOrders = async () => {
      try {
        const baseUrl = getBaseUrl();
        const response = await fetch(`${baseUrl}/api/admin/suppliers`, {
          credentials: "include",
        });

        if (!response.ok) {
          if (response.status === 401) {
            router.push("/login");
            return;
          }
          if (response.status === 403) {
            setError("Forbidden: You do not have administrator privileges.");
            return;
          }
          throw new Error("Failed to fetch supplier orders");
        }

        const data = await response.json();
        setOrders(data);
      } catch {
        setError("An error occurred while fetching supplier orders.");
      } finally {
        setIsLoading(false);
      }
    };

    loadOrders();
  }, [router]);

  const handleImport = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);
    setResult(null);
    setSuccessMessage(null);

    try {
      const baseUrl = getBaseUrl();

      const response = await fetch(
        `${baseUrl}/api/admin/suppliers/import-order`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/xml",
          },
          body: xmlInput,
        }
      );

      if (!response.ok) {
        if (response.status === 401) {
          router.push("/login");
          return;
        }
        if (response.status === 403) {
          setError("Forbidden: You do not have administrator privileges.");
          return;
        }
        const data = await response.json();
        setError(data.error || "Failed to import order.");
        return;
      }

      const data = await response.json();
      setResult(data.order);
      setSuccessMessage(data.message);
      setOrders((prev) => [data.order, ...prev]);
    } catch {
      setError("An error occurred while importing the order.");
    } finally {
      setIsSubmitting(false);
    }
  };

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

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-4xl">
        <div className="mb-6">
          <Link
            href="/admin"
            className="inline-flex items-center text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
          >
            <svg
              className="mr-1.5 h-4 w-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 19l-7-7 7-7"
              />
            </svg>
            Back to Admin
          </Link>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800 md:p-12">
          <div className="mb-8">
            <h2 className="mb-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Import Supplier Order
            </h2>
            <p className="text-slate-600 dark:text-slate-400">
              Paste a supplier order confirmation in XML format to import it
              into the system. This integration supports the legacy XML-based
              workflow used by our supplier partners.
            </p>
          </div>

          <form onSubmit={handleImport}>
            <div className="mb-6">
              <label
                htmlFor="xml-input"
                className="mb-2 block text-sm font-semibold text-slate-700 dark:text-slate-300"
              >
                XML Order Data
              </label>
              <textarea
                id="xml-input"
                value={xmlInput}
                onChange={(e) => setXmlInput(e.target.value)}
                rows={12}
                className="w-full rounded-lg border border-slate-300 bg-slate-50 px-4 py-3 font-mono text-sm text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100 dark:placeholder-slate-500"
                placeholder="Paste XML here..."
              />
            </div>

            <button
              type="submit"
              disabled={isSubmitting || !xmlInput.trim()}
              className="rounded-lg cursor-pointer bg-primary-600 px-6 py-2.5 font-semibold text-white shadow-sm transition-all hover:bg-primary-700 hover:shadow-lg disabled:opacity-50"
            >
              {isSubmitting ? (
                <span className="inline-flex items-center">
                  <svg
                    className="mr-2 h-4 w-4 animate-spin"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    />
                  </svg>
                  Importing...
                </span>
              ) : (
                "Import Order"
              )}
            </button>
          </form>

          {error && (
            <div className="mt-6 rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
              <p className="text-sm font-medium text-red-800 dark:text-red-300">
                {error}
              </p>
            </div>
          )}

          {successMessage && result && (
            <div className="mt-8">
              <div className="mb-4 rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-800 dark:bg-green-900/20">
                <p className="text-sm font-medium text-green-800 dark:text-green-300">
                  {successMessage}
                </p>
              </div>

              <h3 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">
                Imported Order Details
              </h3>
              <div className="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
                <table className="w-full text-left text-sm">
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    <tr>
                      <td className="bg-slate-50 px-4 py-3 font-medium text-slate-700 dark:bg-slate-900/50 dark:text-slate-300">
                        Internal ID
                      </td>
                      <td className="px-4 py-3 text-slate-900 dark:text-slate-100">
                        {result.id}
                      </td>
                    </tr>
                    <tr>
                      <td className="bg-slate-50 px-4 py-3 font-medium text-slate-700 dark:bg-slate-900/50 dark:text-slate-300">
                        Supplier ID
                      </td>
                      <td className="px-4 py-3 text-slate-900 dark:text-slate-100">
                        {result.supplierId}
                      </td>
                    </tr>
                    <tr>
                      <td className="bg-slate-50 px-4 py-3 font-medium text-slate-700 dark:bg-slate-900/50 dark:text-slate-300">
                        Order ID
                      </td>
                      <td className="px-4 py-3 text-slate-900 dark:text-slate-100">
                        {result.orderId}
                      </td>
                    </tr>
                    <tr>
                      <td className="bg-slate-50 px-4 py-3 font-medium text-slate-700 dark:bg-slate-900/50 dark:text-slate-300">
                        Total
                      </td>
                      <td className="px-4 py-3 text-slate-900 dark:text-slate-100">
                        ${result.total.toFixed(2)}
                      </td>
                    </tr>
                    <tr>
                      <td className="bg-slate-50 px-4 py-3 font-medium text-slate-700 dark:bg-slate-900/50 dark:text-slate-300">
                        Notes
                      </td>
                      <td className="whitespace-pre-wrap px-4 py-3 text-slate-900 dark:text-slate-100">
                        {result.notes || "—"}
                      </td>
                    </tr>
                    <tr>
                      <td className="bg-slate-50 px-4 py-3 font-medium text-slate-700 dark:bg-slate-900/50 dark:text-slate-300">
                        Imported At
                      </td>
                      <td className="px-4 py-3 text-slate-900 dark:text-slate-100">
                        {new Date(result.createdAt).toLocaleString()}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        <div className="mt-10 rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-800 dark:bg-slate-800 md:p-12">
          <h2 className="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
            Imported Orders
          </h2>
          {orders.length === 0 ? (
            <p className="text-slate-500 dark:text-slate-400">
              No supplier orders have been imported yet.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-900/50">
                    <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                      Order ID
                    </th>
                    <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                      Supplier
                    </th>
                    <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                      Total
                    </th>
                    <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                      Notes
                    </th>
                    <th className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">
                      Imported At
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                  {orders.map((order) => (
                    <tr key={order.id}>
                      <td className="px-4 py-3 font-mono text-slate-900 dark:text-slate-100">
                        {order.orderId}
                      </td>
                      <td className="px-4 py-3 text-slate-900 dark:text-slate-100">
                        {order.supplierId}
                      </td>
                      <td className="px-4 py-3 text-slate-900 dark:text-slate-100">
                        ${order.total.toFixed(2)}
                      </td>
                      <td className="max-w-xs truncate px-4 py-3 text-slate-600 dark:text-slate-400">
                        {order.notes || "—"}
                      </td>
                      <td className="px-4 py-3 text-slate-600 dark:text-slate-400">
                        {new Date(order.createdAt).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
