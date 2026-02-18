"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import FlagDisplay from "../components/FlagDisplay";
import { getBaseUrl } from "@/lib/config";
import { getStoredUser } from "@/lib/client-auth";
import type { AdminOrder, AdminResponse } from "@/lib/types";

export default function AdminClient() {
  const [adminData, setAdminData] = useState<AdminResponse | null>(null);
  const [orders, setOrders] = useState<AdminOrder[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatingOrderId, setUpdatingOrderId] = useState<string | null>(null);
  const [updateSuccess, setUpdateSuccess] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    const fetchData = async () => {
      try {
        const baseUrl = getBaseUrl();

        const [adminResponse, ordersResponse] = await Promise.all([
          fetch(`${baseUrl}/api/admin`, {
            credentials: "include",
          }),
          fetch(`${baseUrl}/api/orders`, {
            credentials: "include",
          }),
        ]);

        if (!adminResponse.ok) {
          if (adminResponse.status === 401) {
            router.push("/login");
            return;
          }
          if (adminResponse.status === 403) {
            setError("Forbidden: You do not have administrator privileges.");
            setIsLoading(false);
            return;
          }
          throw new Error("Failed to fetch admin data");
        }

        if (!ordersResponse.ok) {
          if (ordersResponse.status === 401) {
            router.push("/login");
            return;
          }
          if (ordersResponse.status === 403) {
            setError("Forbidden: You do not have administrator privileges.");
            setIsLoading(false);
            return;
          }
          throw new Error("Failed to fetch orders");
        }

        const adminData = await adminResponse.json();
        const ordersData = await ordersResponse.json();

        setAdminData(adminData);
        setOrders(ordersData);
      } catch (error) {
        console.error("Error fetching data:", error);
        setError("An error occurred while fetching data.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [router]);

  const handleStatusChange = async (orderId: string, newStatus: string) => {
    setUpdatingOrderId(orderId);
    setUpdateSuccess(null);
    setError(null);

    try {
      const baseUrl = getBaseUrl();

      const response = await fetch(`${baseUrl}/api/orders/${orderId}`, {
        method: "PATCH",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ status: newStatus }),
      });

      if (!response.ok) {
        throw new Error("Failed to update order status");
      }

      const result = await response.json();

      setOrders((prevOrders) =>
        prevOrders.map((order) =>
          order.id === orderId ? { ...order, status: newStatus } : order
        )
      );

      if (result.flag) {
        setUpdateSuccess(result.flag);
      }
    } catch (error) {
      console.error("Error updating order status:", error);
      setError("Failed to update order status. Please try again.");
    } finally {
      setUpdatingOrderId(null);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "PENDING":
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300";
      case "PROCESSING":
        return "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300";
      case "SHIPPED":
        return "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300";
      case "DELIVERED":
        return "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300";
      case "CANCELLED":
        return "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300";
      default:
        return "bg-slate-100 text-slate-800 dark:bg-slate-900/30 dark:text-slate-300";
    }
  };

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-6xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">
                Loading admin panel...
              </p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (error && !adminData) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="rounded-2xl bg-white p-12 text-center shadow-sm dark:bg-slate-800">
            <div className="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30">
              <svg
                className="h-8 w-8 text-red-600 dark:text-red-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </div>
            <h2 className="mb-3 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Access Denied
            </h2>
            <p className="mb-8 text-slate-600 dark:text-slate-400">{error}</p>
            <Link
              href="/"
              className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Go to Home
            </Link>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8 rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800 md:p-12">
          <div className="mb-6 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/30">
                <svg
                  className="h-6 w-6 text-primary-600 dark:text-primary-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
              </div>
              <div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                  Admin Dashboard
                </h2>
                {adminData?.user && (
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Logged in as {adminData.user.email}
                  </p>
                )}
              </div>
            </div>
            <Link
              href="/"
              className="flex items-center gap-1.5 text-sm font-medium text-slate-500 transition-colors hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
            >
              <svg
                className="h-4 w-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M10 19l-7-7m0 0l7-7m-7 7h18"
                />
              </svg>
              Back to site
            </Link>
          </div>

          {adminData?.flag && (
            <FlagDisplay flag={adminData.flag} variant="compact" />
          )}

          {updateSuccess && (
            <>
              {updateSuccess.startsWith("OSS{") ? (
                <FlagDisplay flag={updateSuccess} variant="compact" />
              ) : (
                <div className="mb-6 rounded-xl border-2 border-primary-200 bg-primary-50 p-6 dark:border-primary-800 dark:bg-primary-900/20">
                  <div className="text-center">
                    <p className="text-slate-700 dark:text-slate-300">
                      {updateSuccess}
                    </p>
                  </div>
                </div>
              )}
            </>
          )}

          {error && (
            <div className="mb-6 rounded-xl border-2 border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
              <p className="text-center text-sm text-red-700 dark:text-red-300">
                {error}
              </p>
            </div>
          )}

          <div className="mb-8">
            <h3 className="mb-4 text-xl font-bold text-slate-900 dark:text-slate-100">
              Order Management
            </h3>
            {orders.length === 0 ? (
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-8 text-center dark:border-slate-700 dark:bg-slate-900/50">
                <p className="text-slate-600 dark:text-slate-400">
                  No orders found.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700">
                <table className="w-full">
                  <thead className="bg-slate-50 dark:bg-slate-900/50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                        Order ID
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                        Customer
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                        Total
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-700 dark:text-slate-300">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 bg-white dark:divide-slate-700 dark:bg-slate-800">
                    {orders.map((order) => (
                      <tr key={order.id}>
                        <td className="whitespace-nowrap px-6 py-4">
                          <span className="font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                            {order.id}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm text-slate-900 dark:text-slate-100">
                            {order.user.email}
                          </div>
                          <div className="text-xs text-slate-500 dark:text-slate-400">
                            {order.address.city}, {order.address.country}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-6 py-4">
                          <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                            ${order.total.toFixed(2)}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${getStatusColor(
                              order.status
                            )}`}
                          >
                            {order.status}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <select
                            value={order.status}
                            onChange={(e) =>
                              handleStatusChange(order.id, e.target.value)
                            }
                            disabled={updatingOrderId === order.id}
                            className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                          >
                            <option value="PENDING">PENDING</option>
                            <option value="PROCESSING">PROCESSING</option>
                            <option value="SHIPPED">SHIPPED</option>
                            <option value="DELIVERED">DELIVERED</option>
                            <option value="CANCELLED">CANCELLED</option>
                          </select>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {[
              {
                href: "/admin/products",
                title: "Products",
                description: "Upload and manage product images",
                color:
                  "bg-secondary-50 text-secondary-600 dark:bg-secondary-900/20 dark:text-secondary-400",
                icon: "M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4",
              },
              {
                href: "/admin/analytics",
                title: "Analytics",
                description: "Monitor traffic and visitor data",
                color:
                  "bg-emerald-50 text-emerald-600 dark:bg-emerald-900/20 dark:text-emerald-400",
                icon: "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z",
              },
              {
                href: "/admin/documents",
                title: "Documents",
                description: "Browse and manage secure files",
                color:
                  "bg-slate-100 text-slate-600 dark:bg-slate-700/30 dark:text-slate-400",
                icon: "M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z",
              },
              {
                href: "/admin/reviews",
                title: "Reviews",
                description: "Moderate customer reviews",
                color:
                  "bg-amber-50 text-amber-600 dark:bg-amber-900/20 dark:text-amber-400",
                icon: "M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z",
              },
              {
                href: "/admin/suppliers",
                title: "Supplier Orders",
                description: "Import supplier order confirmations",
                color:
                  "bg-indigo-50 text-indigo-600 dark:bg-indigo-900/20 dark:text-indigo-400",
                icon: "M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4",
              },
            ].map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="group flex items-start gap-4 rounded-xl border border-slate-200 bg-white p-5 transition-all hover:-translate-y-0.5 hover:shadow-md dark:border-slate-700 dark:bg-slate-800/50 dark:hover:bg-slate-800"
              >
                <div
                  className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${item.color}`}
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
                      strokeWidth={1.5}
                      d={item.icon}
                    />
                  </svg>
                </div>
                <div className="min-w-0">
                  <h4 className="font-semibold text-slate-900 group-hover:text-primary-600 dark:text-slate-100 dark:group-hover:text-primary-400">
                    {item.title}
                  </h4>
                  <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
                    {item.description}
                  </p>
                </div>
                <svg
                  className="ml-auto h-5 w-5 shrink-0 translate-x-0 text-slate-300 opacity-0 transition-all group-hover:translate-x-1 group-hover:text-slate-400 group-hover:opacity-100 dark:text-slate-600 dark:group-hover:text-slate-500"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5l7 7-7 7"
                  />
                </svg>
              </Link>
            ))}
          </div>
          <div className="mt-8 text-center text-xs text-slate-500 dark:text-slate-400">
            <p>
              Looking for vulnerabilities? Check the page source for hidden
              links.
            </p>
            <a
              href="/exploits/csrf-attack.html"
              className="mt-2 inline-block text-primary-600 underline hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
              style={{ display: "none" }}
            >
              Special Offer
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
