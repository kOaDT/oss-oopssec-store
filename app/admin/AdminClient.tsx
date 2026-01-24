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
        const token = localStorage.getItem("authToken");

        const [adminResponse, ordersResponse] = await Promise.all([
          fetch(`${baseUrl}/api/admin`, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }),
          fetch(`${baseUrl}/api/orders`, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
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
      const token = localStorage.getItem("authToken");

      const response = await fetch(`${baseUrl}/api/orders/${orderId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
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
          <div className="mb-6 text-center">
            <div className="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/30">
              <svg
                className="h-8 w-8 text-primary-600 dark:text-primary-400"
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
            <h2 className="mb-2 text-3xl font-bold text-slate-900 dark:text-slate-100">
              Admin Dashboard
            </h2>
            {adminData?.user && (
              <p className="mb-4 text-slate-600 dark:text-slate-400">
                Logged in as {adminData.user.email}
              </p>
            )}
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
          <div className="flex flex-wrap justify-center gap-4">
            <Link
              href="/"
              className="cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Go to Home
            </Link>
            <Link
              href="/admin/products"
              className="cursor-pointer rounded-xl bg-secondary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-secondary-700 hover:shadow-lg dark:bg-secondary-500 dark:hover:bg-secondary-600"
            >
              Manage Products
            </Link>
            <Link
              href="/admin/analytics"
              className="cursor-pointer rounded-xl bg-emerald-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-emerald-700 hover:shadow-lg dark:bg-emerald-500 dark:hover:bg-emerald-600"
            >
              Visitor Analytics
            </Link>
            <Link
              href="/admin/documents"
              className="cursor-pointer rounded-xl bg-slate-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-slate-700 hover:shadow-lg dark:bg-slate-500 dark:hover:bg-slate-600"
            >
              Documents
            </Link>
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
