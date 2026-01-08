"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import FlagDisplay from "../../components/FlagDisplay";

interface Order {
  id: string;
  total: number;
  status: string;
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
  flag?: string;
}

const getStoredUser = () => {
  if (typeof window === "undefined") return null;
  const storedUser = localStorage.getItem("user");
  if (storedUser) {
    try {
      return JSON.parse(storedUser);
    } catch {
      localStorage.removeItem("user");
      localStorage.removeItem("authToken");
      return null;
    }
  }
  return null;
};

export default function OrderSearchClient() {
  const [status, setStatus] = useState("");
  const [allOrders, setAllOrders] = useState<Order[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [flag, setFlag] = useState<string | null>(null);
  const router = useRouter();

  const filteredOrders = useMemo(() => {
    if (!status) {
      return allOrders;
    }
    return allOrders.filter((order) => order.status === status);
  }, [allOrders, status]);

  const fetchOrders = useCallback(async () => {
    setError(null);
    setFlag(null);
    setIsLoading(true);

    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    try {
      const baseUrl =
        process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
      const token = localStorage.getItem("authToken");

      const response = await fetch(`${baseUrl}/api/orders/search`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({}),
      });

      if (!response.ok) {
        if (response.status === 401) {
          router.push("/login");
          return;
        }
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to fetch orders");
      }

      const data = await response.json();
      const results = Array.isArray(data.orders) ? data.orders : [];

      if (data.flag) {
        setFlag(data.flag);
      }

      const filteredResults = results.filter(
        (order: Order) => order.id && order.status
      );
      setAllOrders(filteredResults);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
      setAllOrders([]);
    } finally {
      setIsLoading(false);
    }
  }, [router]);

  useEffect(() => {
    fetchOrders();
  }, [fetchOrders]);

  return (
    <section className="container mx-auto px-4 py-16">
      <div className="mx-auto max-w-4xl">
        <div className="mb-8">
          <h2 className="mb-4 text-2xl font-bold text-slate-900 dark:text-slate-100">
            My Orders
          </h2>
          <p className="mb-6 text-slate-600 dark:text-slate-400">
            Filter your order history by status to find specific orders quickly.
          </p>

          <div className="mb-8">
            <div className="flex flex-col gap-4 sm:flex-row">
              <div className="flex-1">
                <label
                  htmlFor="status"
                  className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300"
                >
                  Filter by Status
                </label>
                <select
                  id="status"
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 bg-white px-4 py-2 text-slate-900 shadow-sm focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100 dark:focus:border-primary-400 dark:focus:ring-primary-400"
                >
                  <option value="">All orders</option>
                  <option value="PENDING">Pending</option>
                  <option value="PROCESSING">Processing</option>
                  <option value="SHIPPED">Shipped</option>
                  <option value="DELIVERED">Delivered</option>
                  <option value="CANCELLED">Cancelled</option>
                </select>
              </div>
            </div>
          </div>

          {error && (
            <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400">
              {error}
            </div>
          )}

          {flag && (
            <div className="mb-6">
              <FlagDisplay flag={flag} title="Flag Retrieved" />
            </div>
          )}

          {isLoading && (
            <div className="flex items-center justify-center py-20">
              <div className="text-center">
                <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
                <p className="text-slate-600 dark:text-slate-400">
                  Loading orders...
                </p>
              </div>
            </div>
          )}

          {filteredOrders.length > 0 && !isLoading && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                {status
                  ? `Filtered Results (${filteredOrders.length})`
                  : `All Orders (${filteredOrders.length})`}
              </h3>
              <div className="space-y-4">
                {filteredOrders.map((order) => (
                  <div
                    key={order.id}
                    className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800"
                  >
                    <div className="mb-4 flex items-center justify-between">
                      <div>
                        <h4 className="font-mono text-lg font-semibold text-slate-900 dark:text-slate-100">
                          {order.id}
                        </h4>
                        <p className="text-sm text-slate-600 dark:text-slate-400">
                          {order.street}, {order.city}, {order.state}{" "}
                          {order.zipCode}
                        </p>
                      </div>
                      <div className="text-right">
                        <span className="mb-2 block rounded-full bg-primary-100 px-3 py-1 text-sm font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">
                          {order.status}
                        </span>
                        <span className="text-lg font-bold text-primary-600 dark:text-primary-400">
                          $
                          {typeof order.total === "number"
                            ? order.total.toFixed(2)
                            : order.total}
                        </span>
                      </div>
                    </div>
                    <Link
                      href={`/order?id=${order.id}`}
                      className="text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
                    >
                      View Details →
                    </Link>
                  </div>
                ))}
              </div>
            </div>
          )}

          {filteredOrders.length === 0 &&
            !isLoading &&
            !error &&
            allOrders.length > 0 &&
            status && (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-8 text-center dark:border-slate-700 dark:bg-slate-900/50">
                <p className="text-slate-600 dark:text-slate-400">
                  No orders found with the selected status.
                </p>
              </div>
            )}

          {allOrders.length === 0 && !isLoading && !error && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-8 text-center dark:border-slate-700 dark:bg-slate-900/50">
              <p className="text-slate-600 dark:text-slate-400">
                No orders found.
              </p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
