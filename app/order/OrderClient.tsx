"use client";

import { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import FlagDisplay from "../components/FlagDisplay";
import { getBaseUrl } from "@/lib/config";

interface DeliveryAddress {
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
}

interface Order {
  id: string;
  total: number;
  status: string;
  customerName: string;
  customerEmail: string;
  deliveryAddress: DeliveryAddress;
  flag?: string;
}

import { getStoredUser } from "@/lib/utils/auth";

export default function OrderClient() {
  const [order, setOrder] = useState<Order | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const searchParams = useSearchParams();
  const orderId = searchParams.get("id");
  const flagFromUrl = searchParams.get("flag");

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    if (!orderId) {
      router.push("/");
      return;
    }

    const fetchOrder = async () => {
      try {
        const baseUrl = getBaseUrl();
        const token = localStorage.getItem("authToken");

        const response = await fetch(`${baseUrl}/api/orders/${orderId}`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!response.ok) {
          if (response.status === 401) {
            router.push("/login");
            return;
          }
          if (response.status === 404) {
            router.push("/");
            return;
          }
          throw new Error("Failed to fetch order");
        }

        const data = await response.json();
        if (flagFromUrl) {
          data.flag = decodeURIComponent(flagFromUrl);
        }
        setOrder(data);
      } catch (error) {
        console.error("Error fetching order:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchOrder();
  }, [orderId, flagFromUrl, router]);

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">
                Loading order...
              </p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (!order) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="rounded-2xl bg-white p-12 text-center shadow-sm dark:bg-slate-800">
            <h2 className="mb-3 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Order not found
            </h2>
            <p className="mb-8 text-slate-600 dark:text-slate-400">
              The order you are looking for does not exist.
            </p>
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
      <div className="mx-auto max-w-4xl">
        <div className="rounded-2xl bg-white p-8 shadow-sm dark:bg-slate-800 md:p-12">
          <div className="mb-8 text-center">
            <div className="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/30">
              <svg
                className="h-8 w-8 text-green-600 dark:text-green-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 13l4 4L19 7"
                />
              </svg>
            </div>
            <h2 className="mb-2 text-3xl font-bold text-slate-900 dark:text-slate-100">
              Order Confirmed!
            </h2>
            <p className="text-slate-600 dark:text-slate-400">
              Your order has been successfully placed.
            </p>
          </div>

          {order.flag && <FlagDisplay flag={order.flag} title="Flag" />}

          <div className="mb-8 space-y-6 rounded-xl border border-slate-200 bg-slate-50 p-6 dark:border-slate-700 dark:bg-slate-900/50">
            <div className="flex justify-between border-b border-slate-200 pb-4 dark:border-slate-700">
              <span className="font-medium text-slate-700 dark:text-slate-300">
                Order ID
              </span>
              <span className="font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                {order.id}
              </span>
            </div>
            <div className="flex justify-between border-b border-slate-200 pb-4 dark:border-slate-700">
              <span className="font-medium text-slate-700 dark:text-slate-300">
                Customer Name
              </span>
              <span className="font-semibold text-slate-900 dark:text-slate-100">
                {order.customerName}
              </span>
            </div>
            <div className="flex justify-between border-b border-slate-200 pb-4 dark:border-slate-700">
              <span className="font-medium text-slate-700 dark:text-slate-300">
                Customer Email
              </span>
              <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {order.customerEmail}
              </span>
            </div>
            <div className="border-b border-slate-200 pb-4 dark:border-slate-700">
              <span className="mb-2 block font-medium text-slate-700 dark:text-slate-300">
                Delivery Address
              </span>
              <div className="text-sm text-slate-900 dark:text-slate-100">
                <p className="font-semibold">{order.deliveryAddress.street}</p>
                <p>
                  {order.deliveryAddress.city}, {order.deliveryAddress.state}{" "}
                  {order.deliveryAddress.zipCode}
                </p>
                <p>{order.deliveryAddress.country}</p>
              </div>
            </div>
            <div className="flex justify-between border-b border-slate-200 pb-4 dark:border-slate-700">
              <span className="font-medium text-slate-700 dark:text-slate-300">
                Status
              </span>
              <span className="rounded-full bg-primary-100 px-3 py-1 text-sm font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">
                {order.status}
              </span>
            </div>
            <div className="flex justify-between border-b border-slate-200 pb-4 dark:border-slate-700">
              <span className="font-medium text-slate-700 dark:text-slate-300">
                Total Amount
              </span>
              <span className="text-xl font-bold text-primary-600 dark:text-primary-400">
                ${order.total.toFixed(2)}
              </span>
            </div>
          </div>

          <div className="flex flex-col gap-4 sm:flex-row sm:justify-center">
            <Link
              href="/"
              className="cursor-pointer rounded-xl bg-primary-600 px-6 py-3 text-center font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Continue Shopping
            </Link>
            <Link
              href="/cart"
              className="cursor-pointer rounded-xl border-2 border-slate-300 bg-white px-6 py-3 text-center font-semibold text-slate-700 transition-all hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
            >
              View Cart
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
