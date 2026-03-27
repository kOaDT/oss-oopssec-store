"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import { api, ApiError } from "@/lib/api";
import { getStoredUser } from "@/lib/client-auth";
import type { CartData, UserData } from "@/lib/types";

export default function CheckoutClient() {
  const [cartData, setCartData] = useState<CartData | null>(null);
  const [userData, setUserData] = useState<UserData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [couponCode, setCouponCode] = useState("");
  const [couponOpen, setCouponOpen] = useState(false);
  const [couponApplying, setCouponApplying] = useState(false);
  const [couponError, setCouponError] = useState<string | null>(null);
  const [discountedTotal, setDiscountedTotal] = useState<number | null>(null);
  const [discountPercent, setDiscountPercent] = useState<number | null>(null);
  const router = useRouter();

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    const fetchData = async () => {
      try {
        const [cartData, userData] = await Promise.all([
          api.get<CartData>("/api/cart"),
          api.get<UserData>("/api/user"),
        ]);

        setCartData(cartData);
        setUserData({
          email: userData.email,
          address: userData.address,
        });

        const saved = localStorage.getItem("checkout_coupon");
        if (saved) {
          const { code, discountPercent } = JSON.parse(saved) as {
            code: string;
            discountPercent: number;
          };
          setCouponCode(code);
          setDiscountPercent(discountPercent);
          setDiscountedTotal(cartData.total * (1 - discountPercent / 100));
          setCouponOpen(true);
        }
      } catch (error) {
        console.error("Error fetching data:", error);
        if (error instanceof ApiError && error.status === 401) {
          router.push("/login");
          return;
        }
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [router]);

  const handleApplyCoupon = async () => {
    if (!cartData || !couponCode.trim()) return;

    setCouponApplying(true);
    setCouponError(null);

    try {
      const result = await api.post<{
        discountedTotal: number;
        discountPercent: number;
        flag?: string;
      }>("/api/coupon/apply", {
        code: couponCode.trim(),
        cartTotal: cartData.total,
      });

      setDiscountedTotal(result.discountedTotal);
      setDiscountPercent(result.discountPercent);
      localStorage.setItem(
        "checkout_coupon",
        JSON.stringify({
          code: couponCode.trim(),
          discountPercent: result.discountPercent,
        })
      );
    } catch (error) {
      if (error instanceof ApiError) {
        setCouponError(error.message || "Failed to apply coupon.");
      } else {
        setCouponError("Failed to apply coupon.");
      }
      setDiscountedTotal(null);
      setDiscountPercent(null);
    } finally {
      setCouponApplying(false);
    }
  };

  const handleRemoveCoupon = () => {
    setDiscountedTotal(null);
    setDiscountPercent(null);
    setCouponCode("");
    setCouponError(null);
    localStorage.removeItem("checkout_coupon");
  };

  const handlePayment = async () => {
    if (!cartData || cartData.cartItems.length === 0) {
      return;
    }

    const paymentSecret = process.env.NEXT_PUBLIC_PAYMENT_SECRET;

    if (paymentSecret !== "T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=") {
      alert("Payment failed: Payment method is not properly configured.");
      return;
    }

    setIsProcessing(true);
    try {
      const saved = localStorage.getItem("checkout_coupon");
      const appliedCouponCode = saved
        ? (JSON.parse(saved) as { code: string }).code
        : undefined;

      const order = await api.post<{
        id: string;
        total: number;
        status: string;
        flag?: string;
      }>("/api/orders", {
        total: discountedTotal ?? cartData.total,
        ...(appliedCouponCode ? { couponCode: appliedCouponCode } : {}),
      });
      localStorage.removeItem("checkout_coupon");
      const url = order.flag
        ? `/order?id=${order.id}&flag=${encodeURIComponent(order.flag)}`
        : `/order?id=${order.id}`;
      router.push(url);
    } catch (error) {
      console.error("Error processing payment:", error);
      alert("Failed to process payment. Please try again.");
      setIsProcessing(false);
    }
  };

  if (isLoading) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
              <p className="text-slate-600 dark:text-slate-400">
                Loading checkout...
              </p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  if (!cartData || cartData.cartItems.length === 0) {
    return (
      <section className="container mx-auto px-4 py-16">
        <div className="mx-auto max-w-4xl">
          <div className="rounded-2xl bg-white p-12 text-center shadow-sm dark:bg-slate-800">
            <h2 className="mb-3 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Your cart is empty
            </h2>
            <p className="mb-8 text-slate-600 dark:text-slate-400">
              Add items to your cart before checkout.
            </p>
            <Link
              href="/cart"
              className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Back to Cart
            </Link>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="container mx-auto px-4 py-8 lg:px-6 lg:py-12">
      <div className="mx-auto max-w-6xl">
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <div className="mb-6">
              <Link
                href="/cart"
                className="inline-flex cursor-pointer items-center gap-2 text-sm font-medium text-primary-600 transition-colors hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
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
                    d="M15 19l-7-7 7-7"
                  />
                </svg>
                Back to Cart
              </Link>
            </div>

            <div className="space-y-6">
              <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h2 className="mb-4 text-xl font-bold text-slate-900 dark:text-slate-100">
                  Delivery Address
                </h2>
                {userData?.address ? (
                  <div className="space-y-2 text-slate-700 dark:text-slate-300">
                    <p className="font-semibold">
                      {userData.email.split("@")[0].charAt(0).toUpperCase() +
                        userData.email.split("@")[0].slice(1)}
                    </p>
                    <p>{userData.address.street}</p>
                    <p>
                      {userData.address.city}, {userData.address.state}{" "}
                      {userData.address.zipCode}
                    </p>
                    <p>{userData.address.country}</p>
                  </div>
                ) : (
                  <p className="text-slate-600 dark:text-slate-400">
                    No delivery address configured
                  </p>
                )}
              </div>

              <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                <h2 className="mb-4 text-xl font-bold text-slate-900 dark:text-slate-100">
                  Order Items
                </h2>
                <div className="space-y-4">
                  {cartData.cartItems.map((item) => (
                    <div
                      key={item.id}
                      className="flex items-center gap-4 border-b border-slate-200 pb-4 last:border-b-0 last:pb-0 dark:border-slate-700"
                    >
                      <div className="relative aspect-square h-20 w-20 flex-shrink-0 overflow-hidden rounded-lg bg-slate-100 dark:bg-slate-700">
                        <Image
                          src={item.product.imageUrl}
                          alt={item.product.name}
                          fill
                          className="object-cover object-center"
                          sizes="80px"
                        />
                      </div>
                      <div className="flex-1">
                        <h3 className="font-semibold text-slate-900 dark:text-slate-100">
                          {item.product.name}
                        </h3>
                        <p className="text-sm text-slate-600 dark:text-slate-400">
                          Quantity: {item.quantity}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="font-bold text-slate-900 dark:text-slate-100">
                          ${(item.product.price * item.quantity).toFixed(2)}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="lg:col-span-1">
            <div className="sticky top-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
              <h2 className="mb-6 text-xl font-bold text-slate-900 dark:text-slate-100">
                Order Summary
              </h2>

              <div className="mb-6 space-y-3">
                <div className="flex justify-between text-sm text-slate-600 dark:text-slate-400">
                  <span>Subtotal</span>
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    ${cartData.total.toFixed(2)}
                  </span>
                </div>
                {discountedTotal !== null && discountPercent !== null && (
                  <div className="flex justify-between text-sm text-green-600 dark:text-green-400">
                    <span>Discount ({discountPercent}% off)</span>
                    <span className="font-semibold">
                      -${(cartData.total - discountedTotal).toFixed(2)}
                    </span>
                  </div>
                )}
                <div className="flex justify-between text-sm text-slate-600 dark:text-slate-400">
                  <span>Shipping</span>
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    Free
                  </span>
                </div>
                <div className="flex justify-between text-sm text-slate-600 dark:text-slate-400">
                  <span>Tax</span>
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    Included
                  </span>
                </div>
                <hr className="border-slate-200 dark:border-slate-700" />
                <div className="flex justify-between text-lg font-bold text-slate-900 dark:text-slate-100">
                  <span>Total</span>
                  <span className="text-primary-600 dark:text-primary-400">
                    ${(discountedTotal ?? cartData.total).toFixed(2)}
                  </span>
                </div>
              </div>

              <div className="mb-4">
                <button
                  type="button"
                  onClick={() => setCouponOpen((o) => !o)}
                  className="flex w-full cursor-pointer items-center justify-between text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
                >
                  <span>Have a promo code?</span>
                  <svg
                    className={`h-4 w-4 transition-transform ${couponOpen ? "rotate-180" : ""}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </button>

                {couponOpen && (
                  <div className="mt-3 space-y-2">
                    {discountedTotal !== null && discountPercent !== null ? (
                      <div className="flex items-center justify-between rounded-lg border border-green-200 bg-green-50 px-3 py-2 dark:border-green-800 dark:bg-green-900/20">
                        <span className="text-sm font-medium text-green-700 dark:text-green-400">
                          <span className="font-mono">{couponCode}</span> —{" "}
                          {discountPercent}% off
                        </span>
                        <button
                          type="button"
                          onClick={handleRemoveCoupon}
                          className="ml-2 cursor-pointer text-xs text-green-600 underline hover:text-green-800 dark:text-green-400 dark:hover:text-green-200"
                        >
                          Remove
                        </button>
                      </div>
                    ) : (
                      <div className="flex flex-col gap-2">
                        <input
                          type="text"
                          value={couponCode}
                          onChange={(e) => setCouponCode(e.target.value)}
                          placeholder="Enter code"
                          className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 placeholder-slate-400 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
                        />
                        <button
                          type="button"
                          onClick={handleApplyCoupon}
                          disabled={couponApplying || !couponCode.trim()}
                          className="w-full cursor-pointer rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
                        >
                          {couponApplying ? "Applying..." : "Apply"}
                        </button>
                      </div>
                    )}
                    {couponError && (
                      <p className="text-sm text-red-600 dark:text-red-400">
                        {couponError}
                      </p>
                    )}
                  </div>
                )}
              </div>

              <button
                onClick={handlePayment}
                disabled={isProcessing}
                className="w-full cursor-pointer rounded-xl bg-primary-600 px-6 py-3.5 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                {isProcessing ? "Processing..." : "Complete Payment"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
