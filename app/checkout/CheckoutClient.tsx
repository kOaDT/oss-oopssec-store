"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";

interface CartItem {
  id: string;
  productId: string;
  quantity: number;
  product: {
    id: string;
    name: string;
    price: number;
    imageUrl: string;
  };
}

interface CartData {
  cartItems: CartItem[];
  total: number;
}

import { getStoredUser } from "@/lib/utils/auth";

interface UserAddress {
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
}

interface UserData {
  email: string;
  address: UserAddress | null;
}

export default function CheckoutClient() {
  const [cartData, setCartData] = useState<CartData | null>(null);
  const [userData, setUserData] = useState<UserData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
    const token = localStorage.getItem("authToken");

    const fetchData = async () => {
      try {
        const [cartResponse, userResponse] = await Promise.all([
          fetch(`${baseUrl}/api/cart`, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }),
          fetch(`${baseUrl}/api/user`, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }),
        ]);

        if (!cartResponse.ok) {
          if (cartResponse.status === 401) {
            router.push("/login");
            return;
          }
          throw new Error("Failed to fetch cart");
        }

        if (!userResponse.ok) {
          if (userResponse.status === 401) {
            router.push("/login");
            return;
          }
          throw new Error("Failed to fetch user");
        }

        const cartData = await cartResponse.json();
        const userData = await userResponse.json();

        setCartData(cartData);
        setUserData({
          email: userData.email,
          address: userData.address,
        });
      } catch (error) {
        console.error("Error fetching data:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [router]);

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
      const baseUrl =
        process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
      const token = localStorage.getItem("authToken");

      const response = await fetch(`${baseUrl}/api/orders`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          total: cartData.total,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to create order");
      }

      const order = await response.json();
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
                    ${cartData.total.toFixed(2)}
                  </span>
                </div>
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
