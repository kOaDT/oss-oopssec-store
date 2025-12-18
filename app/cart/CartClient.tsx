"use client";

import { useState, useEffect, useCallback } from "react";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";

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

export default function CartClient() {
  const [cartData, setCartData] = useState<CartData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isUpdating, setIsUpdating] = useState<string | null>(null);
  const router = useRouter();

  const fetchCart = useCallback(async () => {
    try {
      const baseUrl =
        process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
      const token = localStorage.getItem("authToken");

      const response = await fetch(`${baseUrl}/api/cart`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          router.push("/login");
          return;
        }
        throw new Error("Failed to fetch cart");
      }

      const data = await response.json();
      setCartData(data);
    } catch (error) {
      console.error("Error fetching cart:", error);
    } finally {
      setIsLoading(false);
    }
  }, [router]);

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      router.push("/login");
      return;
    }

    fetchCart();
  }, [router, fetchCart]);

  const handleRemoveItem = async (itemId: string) => {
    setIsUpdating(itemId);
    try {
      const baseUrl =
        process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
      const token = localStorage.getItem("authToken");

      const response = await fetch(`${baseUrl}/api/cart/items/${itemId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to remove item");
      }

      await fetchCart();
    } catch (error) {
      console.error("Error removing item:", error);
      alert("Failed to remove item. Please try again.");
    } finally {
      setIsUpdating(null);
    }
  };

  const handleUpdateQuantity = async (itemId: string, newQuantity: number) => {
    if (newQuantity < 1) {
      return;
    }

    setIsUpdating(itemId);
    try {
      const baseUrl =
        process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
      const token = localStorage.getItem("authToken");

      const response = await fetch(`${baseUrl}/api/cart/items/${itemId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ quantity: newQuantity }),
      });

      if (!response.ok) {
        throw new Error("Failed to update quantity");
      }

      await fetchCart();
    } catch (error) {
      console.error("Error updating quantity:", error);
      alert("Failed to update quantity. Please try again.");
    } finally {
      setIsUpdating(null);
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
                Loading cart...
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
            <div className="mb-6 inline-flex h-20 w-20 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-700">
              <svg
                className="h-10 w-10 text-slate-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z"
                />
              </svg>
            </div>
            <h2 className="mb-3 text-2xl font-bold text-slate-900 dark:text-slate-100">
              Your cart is empty
            </h2>
            <p className="mb-8 text-slate-600 dark:text-slate-400">
              Start adding products to your cart to see them here.
            </p>
            <Link
              href="/"
              className="inline-block cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              Continue Shopping
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
            <div className="mb-6 flex items-center justify-between">
              <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                Cart Items ({cartData.cartItems.length})
              </h2>
              <Link
                href="/"
                className="cursor-pointer text-sm font-medium text-primary-600 transition-colors hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
              >
                ← Continue Shopping
              </Link>
            </div>

            <div className="space-y-4">
              {cartData.cartItems.map((item) => (
                <div
                  key={item.id}
                  className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800"
                >
                  <div className="flex flex-col gap-4 sm:flex-row">
                    <Link
                      href={`/products/${item.product.id}`}
                      className="relative aspect-square h-32 w-32 flex-shrink-0 cursor-pointer overflow-hidden rounded-xl bg-slate-100 dark:bg-slate-700"
                    >
                      <Image
                        src={item.product.imageUrl}
                        alt={item.product.name}
                        fill
                        className="object-cover object-center"
                        sizes="128px"
                      />
                    </Link>

                    <div className="flex flex-1 flex-col gap-4 sm:flex-row">
                      <div className="flex-1">
                        <Link
                          href={`/products/${item.product.id}`}
                          className="mb-2 block cursor-pointer text-lg font-semibold text-slate-900 transition-colors hover:text-primary-600 dark:text-slate-100 dark:hover:text-primary-400"
                        >
                          {item.product.name}
                        </Link>
                        <div className="mb-4 text-xl font-bold text-primary-600 dark:text-primary-400">
                          ${item.product.price.toFixed(2)}
                        </div>

                        <div className="flex items-center gap-3">
                          <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                            Quantity:
                          </label>
                          <div className="flex items-center overflow-hidden rounded-lg border-2 border-slate-200 dark:border-slate-700">
                            <button
                              onClick={() =>
                                handleUpdateQuantity(item.id, item.quantity - 1)
                              }
                              disabled={
                                isUpdating === item.id || item.quantity <= 1
                              }
                              className="cursor-pointer bg-white px-3 py-2 text-sm font-medium transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-slate-800 dark:hover:bg-slate-700"
                              aria-label="Decrease quantity"
                            >
                              −
                            </button>
                            <span className="w-12 border-x-2 border-slate-200 p-2 text-center text-sm font-semibold dark:border-slate-700 dark:bg-slate-800">
                              {item.quantity}
                            </span>
                            <button
                              onClick={() =>
                                handleUpdateQuantity(item.id, item.quantity + 1)
                              }
                              disabled={isUpdating === item.id}
                              className="cursor-pointer bg-white px-3 py-2 text-sm font-medium transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-slate-800 dark:hover:bg-slate-700"
                              aria-label="Increase quantity"
                            >
                              +
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="flex flex-col items-end justify-between gap-4 sm:items-start">
                        <div className="text-right sm:text-left">
                          <div className="text-sm text-slate-500 dark:text-slate-400">
                            Subtotal
                          </div>
                          <div className="text-xl font-bold text-slate-900 dark:text-slate-100">
                            ${(item.product.price * item.quantity).toFixed(2)}
                          </div>
                        </div>

                        <button
                          onClick={() => handleRemoveItem(item.id)}
                          disabled={isUpdating === item.id}
                          className="flex cursor-pointer items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400 dark:hover:bg-red-900/30"
                          aria-label="Remove item"
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
                              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                            />
                          </svg>
                          Remove
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
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
                onClick={() => router.push("/checkout")}
                className="w-full rounded-xl cursor-pointer bg-primary-600 px-6 py-3.5 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                Proceed to Checkout
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
