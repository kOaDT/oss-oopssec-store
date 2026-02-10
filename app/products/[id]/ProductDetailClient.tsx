"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api, ApiError } from "@/lib/api";
import type { Review, ProductDetailClientProps } from "@/lib/types";
import AddToWishlistButton from "@/app/components/AddToWishlistButton";

export default function ProductDetailClient({
  product,
}: ProductDetailClientProps) {
  const { user } = useAuth();
  const [quantity, setQuantity] = useState(1);
  const [isLoading, setIsLoading] = useState(false);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [reviewContent, setReviewContent] = useState("");
  const [isSubmittingReview, setIsSubmittingReview] = useState(false);
  const [isLoadingReviews, setIsLoadingReviews] = useState(true);
  const reviewRefs = useRef<{ [key: string]: HTMLDivElement | null }>({});
  const router = useRouter();
  const maxQuantity = 99;

  const fetchReviews = useCallback(async () => {
    try {
      setIsLoadingReviews(true);
      const data = await api.get<Review[]>(
        `/api/products/${product.id}/reviews`
      );
      setReviews(data);
    } catch (error) {
      console.error("Error fetching reviews:", error);
    } finally {
      setIsLoadingReviews(false);
    }
  }, [product.id]);

  useEffect(() => {
    fetchReviews();
  }, [fetchReviews]);

  useEffect(() => {
    reviews.forEach((review) => {
      const reviewElement = reviewRefs.current[review.id];
      if (reviewElement && reviewElement.innerHTML !== review.content) {
        reviewElement.innerHTML = review.content;
        const scripts = reviewElement.querySelectorAll("script");
        scripts.forEach((oldScript) => {
          const newScript = document.createElement("script");
          Array.from(oldScript.attributes).forEach((attr) => {
            newScript.setAttribute(attr.name, attr.value);
          });
          newScript.textContent = oldScript.textContent;
          oldScript.parentNode?.replaceChild(newScript, oldScript);
        });
      }
    });
  }, [reviews]);

  const handleSubmitReview = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!reviewContent.trim()) {
      return;
    }

    setIsSubmittingReview(true);

    try {
      await api.post(`/api/products/${product.id}/reviews`, {
        content: reviewContent,
      });

      setReviewContent("");
      await fetchReviews();
    } catch (error) {
      console.error("Error submitting review:", error);
      alert("Failed to submit review. Please try again.");
    } finally {
      setIsSubmittingReview(false);
    }
  };

  const handleDecrement = () => {
    if (quantity > 1) {
      setQuantity(quantity - 1);
    }
  };

  const handleIncrement = () => {
    if (quantity < maxQuantity) {
      setQuantity(quantity + 1);
    }
  };

  const handleQuantityChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = parseInt(e.target.value, 10);
    if (!isNaN(value) && value >= 1 && value <= maxQuantity) {
      setQuantity(value);
    }
  };

  const handleAddToCart = async () => {
    if (!user) {
      router.push("/login");
      return;
    }

    if (quantity > maxQuantity) {
      alert(`Maximum order limit is ${maxQuantity} per customer`);
      return;
    }

    setIsLoading(true);

    try {
      await api.post("/api/cart/add", {
        productId: product.id,
        quantity: quantity,
      });

      router.push("/cart");
    } catch (error) {
      console.error("Error adding to cart:", error);
      const errorMessage =
        error instanceof ApiError
          ? error.message
          : "Failed to add item to cart. Please try again.";
      alert(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <section className="container mx-auto px-4 py-6 lg:px-6 lg:py-10">
      <nav
        className="mb-6 text-sm text-slate-500 dark:text-slate-400"
        aria-label="Breadcrumb"
      >
        <ol className="flex items-center gap-2">
          <li>
            <Link
              href="/"
              className="cursor-pointer transition-colors hover:text-primary-600 hover:underline dark:hover:text-primary-400"
            >
              Back to products
            </Link>
          </li>
          <li>•</li>
          <li className="text-slate-700 dark:text-slate-300">{product.name}</li>
        </ol>
      </nav>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-2 lg:items-start">
        <div className="space-y-6">
          <div className="overflow-hidden rounded-2xl bg-white shadow-sm dark:bg-slate-800">
            <div className="relative aspect-square w-full overflow-hidden bg-slate-100 dark:bg-slate-700">
              {product.imageUrl.startsWith("/api/uploads/") &&
              product.imageUrl.endsWith(".svg") ? (
                <object
                  data={product.imageUrl}
                  type="image/svg+xml"
                  className="h-full w-full object-cover"
                >
                  <img
                    src={product.imageUrl}
                    alt={product.name}
                    className="h-full w-full object-cover object-center"
                  />
                </object>
              ) : (
                <Image
                  src={product.imageUrl}
                  alt={product.name}
                  fill
                  className="object-cover object-center"
                  sizes="(max-width: 768px) 100vw, 50vw"
                  quality={90}
                  priority
                />
              )}
            </div>
          </div>

          {product.description && (
            <div className="rounded-2xl bg-white p-6 shadow-sm dark:bg-slate-800">
              <h2 className="mb-3 text-lg font-semibold text-slate-900 dark:text-slate-100">
                About this product
              </h2>
              <p className="leading-relaxed text-slate-600 dark:text-slate-400">
                {product.description}
              </p>
            </div>
          )}
        </div>

        <aside className="sticky top-6">
          <div className="rounded-2xl bg-white p-6 shadow-sm dark:bg-slate-800 lg:p-8">
            <div className="mb-6 flex items-start justify-between">
              <h1 className="flex-1 text-2xl font-extrabold leading-tight text-slate-900 dark:text-slate-100 lg:text-3xl">
                {product.name}
              </h1>
              <AddToWishlistButton productId={product.id} />
            </div>

            <div className="mb-6">
              <div className="text-4xl font-extrabold text-primary-600 dark:text-primary-400 lg:text-5xl">
                ${product.price.toFixed(2)}
              </div>
              <div className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                Inclusive of all taxes
              </div>
            </div>

            <div className="mb-6 flex items-center gap-4 rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-700/50">
              <div className="flex-1">
                <div className="font-semibold text-slate-900 dark:text-slate-100">
                  Delivery in 10-15 mins
                </div>
                <div className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
                  Shipment of {quantity} item{quantity !== 1 ? "s" : ""}
                </div>
              </div>
              <div className="rounded-full bg-primary-100 px-3 py-1.5 text-sm font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-400">
                In Stock
              </div>
            </div>

            <div className="mb-6">
              <label
                htmlFor="qty"
                className="mb-3 block text-sm font-semibold text-slate-900 dark:text-slate-100"
              >
                Quantity{" "}
                <span className="font-normal text-slate-500 dark:text-slate-400">
                  ({maxQuantity} available)
                </span>
              </label>
              <div className="flex items-center gap-3">
                <div className="flex items-center overflow-hidden rounded-xl border-2 border-slate-200 dark:border-slate-700">
                  <button
                    onClick={handleDecrement}
                    className="cursor-pointer bg-white px-4 py-3 text-lg font-medium transition-colors hover:bg-slate-50 dark:bg-slate-800 dark:hover:bg-slate-700"
                    aria-label="Decrease quantity"
                  >
                    −
                  </button>
                  <input
                    id="qty"
                    type="number"
                    value={quantity}
                    min={1}
                    max={maxQuantity}
                    onChange={handleQuantityChange}
                    className="w-20 border-x-2 border-slate-200 p-2 text-center font-semibold outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                    aria-label="Quantity"
                  />
                  <button
                    onClick={handleIncrement}
                    className="cursor-pointer bg-white px-4 py-3 text-lg font-medium transition-colors hover:bg-slate-50 dark:bg-slate-800 dark:hover:bg-slate-700"
                    aria-label="Increase quantity"
                  >
                    +
                  </button>
                </div>

                <button
                  onClick={handleAddToCart}
                  disabled={isLoading}
                  className="flex-1 cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600 lg:flex-none"
                >
                  {isLoading ? "Adding..." : "Add to Cart"}
                </button>
              </div>
              <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                Max order limit:{" "}
                <span className="font-medium text-slate-700 dark:text-slate-300">
                  {maxQuantity} per customer
                </span>
              </p>
            </div>

            <hr className="my-6 border-slate-200 dark:border-slate-700" />

            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
              <div>
                <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">
                  Price
                </dt>
                <dd className="mt-1 font-semibold text-slate-900 dark:text-slate-100">
                  ${product.price.toFixed(2)}
                </dd>
              </div>
              <div>
                <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">
                  Availability
                </dt>
                <dd className="mt-1 font-semibold text-primary-600 dark:text-primary-400">
                  In Stock
                </dd>
              </div>
            </dl>
          </div>

          <div className="fixed bottom-4 left-0 right-0 z-10 px-4 lg:hidden">
            <div className="mx-auto max-w-3xl">
              <button
                onClick={handleAddToCart}
                disabled={isLoading}
                className="w-full cursor-pointer rounded-xl bg-primary-600 py-3.5 font-semibold text-white shadow-lg transition-all hover:bg-primary-700 hover:shadow-xl disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
              >
                {isLoading
                  ? "Adding..."
                  : `Add to Cart — ${(product.price * quantity).toFixed(2)}`}
              </button>
            </div>
          </div>
        </aside>
      </div>

      <div className="mt-12 border-t border-slate-200 pt-12 dark:border-slate-700">
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Reviews
          </h2>
          <p className="mt-2 text-slate-600 dark:text-slate-400">
            Share your thoughts about this product
          </p>
        </div>

        <div className="mb-8 rounded-2xl bg-white p-6 shadow-sm dark:bg-slate-800">
          <form onSubmit={handleSubmitReview} className="space-y-4">
            <div>
              <label
                htmlFor="review"
                className="mb-2 block text-sm font-semibold text-slate-900 dark:text-slate-100"
              >
                Write a review
                <span className="ml-2 text-xs font-normal text-slate-500 dark:text-slate-400">
                  ({user?.email || "anonymous"})
                </span>
              </label>
              <textarea
                id="review"
                value={reviewContent}
                onChange={(e) => setReviewContent(e.target.value)}
                rows={4}
                className="w-full rounded-xl border-2 border-slate-200 p-4 text-slate-900 outline-none transition-colors focus:border-primary-500 dark:border-slate-700 dark:bg-slate-700 dark:text-slate-100 dark:focus:border-primary-400"
                placeholder="Share your experience with this product..."
              />
            </div>
            <button
              type="submit"
              disabled={isSubmittingReview || !reviewContent.trim()}
              className="cursor-pointer rounded-xl bg-primary-600 px-6 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-700 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-50 dark:bg-primary-500 dark:hover:bg-primary-600"
            >
              {isSubmittingReview ? "Submitting..." : "Submit Review"}
            </button>
          </form>
        </div>

        <div className="space-y-6">
          {isLoadingReviews ? (
            <div className="text-center text-slate-500 dark:text-slate-400">
              Loading reviews...
            </div>
          ) : reviews.length === 0 ? (
            <div className="rounded-2xl bg-white p-8 text-center shadow-sm dark:bg-slate-800">
              <p className="text-slate-600 dark:text-slate-400">
                No reviews yet. Be the first to review this product!
              </p>
            </div>
          ) : (
            reviews.map((review) => (
              <div
                key={review.id}
                className="rounded-2xl bg-white p-6 shadow-sm dark:bg-slate-800"
              >
                <div className="mb-3 flex items-center justify-between">
                  <div className="font-semibold text-slate-900 dark:text-slate-100">
                    {review.author}
                  </div>
                  <div className="text-sm text-slate-500 dark:text-slate-400">
                    {new Date(review.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <div
                  ref={(el) => {
                    reviewRefs.current[review.id] = el;
                  }}
                  className="text-slate-700 dark:text-slate-300"
                />
              </div>
            ))
          )}
        </div>
      </div>
    </section>
  );
}
