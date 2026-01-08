"use client";

import Image from "next/image";
import Link from "next/link";
import type { ProductCardProps } from "@/lib/types";

export default function ProductCard({
  id,
  name,
  price,
  imageUrl,
}: ProductCardProps) {
  return (
    <Link
      href={`/products/${id}`}
      className="group flex flex-col overflow-hidden rounded-2xl bg-white shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-xl dark:bg-slate-800"
    >
      <div className="relative aspect-square w-full overflow-hidden bg-slate-100 dark:bg-slate-700">
        <Image
          src={imageUrl}
          alt={name}
          fill
          className="object-cover object-center transition-transform duration-500 group-hover:scale-110"
          sizes="(max-width: 768px) 50vw, (max-width: 1200px) 33vw, 25vw"
        />
        <div className="absolute right-3 top-3 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
          <button
            className="cursor-pointer rounded-full bg-white p-2 shadow-lg transition-transform hover:scale-110 dark:bg-slate-700"
            aria-label="Add to cart"
          >
            <svg
              className="h-5 w-5 text-primary-600 dark:text-primary-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 4v16m8-8H4"
              />
            </svg>
          </button>
        </div>
      </div>
      <div className="flex flex-1 flex-col p-4">
        <h3 className="mb-2 line-clamp-2 text-base font-semibold text-slate-900 dark:text-slate-100">
          {name}
        </h3>
        <div className="mt-auto flex items-center justify-between">
          <span className="text-xl font-bold text-primary-600 dark:text-primary-400">
            ${price.toFixed(2)}
          </span>
          <button
            className="cursor-pointer rounded-lg bg-primary-50 px-3 py-1.5 text-sm font-medium text-primary-600 transition-colors hover:bg-primary-100 dark:bg-primary-900/20 dark:text-primary-400 dark:hover:bg-primary-900/30"
            onClick={(e) => {
              e.preventDefault();
            }}
          >
            Add
          </button>
        </div>
      </div>
    </Link>
  );
}
