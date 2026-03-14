"use client";

import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";
import { useMounted } from "@/hooks/useMounted";

export default function OrderSearchLink() {
  const { user } = useAuth();
  const mounted = useMounted();

  if (!mounted || !user) {
    return null;
  }

  return (
    <Link
      href="/orders/search"
      className="text-sm font-medium text-slate-700 transition-colors hover:text-primary-600 dark:text-slate-300 dark:hover:text-primary-400"
    >
      My Orders
    </Link>
  );
}
