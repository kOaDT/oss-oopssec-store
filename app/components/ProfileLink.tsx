"use client";

import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";

export default function ProfileLink() {
  const { user } = useAuth();

  if (!user) {
    return null;
  }

  return (
    <Link
      href="/profile"
      className="text-sm font-medium text-slate-700 transition-colors hover:text-primary-600 dark:text-slate-300 dark:hover:text-primary-400"
    >
      Profile
    </Link>
  );
}
