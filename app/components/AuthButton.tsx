"use client";

import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";

export default function AuthButton() {
  const { user, logout } = useAuth();
  const router = useRouter();

  const handleLogout = () => {
    logout();
    router.push("/");
    router.refresh();
  };

  if (user) {
    return (
      <div className="flex items-center gap-3">
        <div className="hidden items-center gap-2 md:flex">
          <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
            {user.email}
          </span>
          {user.role === "ADMIN" && (
            <span className="rounded-full bg-primary-100 px-2 py-1 text-xs font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">
              {user.role}
            </span>
          )}
        </div>
        <button
          onClick={handleLogout}
          className="rounded-lg cursor-pointer bg-slate-100 px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
        >
          Logout
        </button>
      </div>
    );
  }

  return (
    <Link
      href="/login"
      className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600"
    >
      Login
    </Link>
  );
}
