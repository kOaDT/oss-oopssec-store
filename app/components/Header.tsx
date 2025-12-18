import Link from "next/link";
import AuthButton from "./AuthButton";
import CartButton from "./CartButton";

export default function Header() {
  return (
    <header className="sticky top-0 z-50 border-b border-slate-200 bg-white/80 backdrop-blur-md dark:border-slate-800 dark:bg-slate-900/80">
      <nav className="container mx-auto flex items-center justify-between px-4 py-4">
        <Link
          href="/"
          className="text-2xl font-bold tracking-tight text-primary-600 dark:text-primary-400"
        >
          OopsSec Store
        </Link>

        <div className="hidden items-center gap-8 md:flex">
          <Link
            href="/"
            className="text-sm font-medium text-slate-700 transition-colors hover:text-primary-600 dark:text-slate-300 dark:hover:text-primary-400"
          >
            Home
          </Link>
          <Link
            href="/about"
            className="text-sm font-medium text-slate-700 transition-colors hover:text-primary-600 dark:text-slate-300 dark:hover:text-primary-400"
          >
            About
          </Link>
          <Link
            href="/contact"
            className="text-sm font-medium text-slate-700 transition-colors hover:text-primary-600 dark:text-slate-300 dark:hover:text-primary-400"
          >
            Contact
          </Link>
        </div>

        <div className="flex items-center gap-4">
          <CartButton />

          <AuthButton />

          <button
            className="cursor-pointer rounded-lg p-2 text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800 md:hidden"
            aria-label="Menu"
          >
            <svg
              className="h-6 w-6"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 6h16M4 12h16M4 18h16"
              />
            </svg>
          </button>
        </div>
      </nav>
    </header>
  );
}
