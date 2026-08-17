"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import AuthButton from "./AuthButton";
import CartButton from "./CartButton";
import SignUpLink from "./SignUpLink";
import OrderSearchLink from "./OrderSearchLink";
import ProfileLink from "./ProfileLink";
import WishlistLink from "./WishlistLink";
import ProductSearchLink from "./ProductSearchLink";
import GiftCardsLink from "./GiftCardsLink";

const NAV_LINK_CLASS =
  "text-sm font-medium text-slate-700 transition-colors hover:text-primary-600 dark:text-slate-300 dark:hover:text-primary-400";

const MOBILE_NAV_ID = "mobile-navigation";

function MainNavItems() {
  return (
    <>
      <Link href="/" className={NAV_LINK_CLASS}>
        Home
      </Link>
      <Link href="/about" className={NAV_LINK_CLASS}>
        About
      </Link>
      <Link href="/contact" className={NAV_LINK_CLASS}>
        Contact
      </Link>
      <ProductSearchLink />
      <GiftCardsLink />
      <WishlistLink />
      <OrderSearchLink />
      <ProfileLink />
    </>
  );
}

export default function Header() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const headerRef = useRef<HTMLElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!isMenuOpen) {
      return;
    }

    const handlePointerDown = (event: PointerEvent) => {
      if (
        headerRef.current &&
        !headerRef.current.contains(event.target as Node)
      ) {
        setIsMenuOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsMenuOpen(false);
        menuButtonRef.current?.focus();
      }
    };

    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [isMenuOpen]);

  const closeIfNavigating = (event: React.MouseEvent<HTMLElement>) => {
    if ((event.target as HTMLElement).closest("a")) {
      setIsMenuOpen(false);
    }
  };

  return (
    <header
      ref={headerRef}
      className="sticky top-0 z-50 border-b border-slate-200 bg-white/80 backdrop-blur-md dark:border-slate-800 dark:bg-slate-900/80"
    >
      <nav className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <Link
            href="/"
            className="text-2xl font-bold tracking-tight text-primary-600 dark:text-primary-400"
          >
            OopsSec Store
          </Link>

          <div className="hidden items-center gap-8 md:flex">
            <MainNavItems />
          </div>

          <div className="flex items-center gap-4">
            <CartButton />

            <SignUpLink />

            <AuthButton />

            <button
              ref={menuButtonRef}
              type="button"
              className="cursor-pointer rounded-lg p-2 text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800 md:hidden"
              aria-label="Menu"
              aria-expanded={isMenuOpen}
              aria-controls={MOBILE_NAV_ID}
              onClick={() => setIsMenuOpen((open) => !open)}
            >
              {isMenuOpen ? (
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
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              ) : (
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
              )}
            </button>
          </div>
        </div>

        <div
          id={MOBILE_NAV_ID}
          className={
            isMenuOpen
              ? "mt-4 flex flex-col gap-4 border-t border-slate-200 pt-4 dark:border-slate-800 md:hidden"
              : "hidden"
          }
          onClick={closeIfNavigating}
        >
          {isMenuOpen && <MainNavItems />}
        </div>
      </nav>
    </header>
  );
}
