import Link from "next/link";

export default function GiftCardsLink() {
  return (
    <Link
      href="/gift-cards"
      className="text-sm font-medium text-slate-700 transition-colors hover:text-primary-600 dark:text-slate-300 dark:hover:text-primary-400"
    >
      Gift Cards
    </Link>
  );
}
