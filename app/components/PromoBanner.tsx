export default function PromoBanner() {
  return (
    <div className="bg-secondary-600 py-3 text-center text-sm font-semibold text-white dark:bg-secondary-700">
      <span>
        Limited time offer — use code{" "}
        <span className="rounded bg-white/20 px-2 py-0.5 font-mono tracking-wide">
          FLASHSALE
        </span>{" "}
        for 50% off your next order
      </span>
    </div>
  );
}
