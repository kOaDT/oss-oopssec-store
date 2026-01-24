"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";

export default function VisitorTracker() {
  const pathname = usePathname();

  useEffect(() => {
    const track = async () => {
      try {
        await fetch("/api/tracking", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            path: pathname,
          }),
        });
      } catch {
        // Silent failure
      }
    };

    track();
  }, [pathname]);

  return null;
}
