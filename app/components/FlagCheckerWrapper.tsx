"use client";

import { useState, useEffect } from "react";
import FlagChecker from "./FlagChecker";

export default function FlagCheckerWrapper() {
  const [totalFlags, setTotalFlags] = useState(0);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchTotalFlags = async () => {
      try {
        const response = await fetch("/api/flags/count");
        if (response.ok) {
          const data = await response.json();
          setTotalFlags(data.count);
        }
      } catch (error) {
        console.error("Error fetching total flags:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchTotalFlags();
  }, []);

  if (isLoading || totalFlags === 0) {
    return null;
  }

  return <FlagChecker totalFlags={totalFlags} />;
}
