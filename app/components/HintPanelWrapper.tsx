"use client";

import { useState, useEffect } from "react";
import HintPanel from "./HintPanel";
import type { HintState } from "@/lib/types";

export default function HintPanelWrapper() {
  const [hintState, setHintState] = useState<HintState | null>(null);

  useEffect(() => {
    const fetchHintState = async () => {
      try {
        const response = await fetch("/api/hints/current");
        if (response.ok) {
          setHintState(await response.json());
        }
      } catch (error) {
        console.error("Error fetching hint state:", error);
      }
    };

    fetchHintState();
  }, []);

  if (!hintState) {
    return null;
  }

  return <HintPanel initialState={hintState} />;
}
