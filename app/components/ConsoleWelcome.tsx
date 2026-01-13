"use client";

import { useEffect } from "react";

const ASCII_ART = `
   ____  ____ ____     ____                  ____            ____  _                  
  / __ \\/ __// __/    / __ \\ ___   ___  ___ / __/ ___  ____ / __/ / /_ ___   ____ ___ 
 / /_/ /\\ \\ _\\ \\     / /_/ // _ \\ / _ \\(_-<_\\ \\  / -_)/ __/_\\ \\  / __// _ \\ / __// -_)
 \\____/___//___/     \\____/ \\___// .__/___/___/  \\__/ \\__//___/  \\__/ \\___//_/   \\__/ 
                                /_/                                                   

  Ready to hunt some flags? Start exploring!
  https://github.com/kOaDT/oss-oopssec-store
`;

export default function ConsoleWelcome() {
  useEffect(() => {
    console.log(
      "%c" + ASCII_ART,
      "color: #22d3ee; font-family: monospace; font-size: 12px;"
    );
  }, []);

  return null;
}
