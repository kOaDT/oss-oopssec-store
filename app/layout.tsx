import type { Metadata } from "next";
import { Poppins } from "next/font/google";
import "./globals.css";
import FlagCheckerWrapper from "./components/FlagCheckerWrapper";
import ConsoleWelcome from "./components/ConsoleWelcome";
import VisitorTracker from "./components/VisitorTracker";

const poppins = Poppins({
  weight: ["100", "200", "300", "400", "500", "600", "700", "800", "900"],
  subsets: ["latin"],
  variable: "--font-poppins",
});

export const metadata: Metadata = {
  title: "OSS – OopsSec Store",
  description:
    "OSS – OopsSec Store, a vulnerable e-commerce for modern web security training.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${poppins.variable} font-poppins antialiased`}>
        {children}
        <FlagCheckerWrapper />
        <ConsoleWelcome />
        <VisitorTracker />
      </body>
    </html>
  );
}
