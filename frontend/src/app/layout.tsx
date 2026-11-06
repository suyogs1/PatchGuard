import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PatchGuard AIRLOCK | Proof Before Ship",
  description: "Autonomous Vulnerability Remediation with Measured Host Baseline on Vultr",
  icons: {
    icon: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased bg-slate-950 text-slate-100">
        {children}
      </body>
    </html>
  );
}
