import type { Metadata } from "next";
import type { ReactNode } from "react";
import "@/styles/globals.css";
import { ThemeProvider } from "@/lib/theme";
import Sidebar from "@/components/shared/Sidebar";
import Topbar from "@/components/shared/Topbar";
import ThemeBackdrop from "@/components/shared/ThemeBackdrop";
import { CommandPalette } from "@/components/shared/CommandPalette";

export const metadata: Metadata = {
  title: "SentinelOps — Unified Security Operations",
  description: "Single-pane SOC: SIEM · Recon · IDS · Vault.",
  icons: { icon: "/favicon.svg" }
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <ThemeProvider>
          <ThemeBackdrop />
          <CommandPalette />
          <div className="relative z-10 flex min-h-screen">
            <Sidebar />
            <div className="flex-1 flex flex-col min-w-0">
              <Topbar />
              <main className="flex-1 px-4 md:px-8 py-6">{children}</main>
            </div>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
