"use client";

import dynamic from "next/dynamic";
import { useTheme } from "@/lib/theme";

const AuroraCanvas = dynamic(() => import("@/components/aurora/AuroraCanvas"), { ssr: false });

export default function ThemeBackdrop() {
  const { theme } = useTheme();
  return (
    <>
      {theme === "tactical" ? (
        <>
          <div className="tactical-bg" />
          <div className="scanline" />
        </>
      ) : (
        <>
          <div className="aurora-bg" />
          <AuroraCanvas />
        </>
      )}
    </>
  );
}
