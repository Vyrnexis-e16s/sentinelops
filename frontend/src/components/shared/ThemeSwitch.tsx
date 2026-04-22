"use client";

import { motion } from "framer-motion";
import { Moon, Sparkles } from "lucide-react";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/cn";

export default function ThemeSwitch() {
  const { theme, toggle } = useTheme();
  const isAurora = theme === "aurora";
  return (
    <button
      onClick={toggle}
      aria-label="Toggle theme"
      className={cn(
        "relative flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium",
        "border border-border/80 hover:border-accent/60 transition-colors"
      )}
    >
      <motion.span
        layout
        transition={{ type: "spring", stiffness: 320, damping: 28 }}
        className="flex items-center gap-2"
      >
        {isAurora ? (
          <>
            <Sparkles className="h-3.5 w-3.5 text-accent2" />
            Aurora
          </>
        ) : (
          <>
            <Moon className="h-3.5 w-3.5 text-accent" />
            Tactical
          </>
        )}
      </motion.span>
    </button>
  );
}
