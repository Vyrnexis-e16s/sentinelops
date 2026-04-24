"use client";

import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useSyncExternalStore,
  type ReactNode
} from "react";

export type Theme = "tactical" | "aurora";

type ThemeCtx = {
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggle: () => void;
};

const Ctx = createContext<ThemeCtx | null>(null);

const STORAGE_KEY = "sentinelops:theme";
const THEME_EVENT = "sentinelops:theme-changed";

function getSnapshot(): Theme {
  if (typeof window === "undefined") return "tactical";
  try {
    return (localStorage.getItem(STORAGE_KEY) as Theme | null) || "tactical";
  } catch {
    return "tactical";
  }
}

function getServerSnapshot(): Theme {
  return "tactical";
}

function subscribe(onStoreChange: () => void) {
  if (typeof window === "undefined") {
    return () => {};
  }
  const onStorage = (e: StorageEvent) => {
    if (e.key === STORAGE_KEY) onStoreChange();
  };
  const onLocal = () => onStoreChange();
  window.addEventListener("storage", onStorage);
  window.addEventListener(THEME_EVENT, onLocal);
  return () => {
    window.removeEventListener("storage", onStorage);
    window.removeEventListener(THEME_EVENT, onLocal);
  };
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const setTheme = useCallback((t: Theme) => {
    try {
      localStorage.setItem(STORAGE_KEY, t);
      window.dispatchEvent(new Event(THEME_EVENT));
    } catch {
      // No storage
    }
  }, []);

  const toggle = useCallback(() => {
    setTheme(theme === "tactical" ? "aurora" : "tactical");
  }, [setTheme, theme]);

  return <Ctx.Provider value={{ theme, setTheme, toggle }}>{children}</Ctx.Provider>;
}

export function useTheme() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTheme outside ThemeProvider");
  return ctx;
}
