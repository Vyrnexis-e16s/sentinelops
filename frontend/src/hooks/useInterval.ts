import { useEffect, useRef } from "react";

/**
 * Re-runs `fn` every `ms` while `ms > 0`. Stops on unmount.
 * Uses a ref for `fn` so you can pass a stable tick without re-binding the effect.
 */
export function useInterval(fn: () => void, ms: number): void {
  const ref = useRef(fn);
  ref.current = fn;

  useEffect(() => {
    if (ms <= 0) return;
    const id = setInterval(() => {
      ref.current();
    }, ms);
    return () => clearInterval(id);
  }, [ms]);
}
