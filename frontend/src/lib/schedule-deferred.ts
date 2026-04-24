/**
 * Schedules work so the callback is not part of the synchronous `useEffect` run.
 * Satisfies eslint `react-hooks/set-state-in-effect` for async data loads that
 * eventually call setState.
 */
export function runDeferred(fn: () => void | Promise<void>): ReturnType<typeof setTimeout> {
  return setTimeout(() => {
    void fn();
  }, 0);
}
