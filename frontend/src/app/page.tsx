import DashboardPage from "./dashboard/page";

/** Same UI as `/dashboard` without a 307 (avoids flaky double round-trips via some host port forwards). */
export default function Home() {
  return <DashboardPage />;
}
