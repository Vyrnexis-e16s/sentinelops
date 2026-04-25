/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  experimental: {
    optimizePackageImports: ["lucide-react", "three"]
  },
  async rewrites() {
    // The browser hits the Next.js server, which proxies /api/v1/* to the
    // FastAPI backend. In Docker, the destination must use the Docker service
    // name (`backend`); only the browser side uses `localhost:8000`.
    const target =
      process.env.INTERNAL_API_URL ||
      process.env.NEXT_PUBLIC_API_URL ||
      "http://localhost:8000";
    return [
      {
        source: "/api/v1/:path*",
        destination: `${target}/api/v1/:path*`
      }
    ];
  }
};
export default nextConfig;
