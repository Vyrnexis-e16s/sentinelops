/** @type {import('next').NextConfig} */
const nextConfig = {
  // Next 15+ blocks some dev /_next/* and WS requests unless the origin matches; Docker + 127.0.0.1
  // in the browser is not the same as "localhost" — list both. See:
  // https://nextjs.org/docs/app/api-reference/config/next-config-js/allowedDevOrigins
  allowedDevOrigins: [
    "127.0.0.1",
    "localhost",
    "*.localhost",
  ],
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
