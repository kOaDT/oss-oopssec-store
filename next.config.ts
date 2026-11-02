import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverExternalPackages: ["libxmljs2"],
  // Directory listings of /.git/ must answer on the slashed URL: git-dumper
  // does not follow the redirect and falls back to reachable objects only.
  skipTrailingSlashRedirect: true,
  async rewrites() {
    return [{ source: "/.git/:path*", destination: "/api/vcs/:path*" }];
  },
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "images.unsplash.com",
      },
      {
        protocol: "https",
        hostname: "avatars.githubusercontent.com",
      },
    ],
  },
};

export default nextConfig;
