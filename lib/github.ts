import type { Contributor } from "@/lib/types";
import {
  GITHUB_REPO_SLUG,
  CONTRIBUTORS_REVALIDATE_SECONDS,
} from "@/lib/config";

const CONTRIBUTORS_URL = `https://api.github.com/repos/${GITHUB_REPO_SLUG}/contributors?per_page=100`;

interface GitHubContributor {
  login: string;
  avatar_url: string;
  html_url: string;
  contributions: number;
  type: string;
}

export async function fetchContributors(): Promise<Contributor[]> {
  try {
    const response = await fetch(CONTRIBUTORS_URL, {
      headers: { Accept: "application/vnd.github+json" },
      next: { revalidate: CONTRIBUTORS_REVALIDATE_SECONDS },
    });

    if (!response.ok) {
      return [];
    }

    const data = (await response.json()) as GitHubContributor[];

    return data
      .filter((contributor) => contributor.type !== "Bot")
      .sort((a, b) => b.contributions - a.contributions)
      .map((contributor) => ({
        username: contributor.login,
        avatarUrl: contributor.avatar_url,
        githubUrl: contributor.html_url,
        contributions: contributor.contributions,
      }));
  } catch {
    return [];
  }
}
