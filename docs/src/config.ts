export const SITE = {
  website: "https://kOaDT.github.io/oss-oopssec-store/", // GitHub Pages URL
  author: "kOaDT",
  profile: "https://github.com/kOaDT",
  desc: "OopsSec Store is an open-source, intentionally vulnerable e-commerce application built with Next.js and React. It provides a realistic environment to learn and practice web application security testing, including OWASP Top 10 vulnerabilities, API security flaws, and modern frontend attack vectors. Designed for penetration testers, security engineers, developers, and cybersecurity students, this project demonstrates how real-world vulnerabilities manifest in production-like single-page applications (SPA) with REST APIs.",
  title: "OopsSec Store - Walkthroughs",
  ogImage: "screen.png",
  lightAndDarkMode: true,
  postPerIndex: 6,
  postPerPage: 6,
  scheduledPostMargin: 15 * 60 * 1000, // 15 minutes
  showArchives: true,
  showBackButton: true, // show back button in post detail
  editPost: {
    enabled: true,
    text: "Edit page",
    url: "https://github.com/kOaDT/oss-oopssec-store/edit/develop/docs/",
  },
  dynamicOgImage: true,
  dir: "ltr", // "rtl" | "auto"
  lang: "en", // html lang code. Set this empty and default will be "en"
  timezone: "Europe/Paris", // Default global timezone (IANA format) https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
} as const;
