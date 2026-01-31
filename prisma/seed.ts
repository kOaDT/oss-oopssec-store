import { config } from "dotenv";
import { PrismaClient } from "../lib/generated/prisma/client";
import { getDatabaseUrl } from "../lib/database";
import crypto from "crypto";
import { generateInvoice } from "../lib/invoice";

/**
 * If you want to add a new flag, you can add it here.
 * The flag should be in the format of "OSS{flag}"
 * The cve is optional
 * The walkthroughSlug is optional (from https://koadt.github.io/oss-oopssec-store/)
 *
 * The markdown file should be in the content/vulnerabilities folder
 * The markdown file should be in the format of "vulnerability-name.md"
 *
 * Categories:
 * - INJECTION: SQL injection, XSS, etc.
 * - AUTHENTICATION: JWT, session, password issues
 * - AUTHORIZATION: IDOR, privilege escalation
 * - REQUEST_FORGERY: CSRF, SSRF
 * - INFORMATION_DISCLOSURE: Error messages, exposed data
 * - INPUT_VALIDATION: Path traversal, mass assignment
 * - CRYPTOGRAPHIC: Weak hashing, encryption issues
 * - REMOTE_CODE_EXECUTION: RCE vulnerabilities
 * - OTHER: Miscellaneous
 *
 * Difficulty levels:
 * - EASY: Basic exploitation, no special tools needed
 * - MEDIUM: Requires understanding of the vulnerability type
 * - HARD: Complex exploitation, multiple steps or deep knowledge required
 */
const flags = [
  {
    flag: "OSS{r3act2sh3ll}",
    slug: "react2shell",
    cve: "CVE-2025-55182",
    markdownFile: "react2shell.md",
    walkthroughSlug: "react2shell-cve-2025-55182",
    category: "REMOTE_CODE_EXECUTION" as const,
    difficulty: "HARD" as const,
  },
  {
    flag: "OSS{public_3nvir0nment_v4ri4bl3}",
    slug: "public-env-variable",
    markdownFile: "public-env-variable.md",
    category: "INFORMATION_DISCLOSURE" as const,
    difficulty: "EASY" as const,
  },
  {
    flag: "OSS{w34k_jwt_s3cr3t_k3y}",
    slug: "weak-jwt-secret",
    markdownFile: "weak-jwt-secret.md",
    walkthroughSlug: "jwt-weak-secret-admin-bypass",
    category: "AUTHENTICATION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}",
    slug: "client-side-price-manipulation",
    markdownFile: "client-side-price-manipulation.md",
    walkthroughSlug: "client-side-price-manipulation",
    category: "INPUT_VALIDATION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{w34k_md5_h4sh1ng}",
    slug: "weak-md5-hashing",
    markdownFile: "weak-md5-hashing.md",
    walkthroughSlug: "weak-md5-hashing-admin-compromise",
    category: "CRYPTOGRAPHIC" as const,
    difficulty: "EASY" as const,
  },
  {
    flag: "OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}",
    slug: "insecure-direct-object-reference",
    markdownFile: "insecure-direct-object-reference.md",
    walkthroughSlug: "idor-order-privacy-breach",
    category: "AUTHORIZATION" as const,
    difficulty: "EASY" as const,
  },
  {
    flag: "OSS{cr0ss_s1t3_scr1pt1ng_xss}",
    slug: "cross-site-scripting-xss",
    markdownFile: "cross-site-scripting-xss.md",
    walkthroughSlug: "stored-xss-product-reviews",
    category: "INJECTION" as const,
    difficulty: "EASY" as const,
  },
  {
    flag: "OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}",
    slug: "cross-site-request-forgery",
    markdownFile: "cross-site-request-forgery.md",
    category: "REQUEST_FORGERY" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{m4ss_4ss1gnm3nt_vuln3r4b1l1ty}",
    slug: "mass-assignment",
    markdownFile: "mass-assignment.md",
    walkthroughSlug: "mass-assignment-admin-privilege-escalation",
    category: "INPUT_VALIDATION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{p4th_tr4v3rs4l_4tt4ck}",
    slug: "path-traversal",
    markdownFile: "path-traversal.md",
    category: "INPUT_VALIDATION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}",
    slug: "server-side-request-forgery",
    markdownFile: "server-side-request-forgery.md",
    walkthroughSlug: "ssrf-internal-page-access",
    category: "REQUEST_FORGERY" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{sql_1nj3ct10n_vuln3r4b1l1ty}",
    slug: "sql-injection",
    markdownFile: "sql-injection.md",
    walkthroughSlug: "sql-injection-writeup",
    category: "INJECTION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{1nf0_d1scl0sur3_4p1_3rr0r}",
    slug: "information-disclosure-api-error",
    markdownFile: "information-disclosure-api-error.md",
    category: "INFORMATION_DISCLOSURE" as const,
    difficulty: "EASY" as const,
  },
  {
    flag: "OSS{m4l1c10us_f1l3_upl04d_xss}",
    slug: "malicious-file-upload",
    markdownFile: "malicious-file-upload.md",
    category: "INJECTION" as const,
    difficulty: "HARD" as const,
  },
  {
    flag: "OSS{pr0duct_s34rch_sql_1nj3ct10n}",
    slug: "product-search-sql-injection",
    markdownFile: "product-search-sql-injection.md",
    category: "INJECTION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{s3ss10n_f1x4t10n_4tt4ck}",
    slug: "session-fixation-weak-session-management",
    markdownFile: "session-fixation-weak-session-management.md",
    category: "AUTHENTICATION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{brut3_f0rc3_n0_r4t3_l1m1t}",
    slug: "brute-force-no-rate-limiting",
    markdownFile: "brute-force-no-rate-limiting.md",
    category: "AUTHENTICATION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{x_f0rw4rd3d_f0r_sql1}",
    slug: "x-forwarded-for-sql-injection",
    markdownFile: "x-forwarded-for-sql-injection.md",
    walkthroughSlug: "x-forwarded-for-sql-injection",
    category: "INJECTION" as const,
    difficulty: "HARD" as const,
  },
  {
    flag: "OSS{pr0mpt_1nj3ct10n_41_4ss1st4nt}",
    slug: "prompt-injection-ai-assistant",
    markdownFile: "prompt-injection-ai-assistant.md",
    walkthroughSlug: "prompt-injection-ai-assistant",
    category: "INJECTION" as const,
    difficulty: "MEDIUM" as const,
  },
  {
    flag: "OSS{brok3n_0bj3ct_l3v3l_4uth0r1z4t10n}",
    slug: "broken-object-level-authorization",
    walkthroughSlug: "bola-wishlist-access",
    markdownFile: "broken-object-level-authorization.md",
    category: "AUTHORIZATION" as const,
    difficulty: "MEDIUM" as const,
  },
];

config();

const hashMD5 = (text: string): string => {
  return crypto.createHash("md5").update(text).digest("hex");
};

const databaseUrl = getDatabaseUrl();

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: databaseUrl,
    },
  },
});

async function main() {
  console.log("Seeding database...");

  const existingProjectInit = await prisma.projectInit.findFirst();
  if (!existingProjectInit) {
    await prisma.projectInit.create({
      data: {},
    });
    console.log("Created project initialization timestamp");
  } else {
    console.log("Project initialization already exists, skipping");
  }

  const aliceAddress = await prisma.address.upsert({
    where: { id: "addr-alice-001" },
    update: {},
    create: {
      id: "addr-alice-001",
      street: "Al-Buhtori St. 58",
      city: "Amman",
      state: "Amman Governorate",
      zipCode: "11118",
      country: "Jordan",
    },
  });

  const bobAddress = await prisma.address.upsert({
    where: { id: "addr-bob-001" },
    update: {},
    create: {
      id: "addr-bob-001",
      street: "Friedrichstraße 123",
      city: "Berlin",
      state: "Berlin",
      zipCode: "10117",
      country: "Germany",
    },
  });

  const visBrutaAddress = await prisma.address.upsert({
    where: { id: "addr-vis-bruta-001" },
    update: {},
    create: {
      id: "addr-vis-bruta-001",
      street: "Via Forza Bruta 42",
      city: "Rome",
      state: "Lazio",
      zipCode: "00100",
      country: "Italy",
    },
  });

  await prisma.address.upsert({
    where: { id: "addr-default-001" },
    update: {},
    create: {
      id: "addr-default-001",
      street: "123 Main Street",
      city: "New York",
      state: "NY",
      zipCode: "10001",
      country: "USA",
    },
  });

  const alice = await prisma.user.upsert({
    where: { email: "alice@example.com" },
    update: {
      password: hashMD5("iloveduck"),
      addressId: aliceAddress.id,
    },
    create: {
      email: "alice@example.com",
      password: hashMD5("iloveduck"),
      role: "CUSTOMER",
      addressId: aliceAddress.id,
    },
  });

  const bob = await prisma.user.upsert({
    where: { email: "bob@example.com" },
    update: {
      password: hashMD5("qwerty"),
      addressId: bobAddress.id,
    },
    create: {
      email: "bob@example.com",
      password: hashMD5("qwerty"),
      role: "CUSTOMER",
      addressId: bobAddress.id,
    },
  });

  const visBruta = await prisma.user.upsert({
    where: { email: "vis.bruta@example.com" },
    update: {
      password: hashMD5("sunshine"),
      addressId: visBrutaAddress.id,
    },
    create: {
      email: "vis.bruta@example.com",
      password: hashMD5("sunshine"),
      role: "CUSTOMER",
      addressId: visBrutaAddress.id,
    },
  });

  const admin = await prisma.user.upsert({
    where: { email: "admin@oss.com" },
    update: {
      password: hashMD5("admin"),
    },
    create: {
      email: "admin@oss.com",
      password: hashMD5("admin"),
      role: "ADMIN",
    },
  });

  console.log("Created users:", {
    alice: alice.email,
    admin: admin.email,
    bob: bob.email,
    visBruta: visBruta.email,
  });

  const products = [
    {
      name: "Artisan Sourdough Bread",
      price: 5.49,
      description:
        "Handcrafted sourdough bread with a crispy crust and soft, tangy interior.",
      imageUrl:
        "https://images.unsplash.com/photo-1509440159596-0249088772ff?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Fresh Avocado",
      price: 3.99,
      description:
        "Creamy, perfectly ripe avocados, great for salads and toast.",
      imageUrl:
        "https://images.unsplash.com/photo-1523049673857-eb18f1d7b578?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Strawberry Smoothie",
      price: 5.99,
      description:
        "Refreshing blend of fresh strawberries, banana, and coconut milk.",
      imageUrl:
        "https://images.unsplash.com/photo-1553530666-ba11a7da3888?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Gourmet Coffee Beans",
      price: 12.99,
      description:
        "Premium arabica coffee beans, roasted to perfection for a rich, smooth flavor.",
      imageUrl:
        "https://images.unsplash.com/photo-1559056199-641a0ac8b55e?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Organic Honey",
      price: 9.99,
      description:
        "Pure, raw organic honey from local beekeepers, naturally sweet and flavorful.",
      imageUrl:
        "https://images.unsplash.com/photo-1587049352846-4a222e784d38?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Fresh Pasta",
      price: 4.99,
      description:
        "Handmade Italian pasta, made fresh daily with premium durum wheat.",
      imageUrl:
        "https://images.unsplash.com/photo-1621996346565-e3dbc646d9a9?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Craft Beer Selection",
      price: 14.99,
      description:
        "Assorted pack of 6 craft beers featuring local microbreweries.",
      imageUrl:
        "https://images.unsplash.com/photo-1608270586620-248524c67de9?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Fresh Cherry Tomatoes",
      price: 4.49,
      description:
        "Sweet, juicy cherry tomatoes, perfect for salads and snacking.",
      imageUrl:
        "https://images.unsplash.com/photo-1592841200221-a6898f307baa?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Artisan Cheese Board",
      price: 24.99,
      description:
        "Curated selection of fine cheeses, perfect for entertaining.",
      imageUrl:
        "https://images.unsplash.com/photo-1486297678162-eb2a19b0a32d?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Organic Blueberries",
      price: 7.49,
      description:
        "Fresh organic blueberries, packed with antioxidants and perfect for smoothies or breakfast.",
      imageUrl:
        "https://images.unsplash.com/photo-1498557850523-fd3d118b962e?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Extra Virgin Olive Oil",
      price: 15.99,
      description:
        "Premium cold-pressed olive oil from the Mediterranean, perfect for salads and cooking.",
      imageUrl:
        "https://images.unsplash.com/photo-1474979266404-7eaacbcd87c5?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Fresh Spinach",
      price: 3.49,
      description:
        "Crisp, fresh organic spinach leaves, great for salads and smoothies.",
      imageUrl:
        "https://images.unsplash.com/photo-1576045057995-568f588f82fb?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Fresh Basil",
      price: 2.99,
      description:
        "Aromatic fresh basil leaves, perfect for Italian dishes and pesto.",
      imageUrl:
        "https://images.unsplash.com/photo-1618375569909-3c8616cf7733?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Premium Balsamic Vinegar",
      price: 19.99,
      description:
        "Aged balsamic vinegar from Modena, Italy, with a rich, complex flavor.",
      imageUrl:
        "https://images.unsplash.com/photo-1606914469633-bd39206ea739?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Premium Tea Collection",
      price: 16.99,
      description:
        "Curated selection of premium loose-leaf teas from around the world.",
      imageUrl:
        "https://images.unsplash.com/photo-1556679343-c7306c1976bc?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Fresh Broccoli",
      price: 3.99,
      description:
        "Crisp, fresh broccoli florets, packed with vitamins and perfect for steaming.",
      imageUrl:
        "https://images.unsplash.com/photo-1584270354949-c26b0d5b4a0c?q=80&w=500&auto=format&fit=crop",
    },
    {
      name: "Fresh Carrots",
      price: 2.99,
      description:
        "Sweet, crunchy organic carrots, perfect for snacking or cooking.",
      imageUrl:
        "https://images.unsplash.com/photo-1598170845058-32b9d6a5da37?q=80&w=500&auto=format&fit=crop",
    },
  ];

  const existingProducts = await prisma.product.findMany();
  if (existingProducts.length === 0) {
    await prisma.product.createMany({
      data: products,
    });
  } else {
    console.log("Products already exist, skipping product creation");
  }

  console.log(`Created ${products.length} products`);

  const allProducts = await prisma.product.findMany();
  const existingReviews = await prisma.review.findMany();

  if (existingReviews.length === 0 && allProducts.length > 0) {
    const firstProduct = allProducts[0];
    const secondProduct = allProducts[1];
    const thirdProduct = allProducts[2];

    await prisma.review.createMany({
      data: [
        {
          productId: firstProduct.id,
          content: "Great product! Highly recommend it.",
          author: alice.email,
        },
        {
          productId: firstProduct.id,
          content: "Excellent quality and fast delivery.",
          author: bob.email,
        },
        {
          productId: secondProduct.id,
          content: "Amazing value for money. Will buy again!",
          author: alice.email,
        },
        {
          productId: thirdProduct.id,
          content: "Perfect for my needs. Very satisfied!",
          author: bob.email,
        },
        {
          productId: thirdProduct.id,
          content: "Good product, but could be better.",
          author: "anonymous",
        },
        {
          productId: thirdProduct.id,
          content: "This product sucks!",
          author: "anonymous",
        },
        {
          productId: thirdProduct.id,
          content:
            "Heard the devs left some old flags lying around at the root... files that say exactly what they are. Classic mistake!",
          author: "Mr. Robot",
        },
      ],
    });
    console.log("Created sample reviews");
  } else {
    console.log("Reviews already exist, skipping review creation");
  }

  for (const flag of flags) {
    await prisma.flag.upsert({
      where: { slug: flag.slug },
      update: flag,
      create: flag,
    });
  }

  console.log(`Created ${flags.length} flags`);

  const bobOrderIds = ["ORD-001", "ORD-002", "ORD-003"];

  await prisma.orderItem.deleteMany({
    where: {
      orderId: {
        in: bobOrderIds,
      },
    },
  });

  await prisma.order.deleteMany({
    where: {
      id: {
        in: bobOrderIds,
      },
    },
  });

  const orderItemsMapping: Record<
    string,
    Array<{ productIndex: number; quantity: number }>
  > = {
    "ORD-001": [
      { productIndex: 0, quantity: 2 },
      { productIndex: 1, quantity: 2 },
      { productIndex: 5, quantity: 1 },
    ],
    "ORD-002": [
      { productIndex: 2, quantity: 2 },
      { productIndex: 16, quantity: 2 },
    ],
    "ORD-003": [
      { productIndex: 3, quantity: 2 },
      { productIndex: 14, quantity: 1 },
    ],
  };

  for (const orderId of bobOrderIds) {
    const items = orderItemsMapping[orderId];
    const orderTotal = items.reduce((sum, item) => {
      const product = allProducts[item.productIndex];
      return sum + product.price * item.quantity;
    }, 0);

    const order = await prisma.order.create({
      data: {
        id: orderId,
        userId: bob.id,
        addressId: bobAddress.id,
        total: Math.round(orderTotal * 100) / 100,
        status:
          orderId === "ORD-001"
            ? "DELIVERED"
            : orderId === "ORD-002"
              ? "SHIPPED"
              : "PROCESSING",
      },
    });

    const orderItems = [];
    for (const item of items) {
      const product = allProducts[item.productIndex];
      const orderItem = await prisma.orderItem.create({
        data: {
          orderId: order.id,
          productId: product.id,
          quantity: item.quantity,
          priceAtPurchase: product.price,
        },
      });
      orderItems.push({ ...orderItem, product });
    }

    await generateInvoice({
      orderId: order.id,
      createdAt: order.createdAt,
      customerName: "Bob",
      customerEmail: bob.email,
      address: {
        street: bobAddress.street,
        city: bobAddress.city,
        state: bobAddress.state,
        zipCode: bobAddress.zipCode,
        country: bobAddress.country,
      },
      items: orderItems.map((item) => ({
        name: item.product.name,
        quantity: item.quantity,
        priceAtPurchase: item.priceAtPurchase,
      })),
      total: order.total,
    });

    console.log(`Created order ${order.id} with invoice`);
  }

  console.log(`Created ${bobOrderIds.length} orders for Bob with invoices`);

  // Seed visitor logs for analytics
  const existingVisitorLogs = await prisma.visitorLog.findFirst();

  if (!existingVisitorLogs) {
    const visitorLogs = [
      {
        ip: "192.168.1.100",
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        path: "/",
      },
      {
        ip: "192.168.1.101",
        userAgent:
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
        path: "/products/search",
      },
      {
        ip: "192.168.1.102",
        userAgent:
          "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0 AppleWebKit/537.36",
        path: "/cart",
      },
      {
        ip: "192.168.1.100",
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        path: "/checkout",
      },
      {
        ip: "192.168.1.103",
        userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)",
        path: "/",
      },
      {
        ip: "192.168.1.104",
        userAgent:
          "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36",
        path: "/products/search",
      },
      {
        ip: "192.168.1.100",
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        path: "/order",
      },
      {
        ip: "192.168.1.105",
        userAgent: "curl/8.0.0",
        path: "/api/products",
      },
    ];

    await prisma.visitorLog.createMany({
      data: visitorLogs,
    });

    console.log(`Created ${visitorLogs.length} visitor logs`);
  } else {
    console.log("Visitor logs already exist, skipping visitor log creation");
  }

  const existingWishlists = await prisma.wishlist.findFirst();

  if (!existingWishlists) {
    const aliceWishlist = await prisma.wishlist.create({
      data: {
        id: "wl-alice-001",
        name: "My Favorites",
        userId: alice.id,
        isPublic: false,
      },
    });

    await prisma.wishlistItem.createMany({
      data: [
        { wishlistId: aliceWishlist.id, productId: allProducts[0].id },
        { wishlistId: aliceWishlist.id, productId: allProducts[3].id },
        { wishlistId: aliceWishlist.id, productId: allProducts[8].id },
      ],
    });

    const bobWishlist = await prisma.wishlist.create({
      data: {
        id: "wl-bob-001",
        name: "Weekend Groceries",
        userId: bob.id,
        isPublic: false,
      },
    });

    await prisma.wishlistItem.createMany({
      data: [
        { wishlistId: bobWishlist.id, productId: allProducts[1].id },
        { wishlistId: bobWishlist.id, productId: allProducts[5].id },
        { wishlistId: bobWishlist.id, productId: allProducts[7].id },
        { wishlistId: bobWishlist.id, productId: allProducts[11].id },
      ],
    });

    const bolaFlag = await prisma.flag.findUnique({
      where: { slug: "broken-object-level-authorization" },
    });

    await prisma.wishlist.create({
      data: {
        id: "wl-internal-001",
        name: "Q4 Procurement List",
        userId: admin.id,
        isPublic: false,
        note: bolaFlag?.flag ?? "OSS{brok3n_0bj3ct_l3v3l_4uth0r1z4t10n}",
      },
    });

    await prisma.wishlistItem.createMany({
      data: [
        { wishlistId: "wl-internal-001", productId: allProducts[4].id },
        { wishlistId: "wl-internal-001", productId: allProducts[9].id },
        { wishlistId: "wl-internal-001", productId: allProducts[10].id },
        { wishlistId: "wl-internal-001", productId: allProducts[13].id },
      ],
    });

    console.log("Created wishlists for Alice, Bob, and admin");
  } else {
    console.log("Wishlists already exist, skipping wishlist creation");
  }

  console.log("Seeding completed!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
