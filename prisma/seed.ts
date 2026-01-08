import { config } from "dotenv";
import { PrismaClient } from "../lib/generated/prisma/client";
import { getDatabaseUrl } from "../lib/database";
import crypto from "crypto";

/**
 * If you want to add a new flag, you can add it here.
 * The flag should be in the format of "OSS{flag}"
 * The cve is optional
 * The markdown file should be in the content/vulnerabilities folder
 * The markdown file should be in the format of "vulnerability-name.md"
 */
const flags = [
  {
    flag: "OSS{r3act2sh3ll}",
    slug: "react2shell",
    cve: "CVE-2025-55182",
    markdownFile: "react2shell.md",
  },
  {
    flag: "OSS{public_3nvir0nment_v4ri4bl3}",
    slug: "public-env-variable",
    markdownFile: "public-env-variable.md",
  },
  {
    flag: "OSS{w34k_jwt_n0n3_4lg0r1thm}",
    slug: "weak-jwt-none-algorithm",
    markdownFile: "weak-jwt-none-algorithm.md",
  },
  {
    flag: "OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}",
    slug: "client-side-price-manipulation",
    markdownFile: "client-side-price-manipulation.md",
  },
  {
    flag: "OSS{w34k_md5_h4sh1ng}",
    slug: "weak-md5-hashing",
    markdownFile: "weak-md5-hashing.md",
  },
  {
    flag: "OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}",
    slug: "insecure-direct-object-reference",
    markdownFile: "insecure-direct-object-reference.md",
  },
  {
    flag: "OSS{cr0ss_s1t3_scr1pt1ng_xss}",
    slug: "cross-site-scripting-xss",
    markdownFile: "cross-site-scripting-xss.md",
  },
  {
    flag: "OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}",
    slug: "cross-site-request-forgery",
    markdownFile: "cross-site-request-forgery.md",
  },
  {
    flag: "OSS{m4ss_4ss1gnm3nt_vuln3r4b1l1ty}",
    slug: "mass-assignment",
    markdownFile: "mass-assignment.md",
  },
  {
    flag: "OSS{p4th_tr4v3rs4l_4tt4ck}",
    slug: "path-traversal",
    markdownFile: "path-traversal.md",
  },
  {
    flag: "OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}",
    slug: "server-side-request-forgery",
    markdownFile: "server-side-request-forgery.md",
  },
  {
    flag: "OSS{sql_1nj3ct10n_vuln3r4b1l1ty}",
    slug: "sql-injection",
    markdownFile: "sql-injection.md",
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
      ],
    });
    console.log("Created sample reviews");
  } else {
    console.log("Reviews already exist, skipping review creation");
  }

  const existingFlags = await prisma.flag.findMany();
  if (existingFlags.length === 0) {
    await prisma.flag.createMany({
      data: flags,
    });
  } else {
    console.log("Flags already exist, skipping flag creation");
  }

  console.log(`Created ${flags.length} flags`);

  const bobOrderIds = ["ORD-001", "ORD-002", "ORD-003"];

  await prisma.order.deleteMany({
    where: {
      id: {
        in: bobOrderIds,
      },
    },
  });

  const bobOrders = [
    {
      id: "ORD-001",
      userId: bob.id,
      addressId: bobAddress.id,
      total: 25.47,
      status: "DELIVERED" as const,
    },
    {
      id: "ORD-002",
      userId: bob.id,
      addressId: bobAddress.id,
      total: 18.98,
      status: "SHIPPED" as const,
    },
    {
      id: "ORD-003",
      userId: bob.id,
      addressId: bobAddress.id,
      total: 42.97,
      status: "PROCESSING" as const,
    },
  ];

  await prisma.order.createMany({
    data: bobOrders,
  });

  console.log(`Created ${bobOrders.length} orders for Bob`);

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
