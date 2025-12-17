import { config } from "dotenv";
import { PrismaClient } from "../lib/generated/prisma/client";
import path from "path";

config();

const getDatabaseUrl = () => {
  const projectRoot = path.resolve(process.cwd());
  const defaultPath = path.resolve(projectRoot, "prisma", "dev.db");

  if (process.env.DATABASE_URL) {
    const dbUrl = process.env.DATABASE_URL.trim().replace(/^"|"$/g, "");

    if (dbUrl.startsWith("file:./")) {
      const relativePath = dbUrl.replace("file:./", "");
      const absolutePath = path.resolve(projectRoot, relativePath);
      return `file:${absolutePath}`;
    }

    if (dbUrl.startsWith("file:")) {
      return dbUrl;
    }
  }

  return `file:${defaultPath}`;
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

  const visitor = await prisma.user.upsert({
    where: { email: "visitor@example.com" },
    update: {},
    create: {
      email: "visitor@example.com",
      role: "CUSTOMER",
    },
  });

  const admin = await prisma.user.upsert({
    where: { email: "admin@example.com" },
    update: {},
    create: {
      email: "admin@example.com",
      role: "ADMIN",
    },
  });

  console.log("Created users:", { visitor: visitor.email, admin: admin.email });

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

  const existingCart = await prisma.cart.findFirst({
    where: { userId: visitor.id },
  });

  if (!existingCart) {
    await prisma.cart.create({
      data: {
        userId: visitor.id,
      },
    });
    console.log("Created empty cart for visitor");
  } else {
    console.log("Cart already exists for visitor");
  }

  const vulnerability = await prisma.vulnerability.upsert({
    where: { cve: "CVE-2025-55182" },
    update: {},
    create: {
      cve: "CVE-2025-55182",
      title: "React2Shell",
    },
  });

  console.log("Created vulnerability:", vulnerability.cve);

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
