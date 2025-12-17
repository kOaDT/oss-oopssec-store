import { config } from "dotenv";
import { PrismaClient } from "../lib/generated/prisma/client";

config();

const prisma = new PrismaClient();

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
      name: "Quantum Potato Chips",
      price: 4.99,
      description:
        "Crispy chips that exist in multiple quantum states simultaneously. May or may not be in your bag.",
    },
    {
      name: "Invisible Energy Drink",
      price: 6.99,
      description:
        "The most refreshing drink you will never see. Contains 0% visible ingredients.",
    },
    {
      name: "Time-Delayed Cookies",
      price: 5.49,
      description:
        "These cookies taste better tomorrow. Satisfaction guaranteed in 24-48 hours.",
    },
    {
      name: "Gravity-Defying Popcorn",
      price: 3.99,
      description:
        "Popcorn that floats above the bowl. Warning: May require ceiling cleaning.",
    },
    {
      name: "Self-Heating Ice Cream",
      price: 7.99,
      description:
        "Ice cream that gets colder the longer you wait. Perfect for hot summer days that never end.",
    },
    {
      name: "Echo Chocolate Bar",
      price: 4.49,
      description:
        "A chocolate bar that tastes like whatever you are thinking about. Mind-reading not included.",
    },
    {
      name: "Phantom Pretzels",
      price: 3.49,
      description:
        "Pretzels that disappear when you look away. Great for sharing with yourself.",
    },
    {
      name: "Reverse Coffee",
      price: 8.99,
      description:
        "Coffee that makes you more tired. Perfect for when you need to sleep but have too much energy.",
    },
    {
      name: "Dimensional Crackers",
      price: 5.99,
      description:
        "Crackers that exist in multiple dimensions. May contain parallel universe flavors.",
    },
    {
      name: "Memory Soda",
      price: 6.49,
      description:
        "A soda that tastes like your favorite childhood memory. Results may vary based on childhood.",
    },
    {
      name: "Anti-Gravity Water",
      price: 2.99,
      description:
        "Water that flows upward. Comes with a special cup that defies physics.",
    },
    {
      name: "Probability Gummies",
      price: 4.99,
      description:
        "Each gummy has a 50% chance of being your favorite flavor. The other 50% is a mystery.",
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
