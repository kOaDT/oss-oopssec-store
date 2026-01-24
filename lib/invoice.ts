import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import { writeFile, mkdir } from "fs/promises";
import { join } from "path";
import { existsSync } from "fs";

interface InvoiceAddress {
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
}

interface InvoiceItem {
  name: string;
  quantity: number;
  priceAtPurchase: number;
}

interface InvoiceData {
  orderId: string;
  createdAt: Date | string;
  customerName: string;
  customerEmail: string;
  address: InvoiceAddress;
  items: InvoiceItem[];
  total: number;
}

export async function generateInvoice(data: InvoiceData): Promise<string> {
  const invoicesDir = join(process.cwd(), "documents", "invoices");

  if (!existsSync(invoicesDir)) {
    await mkdir(invoicesDir, { recursive: true });
  }

  const filename = `invoice-${data.orderId}.pdf`;
  const filepath = join(invoicesDir, filename);

  const createdAtDate =
    data.createdAt instanceof Date ? data.createdAt : new Date(data.createdAt);

  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([612, 792]);
  const { height } = page.getSize();

  const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const helveticaBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  let y = height - 50;

  page.drawText("OSS - OopsSec Store", {
    x: 180,
    y,
    size: 24,
    font: helveticaBold,
    color: rgb(0, 0, 0),
  });

  y -= 30;
  page.drawText("INVOICE", {
    x: 270,
    y,
    size: 14,
    font: helvetica,
    color: rgb(0.3, 0.3, 0.3),
  });

  y -= 40;
  page.drawText(`Invoice Number: ${data.orderId}`, {
    x: 50,
    y,
    size: 10,
    font: helvetica,
  });

  y -= 15;
  page.drawText(
    `Date: ${createdAtDate.toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    })}`,
    {
      x: 50,
      y,
      size: 10,
      font: helvetica,
    }
  );

  y -= 30;
  page.drawText("Bill To:", {
    x: 50,
    y,
    size: 12,
    font: helveticaBold,
  });

  y -= 18;
  page.drawText(data.customerName, { x: 50, y, size: 10, font: helvetica });
  y -= 15;
  page.drawText(data.customerEmail, { x: 50, y, size: 10, font: helvetica });
  y -= 15;
  page.drawText(data.address.street, { x: 50, y, size: 10, font: helvetica });
  y -= 15;
  page.drawText(
    `${data.address.city}, ${data.address.state} ${data.address.zipCode}`,
    { x: 50, y, size: 10, font: helvetica }
  );
  y -= 15;
  page.drawText(data.address.country, { x: 50, y, size: 10, font: helvetica });

  y -= 30;
  page.drawText("Order Items:", {
    x: 50,
    y,
    size: 12,
    font: helveticaBold,
  });

  y -= 20;
  page.drawText("Item", { x: 50, y, size: 10, font: helveticaBold });
  page.drawText("Qty", { x: 350, y, size: 10, font: helveticaBold });
  page.drawText("Price", { x: 400, y, size: 10, font: helveticaBold });
  page.drawText("Total", { x: 480, y, size: 10, font: helveticaBold });

  y -= 5;
  page.drawLine({
    start: { x: 50, y },
    end: { x: 550, y },
    thickness: 1,
    color: rgb(0.7, 0.7, 0.7),
  });

  y -= 15;
  for (const item of data.items) {
    const lineTotal = item.quantity * item.priceAtPurchase;
    const itemName =
      item.name.length > 40 ? item.name.substring(0, 40) + "..." : item.name;

    page.drawText(itemName, { x: 50, y, size: 10, font: helvetica });
    page.drawText(item.quantity.toString(), {
      x: 350,
      y,
      size: 10,
      font: helvetica,
    });
    page.drawText(`$${item.priceAtPurchase.toFixed(2)}`, {
      x: 400,
      y,
      size: 10,
      font: helvetica,
    });
    page.drawText(`$${lineTotal.toFixed(2)}`, {
      x: 480,
      y,
      size: 10,
      font: helvetica,
    });
    y -= 18;
  }

  page.drawLine({
    start: { x: 50, y },
    end: { x: 550, y },
    thickness: 1,
    color: rgb(0.7, 0.7, 0.7),
  });

  y -= 20;
  page.drawText("Total:", { x: 400, y, size: 12, font: helveticaBold });
  page.drawText(`$${data.total.toFixed(2)}`, {
    x: 480,
    y,
    size: 12,
    font: helveticaBold,
  });

  y -= 50;
  page.drawText("Thank you for shopping with OopsSec Store!", {
    x: 180,
    y,
    size: 8,
    font: helvetica,
    color: rgb(0.5, 0.5, 0.5),
  });

  const pdfBytes = await pdfDoc.save();
  await writeFile(filepath, pdfBytes);

  return filepath;
}
