import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "fs";
import os from "os";
import path from "path";
import { PDFDocument, PDFPage } from "pdf-lib";
import { generateInvoice } from "../../lib/invoice";

const item = { name: "Test Product", quantity: 1, priceAtPurchase: 10 };

const invoiceData = {
  orderId: "ORD-001",
  createdAt: new Date(2026, 9, 30),
  customerName: "Test Customer",
  customerEmail: "test@example.com",
  address: {
    street: "123 Test Street",
    city: "Test City",
    state: "TS",
    zipCode: "12345",
    country: "Test Country",
  },
  items: [item],
  total: 10,
};

describe("generateInvoice", () => {
  let workDir: string;
  let invoicesDir: string;
  let drawText: jest.SpyInstance;

  const printedText = () => drawText.mock.calls.map(([text]) => text);

  beforeEach(() => {
    workDir = mkdtempSync(path.join(os.tmpdir(), "oopssec-invoice-"));
    invoicesDir = path.join(workDir, "documents", "invoices");
    jest.spyOn(process, "cwd").mockReturnValue(workDir);
    drawText = jest.spyOn(PDFPage.prototype, "drawText");
  });

  afterEach(() => {
    jest.restoreAllMocks();
    rmSync(workDir, { recursive: true, force: true });
  });

  it("stores the invoice as documents/invoices/invoice-<orderId>.pdf under the working directory, creating the folder", async () => {
    const filepath = await generateInvoice(invoiceData);

    expect(filepath).toBe(path.join(invoicesDir, "invoice-ORD-001.pdf"));
    expect(existsSync(filepath)).toBe(true);
  });

  it("keeps the files already stored in the invoices folder", async () => {
    mkdirSync(invoicesDir, { recursive: true });
    writeFileSync(path.join(invoicesDir, "invoice-older.pdf"), "older");

    await generateInvoice(invoiceData);

    expect(readdirSync(invoicesDir).sort()).toEqual([
      "invoice-ORD-001.pdf",
      "invoice-older.pdf",
    ]);
    expect(
      readFileSync(path.join(invoicesDir, "invoice-older.pdf"), "utf8")
    ).toBe("older");
  });

  it("writes a single-page PDF", async () => {
    const filepath = await generateInvoice(invoiceData);

    const pdf = await PDFDocument.load(readFileSync(filepath));
    expect(pdf.getPageCount()).toBe(1);
  });

  it("prints an item name of 40 characters in full", async () => {
    const name = "x".repeat(40);

    await generateInvoice({ ...invoiceData, items: [{ ...item, name }] });

    expect(printedText()).toContain(name);
  });

  it("cuts an item name longer than 40 characters to 40 and appends an ellipsis", async () => {
    const name = "x".repeat(40) + "y";

    await generateInvoice({ ...invoiceData, items: [{ ...item, name }] });

    expect(printedText()).toContain(`${"x".repeat(40)}...`);
    expect(printedText()).not.toContain(name);
  });

  // Local-time inputs keep the expected label independent of the machine's time zone.
  it.each([
    ["a Date", new Date(2026, 9, 30, 10)],
    ["a string", "2026-10-30T10:00:00"],
  ])(
    "prints the order date in long US format when createdAt is %s",
    async (_, createdAt) => {
      await generateInvoice({ ...invoiceData, createdAt });

      expect(printedText()).toContain("Date: October 30, 2026");
    }
  );

  it("prints unit prices, line totals and the order total with two decimals", async () => {
    await generateInvoice({
      ...invoiceData,
      items: [
        { name: "Sticker", quantity: 3, priceAtPurchase: 2.5 },
        { name: "Mug", quantity: 1, priceAtPurchase: 12 },
      ],
      total: 19.5,
    });

    expect(printedText()).toEqual(
      expect.arrayContaining(["$2.50", "$7.50", "$12.00", "$19.50"])
    );
  });

  it("rejects when the invoice cannot be written", async () => {
    mkdirSync(path.dirname(invoicesDir));
    writeFileSync(invoicesDir, "");

    await expect(generateInvoice(invoiceData)).rejects.toThrow();
  });
});
