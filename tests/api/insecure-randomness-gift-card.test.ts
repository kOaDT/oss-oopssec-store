import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";
import { generateGiftCardCode } from "@/lib/gift-card";
import Database from "better-sqlite3";
import { getDatabaseUrl } from "@/lib/database";

const SEEDED_GIFT_CARD_ID = "gc-seeded-001";
const SEEDED_RECIPIENT = "forgotten-friend@oopssec.store";
const SEEDED_AMOUNT = 500;
const SEEDED_CREATED_AT = "2025-01-15T10:42:33.456Z";

interface GiftCardEntry {
  id: string;
  amount: number;
  recipientEmail: string;
  message: string | null;
  status: "PENDING" | "REDEEMED";
  createdAt: string;
  redeemedAt: string | null;
}

function resetSeededGiftCard(): void {
  const dbPath = getDatabaseUrl().replace(/^file:/, "");
  const db = new Database(dbPath);
  const code = generateGiftCardCode(new Date(SEEDED_CREATED_AT).getTime());
  db.prepare(
    `UPDATE gift_cards SET status = 'PENDING', redeemedAt = NULL, redeemedById = NULL, code = ? WHERE id = ?`
  ).run(code, SEEDED_GIFT_CARD_ID);
  db.close();
}

describe("Insecure Randomness - Gift Card (API)", () => {
  let aliceToken: string;
  let bobToken: string;

  beforeAll(async () => {
    aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
    bobToken = await loginOrFail(TEST_USERS.bob.email, TEST_USERS.bob.password);
  });

  beforeEach(() => {
    resetSeededGiftCard();
  });

  it("lets a buyer purchase a gift card without exposing the code", async () => {
    const { status, data } = await apiRequest<
      GiftCardEntry & { code?: string }
    >("/api/gift-cards", {
      method: "POST",
      headers: authHeaders(aliceToken),
      body: JSON.stringify({
        amount: 25,
        recipientEmail: "friend@example.com",
        message: "Enjoy!",
      }),
    });

    expect(status).toBe(201);
    expect(data).toHaveProperty("id");
    expect(data).toHaveProperty("amount", 25);
    expect(data).toHaveProperty("recipientEmail", "friend@example.com");
    expect(data).toHaveProperty("status", "PENDING");
    expect(data).toHaveProperty("createdAt");
    expect(data).not.toHaveProperty("code");

    const { data: list } = await apiRequest<GiftCardEntry[]>(
      "/api/gift-cards",
      { headers: authHeaders(aliceToken) }
    );
    const sent = (list as GiftCardEntry[]).find((c) => c.id === data.id);
    expect(sent).toBeDefined();
    expect(sent).not.toHaveProperty("code");
    expect(sent!.createdAt).toMatch(/\.\d{3}Z$/);
  });

  it("rejects invalid denominations", async () => {
    const { status } = await apiRequest("/api/gift-cards", {
      method: "POST",
      headers: authHeaders(aliceToken),
      body: JSON.stringify({
        amount: 42,
        recipientEmail: "friend@example.com",
      }),
    });

    expect(status).toBe(400);
  });

  it("requires authentication", async () => {
    const { status } = await apiRequest("/api/gift-cards", {
      method: "POST",
      body: JSON.stringify({
        amount: 25,
        recipientEmail: "friend@example.com",
      }),
    });

    expect(status).toBe(401);
  });

  it("resend endpoint always fails with a service-unavailable error", async () => {
    const { status, data } = await apiRequest<{ error: string }>(
      "/api/gift-cards/resend",
      {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ id: SEEDED_GIFT_CARD_ID }),
      }
    );

    expect(status).toBe(503);
    expect((data as { error: string }).error).toMatch(
      /Email service temporarily unavailable/i
    );
  });

  it("lets a different user redeem a card via the derived code", async () => {
    const { status: createStatus, data: created } =
      await apiRequest<GiftCardEntry>("/api/gift-cards", {
        method: "POST",
        headers: authHeaders(bobToken),
        body: JSON.stringify({
          amount: 50,
          recipientEmail: "cross-user@example.com",
        }),
      });
    expect(createStatus).toBe(201);

    const derivedCode = generateGiftCardCode(
      new Date((created as GiftCardEntry).createdAt).getTime()
    );

    const { status: redeemStatus, data: redeemData } = await apiRequest<{
      success: true;
      amount: number;
      balance: number;
      flag?: string;
    }>("/api/gift-cards/redeem", {
      method: "POST",
      headers: authHeaders(aliceToken),
      body: JSON.stringify({ code: derivedCode }),
    });

    expect(redeemStatus).toBe(200);
    expect(redeemData).toHaveProperty("success", true);
    expect(redeemData).toHaveProperty("amount", 50);
    expect(redeemData).not.toHaveProperty("flag");
  });

  it("rejects a buyer who tries to redeem their own gift card", async () => {
    const { status: createStatus, data: created } =
      await apiRequest<GiftCardEntry>("/api/gift-cards", {
        method: "POST",
        headers: authHeaders(bobToken),
        body: JSON.stringify({
          amount: 25,
          recipientEmail: "self-redeem-block@example.com",
        }),
      });
    expect(createStatus).toBe(201);

    const derivedCode = generateGiftCardCode(
      new Date((created as GiftCardEntry).createdAt).getTime()
    );

    const { status, data } = await apiRequest<{ error: string }>(
      "/api/gift-cards/redeem",
      {
        method: "POST",
        headers: authHeaders(bobToken),
        body: JSON.stringify({ code: derivedCode }),
      }
    );

    expect(status).toBe(403);
    expect(data).toHaveProperty("error");
    expect((data as { error: string }).error).toMatch(/yourself/i);
  });

  it("returns the flag when the seeded $500 card is redeemed with the derived code", async () => {
    const { data: list } = await apiRequest<GiftCardEntry[]>(
      "/api/gift-cards",
      { headers: authHeaders(aliceToken) }
    );
    const seeded = (list as GiftCardEntry[]).find(
      (c) => c.recipientEmail === SEEDED_RECIPIENT
    );
    expect(seeded).toBeDefined();
    expect(seeded!.amount).toBe(SEEDED_AMOUNT);
    expect(seeded!.status).toBe("PENDING");

    const derivedCode = generateGiftCardCode(
      new Date(seeded!.createdAt).getTime()
    );

    const { status, data } = await apiRequest<{
      success: true;
      amount: number;
      balance: number;
      flag?: string;
    }>("/api/gift-cards/redeem", {
      method: "POST",
      headers: authHeaders(bobToken),
      body: JSON.stringify({ code: derivedCode }),
    });

    expect(status).toBe(200);
    expect(data).toHaveProperty("success", true);
    expect(data).toHaveProperty("amount", SEEDED_AMOUNT);
    expect((data as { flag?: string }).flag).toBe(
      FLAGS.INSECURE_RANDOMNESS_GIFT_CARD
    );
  });

  it("rejects invalid gift card codes", async () => {
    const { status, data } = await apiRequest<{ error: string }>(
      "/api/gift-cards/redeem",
      {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ code: "FAKE-FAKE-FAKE" }),
      }
    );

    expect(status).toBe(400);
    expect(data).toHaveProperty("error");
  });

  it("cannot redeem the same gift card twice", async () => {
    const { data: created } = await apiRequest<GiftCardEntry>(
      "/api/gift-cards",
      {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({
          amount: 25,
          recipientEmail: "double-redeem@example.com",
        }),
      }
    );
    const code = generateGiftCardCode(
      new Date((created as GiftCardEntry).createdAt).getTime()
    );

    const first = await apiRequest("/api/gift-cards/redeem", {
      method: "POST",
      headers: authHeaders(bobToken),
      body: JSON.stringify({ code }),
    });
    expect(first.status).toBe(200);

    const second = await apiRequest("/api/gift-cards/redeem", {
      method: "POST",
      headers: authHeaders(bobToken),
      body: JSON.stringify({ code }),
    });
    expect(second.status).toBe(400);
  });

  describe("generateGiftCardCode (unit)", () => {
    it("is deterministic for a given seed", () => {
      const seed = 1736937753456;
      const first = generateGiftCardCode(seed);
      const second = generateGiftCardCode(seed);
      const third = generateGiftCardCode(seed);
      expect(first).toBe(second);
      expect(second).toBe(third);
    });

    it("produces different codes for different seeds", () => {
      const a = generateGiftCardCode(1000);
      const b = generateGiftCardCode(1001);
      expect(a).not.toBe(b);
    });

    it("produces codes in XXXX-XXXX-XXXX format", () => {
      const code = generateGiftCardCode(Date.now());
      expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    });
  });
});
