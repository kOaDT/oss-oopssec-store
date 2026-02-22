import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const ADMIN_WISHLIST_ID = "wl-internal-001";

interface WishlistResponse {
  id: string;
  name: string;
  ownerEmail: string;
  items: Array<{
    id: string;
    product: { id: string; name: string; price: number };
  }>;
  flag?: string;
}

describe("Broken Object Level Authorization (BOLA)", () => {
  it("non-admin accessing admin's wishlist returns flag", async () => {
    const aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status, data } = await apiRequest<WishlistResponse>(
      `/api/wishlists/${ADMIN_WISHLIST_ID}`,
      { headers: authHeaders(aliceToken) }
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.BROKEN_OBJECT_LEVEL_AUTHORIZATION);
    expect(data).toHaveProperty("name");
    expect(data).toHaveProperty("items");
    expect(data).toHaveProperty("ownerEmail");
  });

  it("admin accessing own wishlist does NOT return flag", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const { status, data } = await apiRequest<WishlistResponse>(
      `/api/wishlists/${ADMIN_WISHLIST_ID}`,
      { headers: authHeaders(adminToken) }
    );

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
  });

  it("non-existent wishlist returns 404", async () => {
    const aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status } = await apiRequest("/api/wishlists/nonexistent-id", {
      headers: authHeaders(aliceToken),
    });

    expect(status).toBe(404);
  });

  it("unauthenticated request is rejected", async () => {
    const { status } = await apiRequest(`/api/wishlists/${ADMIN_WISHLIST_ID}`);
    expect(status).toBe(401);
  });
});
