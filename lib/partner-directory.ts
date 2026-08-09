/**
 * Public facts about the Partner API: the demo account, the token envelope and
 * the suppliers listed on `/partners`. None of it is secret, so the marketing
 * page can import it without pulling in the key material `partner-auth` needs.
 */

/** Demo partner account handed out by the public sandbox token endpoint. */
export const SANDBOX_SUPPLIER_ID = "SUP-SANDBOX";

export const PARTNER_TOKEN_ISSUER = "https://oopssec.store";
export const PARTNER_TOKEN_TTL_SECONDS = 3600;
export const PARTNER_TOKEN_SCOPE = "orders:read";

export interface PartnerDirectoryEntry {
  company: string;
  partnerId: string;
  categories: string;
  since: string;
}

/** Suppliers wired into the Partner API, as published on `/partners`. */
export const PARTNER_DIRECTORY: PartnerDirectoryEntry[] = [
  {
    company: "Knead to Know Bakehouse",
    partnerId: "SUP-001",
    categories: "Bakery, viennoiserie",
    since: "2019",
  },
  {
    company: "Lettuce Encrypt Organics",
    partnerId: "SUP-LETTUCE",
    categories: "Produce, dairy",
    since: "2021",
  },
  {
    company: "Brie Force Fromagerie",
    partnerId: "SUP-BRIE",
    categories: "Cheese, charcuterie",
    since: "2023",
  },
];
