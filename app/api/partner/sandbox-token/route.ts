import { NextResponse } from "next/server";
import { issuePartnerToken } from "@/lib/partner-auth";
import {
  PARTNER_TOKEN_SCOPE,
  PARTNER_TOKEN_TTL_SECONDS,
  SANDBOX_SUPPLIER_ID,
} from "@/lib/partner-directory";

export async function POST() {
  return NextResponse.json({
    access_token: issuePartnerToken(SANDBOX_SUPPLIER_ID),
    token_type: "Bearer",
    expires_in: PARTNER_TOKEN_TTL_SECONDS,
    scope: PARTNER_TOKEN_SCOPE,
    partner_id: SANDBOX_SUPPLIER_ID,
  });
}
