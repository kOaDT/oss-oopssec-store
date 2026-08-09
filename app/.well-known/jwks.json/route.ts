import { NextResponse } from "next/server";
import { getPartnerPublicJwk } from "@/lib/partner-keys";

/** The key pair is runtime state, never build state: prerendering this would
 * publish whichever key the build host happened to generate. */
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json(
    { keys: [getPartnerPublicJwk()] },
    { headers: { "Cache-Control": "public, max-age=3600" } }
  );
}
