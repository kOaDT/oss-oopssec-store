import crypto from "crypto";
import fs from "fs";
import path from "path";
import { getDatabaseUrl } from "./database";

/**
 * Key material for the Partner API. The pair signs partner access tokens and
 * the outbound webhook callbacks partners verify on their side, so the public
 * half is published as a JWKS.
 *
 * The pair is generated on first use and persisted next to the database, which
 * keeps tokens valid across restarts. `PARTNER_SIGNING_KEY_PATH` overrides the
 * location.
 */

const KEY_FILE_NAME = "partner-signing-key.pem";

interface PartnerKeyPair {
  privateKey: string;
  publicKey: string;
  keyId: string;
}

let cachedKeyPair: PartnerKeyPair | null = null;

export function getPartnerSigningKeyPath(): string {
  const configured = process.env.PARTNER_SIGNING_KEY_PATH?.trim().replace(
    /^"|"$/g,
    ""
  );
  if (configured) {
    return path.resolve(configured);
  }

  const databaseFile = getDatabaseUrl().replace(/^file:/, "");
  return path.join(path.dirname(databaseFile), KEY_FILE_NAME);
}

function readOrCreatePrivateKey(): string {
  const keyPath = getPartnerSigningKeyPath();

  if (fs.existsSync(keyPath)) {
    return fs.readFileSync(keyPath, "utf-8");
  }

  const { privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  try {
    fs.writeFileSync(keyPath, pem, { flag: "wx", mode: 0o600 });
    return pem;
  } catch {
    // Another worker won the race and already wrote a pair; use theirs.
    return fs.readFileSync(keyPath, "utf-8");
  }
}

/** RFC 7638 JWK thumbprint, used as the `kid` of the published key. */
function computeKeyId(jwk: crypto.JsonWebKey): string {
  const canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  return crypto.createHash("sha256").update(canonical).digest("base64url");
}

function getKeyPair(): PartnerKeyPair {
  if (!cachedKeyPair) {
    const privateKey = readOrCreatePrivateKey();
    const publicKeyObject = crypto.createPublicKey(privateKey);
    cachedKeyPair = {
      privateKey,
      publicKey: publicKeyObject.export({
        type: "spki",
        format: "pem",
      }) as string,
      keyId: computeKeyId(publicKeyObject.export({ format: "jwk" })),
    };
  }

  return cachedKeyPair;
}

export function getPartnerPrivateKey(): string {
  return getKeyPair().privateKey;
}

/** The published verification key, in the exact PEM form the API serves. */
export function getPartnerTokenKey(): string {
  return getKeyPair().publicKey;
}

export function getPartnerKeyId(): string {
  return getKeyPair().keyId;
}

export function getPartnerPublicJwk(): crypto.JsonWebKey {
  const { publicKey, keyId } = getKeyPair();
  return {
    ...crypto.createPublicKey(publicKey).export({ format: "jwk" }),
    use: "sig",
    alg: "RS256",
    kid: keyId,
  };
}

/** Materialises the key pair so the first partner request does not pay for it. */
export function ensurePartnerSigningKey(): string {
  getKeyPair();
  return getPartnerSigningKeyPath();
}
