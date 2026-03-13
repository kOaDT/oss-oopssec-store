import crypto from "crypto";

const ALGORITHM = "aes-256-cbc";
const IV_LENGTH = 16;

const SHARE_KEY = Buffer.from(
  process.env.SHARE_ENCRYPTION_KEY ||
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "hex"
);

export function encryptShareToken(plaintext: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, SHARE_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return Buffer.concat([iv, encrypted]).toString("hex");
}

export function decryptShareToken(tokenHex: string): string {
  const data = Buffer.from(tokenHex, "hex");
  const iv = data.subarray(0, IV_LENGTH);
  const ciphertext = data.subarray(IV_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, SHARE_KEY, iv);
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
