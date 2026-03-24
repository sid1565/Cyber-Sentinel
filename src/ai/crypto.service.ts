// FILE: src/ai/crypto.service.ts

import { Injectable, Inject } from "@nestjs/common";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHash,
} from "crypto";
import { CYBER_SENTINEL_OPTIONS } from "../cyber-sentinel.options";
import type { CyberSentinelOptions } from "../cyber-sentinel.options";

const ALGORITHM = "aes-256-cbc";
const IV_LENGTH = 16;

@Injectable()
export class CryptoService {
  private readonly key: Buffer;

  constructor(@Inject(CYBER_SENTINEL_OPTIONS) options: CyberSentinelOptions) {
    const rawKey =
      options.encryptionKey ?? "cyber-sentinel-default-fallback-key-32ch";
    this.key = createHash("sha256").update(rawKey).digest();
  }

  encrypt(plainText: string): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
    return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
  }

  decrypt(cipherText: string): string {
    try {
      const [ivHex, dataHex] = cipherText.split(":");
      if (!ivHex || !dataHex) return cipherText;

      const iv = Buffer.from(ivHex, "hex");
      const data = Buffer.from(dataHex, "hex");
      const decipher = createDecipheriv(ALGORITHM, this.key, iv);
      return Buffer.concat([
        decipher.update(data),
        decipher.final(),
      ]).toString();
    } catch {
      return cipherText;
    }
  }
}
