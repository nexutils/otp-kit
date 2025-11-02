import crypto from "crypto";
import base32Decode from "base32-decode";
import { HotpOptions, OtpAlgorithm } from "./base.algorithm";

export class OtpError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "OtpError";
  }
}

export class HotpOtpAlgorithm implements OtpAlgorithm {
  private readonly digits: number;
  private readonly algorithm: string;
  private readonly secretKey: Buffer;
  private readonly counter: bigint;

  constructor(private readonly opts: HotpOptions) {
    if (!opts.secret) throw new OtpError("Secret is required");
    if (opts.digits && (opts.digits < 4 || opts.digits > 10))
      throw new OtpError("Digits must be between 4 and 10");

    this.digits = opts.digits ?? 6;
    this.algorithm = (opts.algorithm ?? "SHA-1").replace("-", "").toLowerCase();
    this.counter = BigInt(opts.counter);

    try {
      this.secretKey = Buffer.from(base32Decode(opts.secret, "RFC4648"));
    } catch {
      throw new OtpError("Invalid Base32 secret encoding");
    }
  }

  generate(secret?: string, movingFactor: number | bigint = this.counter): string {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(movingFactor));

    const hmac = crypto.createHmac(this.algorithm, this.secretKey).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** this.digits;

    return binary.toString().padStart(this.digits, "0");
  }

  verify(input: string, secret?: string, opts?: { expected?: string }): boolean {
    // if (!opts?.expected) return false;
    // try {
    //   return crypto.timingSafeEqual(Buffer.from(input), Buffer.from(opts.expected));
    // } catch {
    //   return false;
    // }
    return false; // Placeholder implementation
  }
}
