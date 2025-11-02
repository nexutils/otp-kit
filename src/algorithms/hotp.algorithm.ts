import crypto from "crypto";
import base32Decode from "base32-decode";
import { HotpOptions, OtpAlgorithm } from "./base.algorithm";

/**
 * Custom error class for OTP-related exceptions.
 *
 * @remarks
 * Used for validation errors like invalid secret, digit range violations,
 * or Base32 decoding failures.
 */
export class OtpError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "OtpError";
  }
}

/**
 * Implementation of the HMAC-based One-Time Password (HOTP) algorithm.
 *
 * @remarks
 * This follows the RFC 4226 specification, generating OTPs from a shared secret
 * and a moving counter value using an HMAC hash.
 *
 * Best suited for event/counter-based authentication systems (e.g., hardware tokens).
 */
export class HotpOtpAlgorithm implements OtpAlgorithm {
  private readonly digits: number;
  private readonly algorithm: string;
  private readonly secretKey: Buffer;
  private readonly counter: bigint;


  /**
   * Constructs a new HOTP algorithm instance.
   *
   * @param opts - Configuration options for HOTP generation
   * @param opts.secret - Base32 encoded shared secret (required)
   * @param opts.counter - Counter value for HOTP (incremented per use)
   * @param opts.digits - Number of digits in OTP (default: 6, valid: 4–10)
   * @param opts.algorithm - HMAC hash algorithm (default: `"SHA-1"`)
   *
   * @throws {OtpError} if:
   * - Secret is missing
   * - Digits are outside the valid range (4–10)
   * - Secret is not a valid Base32-encoded string
   */
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

   /**
   * Generates an HMAC-based OTP using the provided moving factor (counter).
   *
   * @remarks
   * The algorithm performs the standard HOTP process:
   * 1. Encode counter as an 8-byte buffer.
   * 2. Generate an HMAC using the shared secret and chosen hash algorithm.
   * 3. Apply dynamic truncation (as per RFC 4226).
   * 4. Extract the code and reduce it modulo 10^digits.
   *
   * @param secret - Optional override for the secret (currently unused).
   * @param movingFactor - The counter value to use for OTP generation (default: instance counter).
   *
   * @returns The generated OTP as a zero-padded string.
   *
   * @example
   * ```ts
   * const hotp = new HotpOtpAlgorithm({ secret: "JBSWY3DPEHPK3PXP", counter: 1 });
   * const otp = hotp.generate(); // e.g., "287082"
   * ```
   */
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
