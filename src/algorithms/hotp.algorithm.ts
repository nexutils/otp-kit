import crypto from "crypto";
import base32Decode from "base32-decode";
import { HotpOptions, HotpVerifyOptions, OtpAlgorithm, VerifyResult } from "./base.algorithm";

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
const MAX_WINDOW = 10;

export class HotpOtpAlgorithm implements OtpAlgorithm<VerifyResult> {
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
    this.counter = normalizeCounter(opts.counter);

    try {
      this.secretKey = Buffer.from(base32Decode(normalizeBase32Secret(opts.secret), "RFC4648"));
      if (this.secretKey.length === 0) {
        throw new OtpError("Invalid Base32 secret encoding");
      }
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
    if (secret !== undefined) {
      throw new OtpError(
        "Per-call secret override is not supported; construct a new HotpOtpAlgorithm with the desired secret instead."
      );
    }

    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(normalizeCounter(movingFactor));

    const hmac = crypto.createHmac(this.algorithm, this.secretKey).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** this.digits;

    return binary.toString().padStart(this.digits, "0");
  }

  verify(input: string, secret?: string, opts?: HotpVerifyOptions): VerifyResult {
    if (secret !== undefined) {
      throw new OtpError(
        "Per-call secret override is not supported; construct a new HotpOtpAlgorithm with the desired secret instead."
      );
    }

    if (!input || !/^\d+$/.test(input)) {
      return { valid: false };
    }

    const normalizedInput = input.trim();
    if (normalizedInput.length !== this.digits) {
      return { valid: false };
    }

    const baseCounter = normalizeCounter(opts?.counter ?? this.counter);
    const window = opts?.window ?? 0;

    if (!Number.isInteger(window) || window < 0 || window > MAX_WINDOW) {
      throw new OtpError(`Window must be a non-negative integer no greater than ${MAX_WINDOW}`);
    }

    for (let delta = 0; delta <= window; delta++) {
      const currentCounter = baseCounter + BigInt(delta);
      const expected = this.generate(undefined, currentCounter);

      if (safeEqualDigits(normalizedInput, expected)) {
        return { valid: true, delta };
      }
    }

    return { valid: false };
  }
}

function normalizeBase32Secret(secret: string): string {
  return secret.replace(/[\s-]+/g, "").replace(/=+$/g, "").toUpperCase();
}

function normalizeCounter(value: number | bigint): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new OtpError("Counter must be a non-negative integer");
    }
    return value;
  }

  if (!Number.isInteger(value) || value < 0) {
    throw new OtpError("Counter must be a non-negative integer");
  }

  return BigInt(value);
}

function safeEqualDigits(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
