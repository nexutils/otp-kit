import crypto from "crypto";
import { RandomOtpOptions, OtpAlgorithm } from "./base.algorithm";
import { getChars } from "../utils/getChar";

const DEFAULT_LENGTH = 6;

/**
 * RandomOtpAlgorithm generates random OTPs (One-Time Passwords)
 * using a configurable charset and length.
 *
 * @remarks
 * Unlike HOTP/TOTP, this algorithm does not rely on a secret or time-based factor.
 * It is best suited for use cases like one-time login codes, verification codes,
 * or scenarios where the OTP is stored in a database and validated later.
 */
export class RandomOtpAlgorithm implements OtpAlgorithm {
  /**
   * Creates a new RandomOtpAlgorithm instance with the given options.
   *
   * @param options - Configuration for OTP generation
   * @param options.length - Length of the OTP (default: 6)
   * @param options.charset - The character set to use:
   *   - `"numeric"` → digits `0-9`
   *   - `"alphabetic"` → letters `a-zA-Z`
   *   - `"alphanumeric"` → digits + letters
   *   - `"hex"` → hexadecimal `0-9a-f`
   *   - `"ascii-printable"` → all printable ASCII characters
   *   - `"custom"` → developer provides a `customCharset`
   * @param options.customCharset - Required when charset is `"custom"`.
   *
   * @throws Error if:
   * - `length <= 0`
   * - `charset = "custom"` without providing `customCharset`
   * - `customCharset` is provided but `charset` is not `"custom"`
   */
  constructor(private options: RandomOtpOptions) {
    const defaults = {
      length: DEFAULT_LENGTH,
      charset: "numeric" as const,
      customCharset: undefined,
    };

    this.options = { ...defaults, ...options };

    if (this.options.charset === "custom" && !this.options.customCharset) {
      throw new Error("Custom charset is required when charset is 'custom'");
    }

    if (this.options.length! <= 0) {
      throw new Error("Invalid OTP length: must be greater than 0");
    }

    if (this.options.charset !== "custom" && this.options.customCharset) {
      throw new Error(
        "Custom charset should only be provided when charset is 'custom'"
      );
    }
  }

  /**
   * Generates a random OTP string using the configured charset and length.
   *
   * @example
   * ```ts
   * const otpGen = new RandomOtpAlgorithm({ length: 6, charset: "numeric" });
   * const otp = otpGen.generate(); // e.g., "493028"
   * ```
   *
   * @returns A randomly generated OTP string.
   */
  generate(): string {
    const chars = getChars(this.options.charset, this.options.customCharset);
    let otp = "";
    const randomBytes = crypto.randomBytes(
      this.options.length || DEFAULT_LENGTH
    );

    for (let i = 0; i < randomBytes.length; i++) {
      const index = randomBytes[i] % chars.length;
      otp += chars[index];
    }
    return otp;
  }

/**
 * Verifies whether the user-entered OTP matches the expected OTP.
 *
 * @remarks
 * - Performs a constant-time comparison (`crypto.timingSafeEqual`) to prevent timing attacks.
 * - Supports optional expiration validation through `opts.expiresAt`.
 * - Returns `false` if either OTP is missing, expired, or does not match.
 *
 * @param userOtp - The OTP entered by the user (e.g., from input).
 * @param expectedOtp - The expected OTP to verify against (e.g., stored/generated OTP).
 * @param opts - Optional verification parameters.
 * @param opts.expiresAt - A UNIX timestamp (in ms) indicating when the OTP should expire.
 *
 * @returns `true` if the OTP is valid and matches the expected OTP, otherwise `false`.
 *
 * @example
 * ```ts
 * const otp = "123456"; // From database
 * const userInput = "123456"; // From user
 * const isValid = otpAlgorithm.verify(userInput, otp, { expiresAt: Date.now() + 30000 });
 * console.log(isValid); // true (if not expired)
 * ```
 */
  verify(
    userOtp: string,
    expectedOtp: string,
    opts?: { expiresAt?: number }
  ): boolean | number {
    if (!userOtp || !expectedOtp) return false;

    if (opts?.expiresAt && Date.now() > opts.expiresAt) {
      return false;
    }

    try {
      return crypto.timingSafeEqual(
        Buffer.from(userOtp),
        Buffer.from(expectedOtp)
      );
    } catch {
      return false;
    }
  }
}
