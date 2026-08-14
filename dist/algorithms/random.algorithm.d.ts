import { RandomOtpOptions, OtpAlgorithm } from "./base.algorithm";
/**
 * RandomOtpAlgorithm generates random OTPs (One-Time Passwords)
 * using a configurable charset and length.
 *
 * @remarks
 * Unlike HOTP/TOTP, this algorithm does not rely on a secret or time-based factor.
 * It is best suited for use cases like one-time login codes, verification codes,
 * or scenarios where the OTP is stored in a database and validated later.
 */
export declare class RandomOtpAlgorithm implements OtpAlgorithm {
    private options;
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
    constructor(options: RandomOtpOptions);
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
    generate(): string;
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
    verify(userOtp: string, expectedOtp: string, opts?: {
        expiresAt?: number;
    }): boolean | number;
}
//# sourceMappingURL=random.algorithm.d.ts.map