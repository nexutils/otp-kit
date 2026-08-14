import { HotpOptions, HotpVerifyOptions, OtpAlgorithm, VerifyResult } from "./base.algorithm";
/**
 * Custom error class for OTP-related exceptions.
 *
 * @remarks
 * Used for validation errors like invalid secret, digit range violations,
 * or Base32 decoding failures.
 */
export declare class OtpError extends Error {
    constructor(msg: string);
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
export declare class HotpOtpAlgorithm implements OtpAlgorithm<VerifyResult> {
    private readonly opts;
    private readonly digits;
    private readonly algorithm;
    private readonly secretKey;
    private readonly counter;
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
    constructor(opts: HotpOptions);
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
    generate(secret?: string, movingFactor?: number | bigint): string;
    verify(input: string, secret?: string, opts?: HotpVerifyOptions): VerifyResult;
}
//# sourceMappingURL=hotp.algorithm.d.ts.map