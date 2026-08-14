import { OtpAlgorithm, TotpOptions, TotpVerifyOptions, VerifyResult } from "./base.algorithm";
/**
 * RFC 6238 Time-based One-Time Password (TOTP) implementation.
 */
export declare class TotpOtpAlgorithm implements OtpAlgorithm<VerifyResult> {
    private readonly opts;
    private readonly period;
    private readonly epoch;
    private readonly hotp;
    constructor(opts: TotpOptions);
    generate(secret?: string, movingFactor?: number | bigint): string;
    verify(input: string, secret?: string, opts?: TotpVerifyOptions): VerifyResult;
    private counterForTimestamp;
}
//# sourceMappingURL=totp.algorithm.d.ts.map