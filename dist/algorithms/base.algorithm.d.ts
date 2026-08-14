export interface OtpAlgorithm<ResultType = unknown> {
    generate(secret?: string, movingFactor?: number | bigint): string;
    verify(input: string, secret?: string, opts?: Record<string, unknown>): ResultType;
}
export type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";
export type Charset = "numeric" | "alphabetic" | "alphanumeric" | "hex" | "custom";
export interface RandomOtpOptionsBase {
    readonly length?: number;
    readonly charset?: Charset;
    readonly customCharset?: string;
}
export interface RandomOtpOptionsWithCustom extends RandomOtpOptionsBase {
    readonly charset: "custom";
    readonly customCharset: string;
}
export interface RandomOtpOptionsWithoutCustom extends RandomOtpOptionsBase {
    readonly charset?: Exclude<Charset, "custom">;
    readonly customCharset?: never;
}
export type RandomOtpOptions = RandomOtpOptionsWithCustom | RandomOtpOptionsWithoutCustom;
export interface HotpOptions {
    readonly secret: string;
    readonly counter: number | bigint;
    readonly digits?: number;
    readonly algorithm?: HashAlgorithm;
}
export interface HotpVerifyOptions {
    readonly counter?: number | bigint;
    readonly window?: number;
}
export interface TotpOptions {
    readonly secret: string;
    readonly digits?: number;
    readonly algorithm?: HashAlgorithm;
    readonly period?: number;
    readonly epoch?: number;
}
export interface TotpVerifyOptions {
    readonly timestamp?: number | bigint;
    readonly window?: number;
}
export interface VerifyResult {
    valid: boolean;
    delta?: number;
}
//# sourceMappingURL=base.algorithm.d.ts.map