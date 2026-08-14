// ==================== OTP CORE INTERFACE ====================

export interface OtpAlgorithm<ResultType = unknown> {
  generate(secret?: string, movingFactor?: number | bigint): string;
  verify(input: string, secret?: string, opts?: Record<string, unknown>): ResultType;
}

// ==================== HASH ENUM ====================

export type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

// ==================== CHARSET TYPES ====================

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

// ==================== HOTP OPTIONS ====================

export interface HotpOptions {
  readonly secret: string; // Base32 encoded
  readonly counter: number | bigint;
  readonly digits?: number; // 4–10 recommended
  readonly algorithm?: HashAlgorithm;
}

export interface HotpVerifyOptions {
  readonly counter?: number | bigint;
  readonly window?: number;
}

// ==================== TOTP OPTIONS ====================

export interface TotpOptions {
  readonly secret: string; // Base32 encoded
  readonly digits?: number; // 4–10 recommended
  readonly algorithm?: HashAlgorithm;
  readonly period?: number; // step in seconds (default 30)
  readonly epoch?: number; // epoch in ms (default 0)
}

export interface TotpVerifyOptions {
  readonly timestamp?: number | bigint;
  readonly window?: number;
}

// ==================== VERIFY RESULT ====================

export interface VerifyResult {
  valid: boolean;
  delta?: number;
}
