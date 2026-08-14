import base32Decode from "base32-decode";
import { HotpOtpAlgorithm, OtpError } from "./hotp.algorithm";
import { OtpAlgorithm, TotpOptions, TotpVerifyOptions, VerifyResult } from "./base.algorithm";

const DEFAULT_PERIOD_SECONDS = 30;
const DEFAULT_EPOCH_MS = 0;
const MAX_WINDOW = 10;

// RFC 6238 Time based OTP (TOTP) implementation.

export class TotpOtpAlgorithm implements OtpAlgorithm<VerifyResult> {
  private readonly period: number;
  private readonly epoch: number;
  private readonly hotp: HotpOtpAlgorithm;

  constructor(private readonly opts: TotpOptions) {
    if (!opts.secret) {
      throw new OtpError("Secret is required");
    }

    const period = opts.period ?? DEFAULT_PERIOD_SECONDS;
    const epoch = opts.epoch ?? DEFAULT_EPOCH_MS;

    if (!Number.isInteger(period) || period <= 0) {
      throw new OtpError("Period must be a positive integer (seconds)");
    }

    if (!Number.isInteger(epoch) || epoch < 0) {
      throw new OtpError("Epoch must be a non-negative integer (milliseconds)");
    }

    // Validate Base32 early for clearer constructor errors.
    try {
      const key = Buffer.from(base32Decode(normalizeBase32Secret(opts.secret), "RFC4648"));
      if (key.length === 0) {
        throw new OtpError("Invalid Base32 secret encoding");
      }
    } catch {
      throw new OtpError("Invalid Base32 secret encoding");
    }

    this.period = period;
    this.epoch = epoch;
    this.hotp = new HotpOtpAlgorithm({
      secret: opts.secret,
      counter: 0,
      digits: opts.digits,
      algorithm: opts.algorithm,
    });
  }

  generate(secret?: string, movingFactor: number | bigint = Date.now()): string {
    if (secret !== undefined) {
      throw new OtpError(
        "Per-call secret override is not supported; construct a new TotpOtpAlgorithm with the desired secret instead."
      );
    }

    const timestampMs = normalizeTimestamp(movingFactor);
    const counter = this.counterForTimestamp(timestampMs);
    return this.hotp.generate(undefined, counter);
  }

  verify(input: string, secret?: string, opts?: TotpVerifyOptions): VerifyResult {
    if (secret !== undefined) {
      throw new OtpError(
        "Per-call secret override is not supported; construct a new TotpOtpAlgorithm with the desired secret instead."
      );
    }

    if (!input || !/^\d+$/.test(input.trim())) {
      return { valid: false };
    }

    const timestampMs = normalizeTimestamp(opts?.timestamp ?? Date.now());
    const window = opts?.window ?? 0;

    if (!Number.isInteger(window) || window < 0 || window > MAX_WINDOW) {
      throw new OtpError(`Window must be a non-negative integer no greater than ${MAX_WINDOW}`);
    }

    const baseCounter = this.counterForTimestamp(timestampMs);

    for (let delta = -window; delta <= window; delta++) {
      const shiftedCounter = baseCounter + BigInt(delta);
      if (shiftedCounter < 0n) {
        continue;
      }

      const result = this.hotp.verify(input, undefined, {
        counter: shiftedCounter,
        window: 0,
      });

      if (result.valid) {
        return {
          valid: true,
          delta: delta === 0 ? 0 : delta,
        };
      }
    }

    return { valid: false };
  }

  private counterForTimestamp(timestampMs: number): bigint {
    if (timestampMs < this.epoch) {
      throw new OtpError("Timestamp cannot be earlier than epoch");
    }

    const seconds = Math.floor((timestampMs - this.epoch) / 1000);
    const counter = Math.floor(seconds / this.period);
    return BigInt(counter);
  }
}

function normalizeTimestamp(value: number | bigint): number {
  const numberValue = typeof value === "bigint" ? Number(value) : value;

  if (!Number.isFinite(numberValue) || numberValue < 0) {
    throw new OtpError("Timestamp must be a non-negative finite number");
  }

  if (!Number.isSafeInteger(numberValue)) {
    throw new OtpError("Timestamp must be a safe integer");
  }

  return numberValue;
}

function normalizeBase32Secret(secret: string): string {
  return secret.replace(/[\s-]+/g, "").replace(/=+$/g, "").toUpperCase();
}
