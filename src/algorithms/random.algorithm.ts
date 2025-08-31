import crypto from "crypto";
import { RandomOtpOptions, OtpAlgorithm } from "./base.algorithm";
import { getChars } from "../utils/getChar";

const DEFAULT_LENGTH = 6;

export class RandomOtpAlgorithm implements OtpAlgorithm {
  constructor(private options: RandomOtpOptions) {
    const defaults = {
      length: DEFAULT_LENGTH,
      charset: "numeric",
      customCharset: undefined,
    };

    this.options = { ...defaults, ...options };

    if (this.options.charset === "custom" && !this.options.customCharset) {
      throw new Error("Custom charset is required when charset is 'custom'");
    }

    if (this.options.length! <= 0) {
      throw new Error("Invalid OTP length");
    }

    if (this.options.charset !== "custom" && this.options.customCharset) {
      throw new Error(
        "Custom charset is not allowed when charset is not 'custom'"
      );
    }
  }

  generate(secret?: string, movingFactor?: number | bigint): string {
    const chars = getChars(this.options.charset, this.options.customCharset);
    let otp = "";
    const randomBytes = crypto.randomBytes(this.options.length || DEFAULT_LENGTH);

    for (let i = 0; i < randomBytes.length; i++) {
      const index = randomBytes[i] % chars.length;
      otp += chars[index];
    }
    return otp;
  }

  verify(input: string, secret?: string, opts?: any): boolean | number {
    // Implementation for verifying the OTP
    return false;
  }
}
