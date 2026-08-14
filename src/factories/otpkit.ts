import { RandomOtpAlgorithm } from "../algorithms/random.algorithm";
import { HotpOtpAlgorithm } from "../algorithms/hotp.algorithm";
import { TotpOtpAlgorithm } from "../algorithms/totp.algorithm";
import { OtpAlgorithm, RandomOtpOptions, HotpOptions, TotpOptions } from "../algorithms/base.algorithm";

export type OtpType = "random" | "hotp" | "totp";

export default class OtpKit {
  static create(type: "random", options: RandomOtpOptions): RandomOtpAlgorithm;
  static create(type: "hotp", options: HotpOptions): HotpOtpAlgorithm;
  static create(type: "totp", options: TotpOptions): TotpOtpAlgorithm;
  static create(type: OtpType, options: any): OtpAlgorithm {
    switch (type) {
      case "random":
        return new RandomOtpAlgorithm(options ?? { length: 6, charset: "numeric" });
      case "hotp":
        return new HotpOtpAlgorithm(options);
      case "totp":
        return new TotpOtpAlgorithm(options);
      default:
        throw new Error(`Unsupported OTP type: ${type}`);
    }
  }
}
