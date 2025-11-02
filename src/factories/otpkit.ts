import { RandomOtpAlgorithm } from "../algorithms/random.algorithm";
import { HotpOtpAlgorithm } from "../algorithms/hotp.algorithm";
import { OtpAlgorithm, RandomOtpOptions, HotpOptions } from "../algorithms/base.algorithm";

export type OtpType = "random" | "hotp";

export default class OtpKit {
  static create(type: "random", options: RandomOtpOptions): RandomOtpAlgorithm;
  static create(type: "hotp", options: HotpOptions): HotpOtpAlgorithm;
  static create(type: OtpType, options: any): OtpAlgorithm {
    switch (type) {
      case "random":
        return new RandomOtpAlgorithm(options ?? { length: 6, charset: "numeric" });
      case "hotp":
        return new HotpOtpAlgorithm(options);
      default:
        throw new Error(`Unsupported OTP type: ${type}`);
    }
  }
}
