import { RandomOtpAlgorithm } from "../algorithms/random.algorithm";
import { RandomOtpOptions, OtpAlgorithm } from "../algorithms/base.algorithm";

export type OtpType = "random";

export default class OtpKit {
   static create(type: OtpType, options?: RandomOtpOptions): OtpAlgorithm {
    switch (type) {
      case "random":
        return new RandomOtpAlgorithm(options ?? { length: 6, charset: "numeric" });
      default:
        throw new Error("Unknown OTP type");
    }
  }

}