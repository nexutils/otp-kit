import { RandomOtpAlgorithm } from "../algorithms/random.algorithm";
import { HotpOtpAlgorithm } from "../algorithms/hotp.algorithm";
import { TotpOtpAlgorithm } from "../algorithms/totp.algorithm";
import { RandomOtpOptions, HotpOptions, TotpOptions } from "../algorithms/base.algorithm";
export type OtpType = "random" | "hotp" | "totp";
export default class OtpKit {
    static create(type: "random", options: RandomOtpOptions): RandomOtpAlgorithm;
    static create(type: "hotp", options: HotpOptions): HotpOtpAlgorithm;
    static create(type: "totp", options: TotpOptions): TotpOtpAlgorithm;
}
//# sourceMappingURL=otpkit.d.ts.map