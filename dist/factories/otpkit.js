"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const random_algorithm_1 = require("../algorithms/random.algorithm");
const hotp_algorithm_1 = require("../algorithms/hotp.algorithm");
const totp_algorithm_1 = require("../algorithms/totp.algorithm");
class OtpKit {
    static create(type, options) {
        switch (type) {
            case "random":
                return new random_algorithm_1.RandomOtpAlgorithm(options ?? { length: 6, charset: "numeric" });
            case "hotp":
                return new hotp_algorithm_1.HotpOtpAlgorithm(options);
            case "totp":
                return new totp_algorithm_1.TotpOtpAlgorithm(options);
            default:
                throw new Error(`Unsupported OTP type: ${type}`);
        }
    }
}
exports.default = OtpKit;
//# sourceMappingURL=otpkit.js.map