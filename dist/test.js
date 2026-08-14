"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("./index");
const otpGenerator = index_1.OtpKit.create("hotp", {
    counter: 1,
    digits: 6,
    algorithm: "SHA-1",
    secret: "JBSWY3DPEHPK3PXP"
});
const otp = otpGenerator.generate();
console.log("Generated HOTP:", otp);
//# sourceMappingURL=test.js.map