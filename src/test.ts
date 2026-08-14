import {OtpKit} from "./index";

import { HashAlgorithm } from "./algorithms/base.algorithm";

const otpGenerator = OtpKit.create("hotp", {
  counter: 1,
  digits: 6,
  algorithm: "SHA-1",
  secret: "JBSWY3DPEHPK3PXP"
});
const otp = otpGenerator.generate();
console.log("Generated HOTP:", otp);