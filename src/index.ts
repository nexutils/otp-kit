import { RandomOtpAlgorithm } from "./algorithms/random.algorithm";


const otpGenerator = new RandomOtpAlgorithm({length:4,charset:'numeric'});

const otp = otpGenerator.generate();

console.log("otp gen", otp);