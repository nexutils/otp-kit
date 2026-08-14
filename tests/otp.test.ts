import { describe, expect, it } from "@jest/globals";
import OtpKit from "../src/factories/otpkit";
import { HotpOtpAlgorithm, OtpError } from "../src/algorithms/hotp.algorithm";
import { TotpOtpAlgorithm } from "../src/algorithms/totp.algorithm";

describe("RandomOtpAlgorithm", () => {
  describe("Valid OTP Generation", () => {
    it("should generate an OTP of default length (6) when no length is provided", () => {
      const otpGenerator = OtpKit.create("random", { charset: "numeric" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(6);
      expect(/^\d{6}$/.test(otp)).toBe(true);
    });

    it("should generate a numeric OTP of given length", () => {
      const otpGenerator = OtpKit.create("random", { length: 4, charset: "numeric" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(4);
      expect(/^\d{4}$/.test(otp)).toBe(true);
    });

    it("should generate an alphabetic OTP of given length", () => {
      const otpGenerator = OtpKit.create("random", { length: 5, charset: "alphabetic" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(5);
      expect(/^[a-zA-Z]{5}$/.test(otp)).toBe(true);
    });

    it("should generate an alphanumeric OTP of given length", () => {
      const otpGenerator = OtpKit.create("random", { length: 8, charset: "alphanumeric" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(8);
      expect(/^[a-zA-Z0-9]{8}$/.test(otp)).toBe(true);
    });

    it("should generate a hex OTP", () => {
      const otpGenerator = OtpKit.create("random", { length: 6, charset: "hex" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(6);
      expect(/^[0-9a-f]+$/.test(otp)).toBe(true);
    });

    it("should generate an OTP from a custom charset", () => {
      const otpGenerator = OtpKit.create("random", {
        length: 5,
        charset: "custom",
        customCharset: "abcd1234"
      });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(5);
      expect(/^[abcd1234]+$/.test(otp)).toBe(true);
    });
  });

  describe("Invalid Options Handling", () => {
    it("should throw if length is 0 or negative", () => {
      expect(() => OtpKit.create("random", { length: 0, charset: "numeric" }))
        .toThrow("Invalid OTP length");
      expect(() => OtpKit.create("random", { length: -5, charset: "numeric" }))
        .toThrow("Invalid OTP length");
    });

    it("should throw if customCharset is an empty string", () => {
      expect(() =>
        OtpKit.create("random", { length: 6, charset: "custom", customCharset: "" })
      ).toThrow("Custom charset is required when charset is 'custom'");
    });
  });

  describe("Randomness Checks", () => {
    it("should generate different OTPs on consecutive calls", () => {
      const otpGenerator = OtpKit.create("random", { length: 6, charset: "numeric" });
      const otp1 = otpGenerator.generate();
      const otp2 = otpGenerator.generate();
      expect(otp1).not.toEqual(otp2);
    });
  });

  describe("OTP Verification", () => {
    it("should return true for matching OTPs", () => {
      const otpGenerator = OtpKit.create("random", { length: 6, charset: "numeric" });
      const otp = otpGenerator.generate();
      const isValid = otpGenerator.verify(otp, otp);
      expect(isValid).toBe(true);
    });

    it("should return false for non-matching OTPs", () => {
      const otpGenerator = OtpKit.create("random", { length: 6, charset: "numeric" });
      const otp = otpGenerator.generate();
      const isValid = otpGenerator.verify("123456", otp);
      expect(isValid).toBe(false);
    });

    it("should return false if OTP is expired", () => {
      const otpGenerator = OtpKit.create("random", { length: 6, charset: "numeric" });
      const otp = otpGenerator.generate();
      const isValid = otpGenerator.verify(otp, otp, { expiresAt: Date.now() - 1000 });
      expect(isValid).toBe(false);
    });

    it("should return true if OTP matches and not expired", () => {
      const otpGenerator = OtpKit.create("random", { length: 6, charset: "numeric" });
      const otp = otpGenerator.generate();
      const isValid = otpGenerator.verify(otp, otp, { expiresAt: Date.now() + 5000 });
      expect(isValid).toBe(true);
    });
  });

  describe("Factory", () => {
    it("should create TOTP algorithm via factory", () => {
      const totp = OtpKit.create("totp", { secret: "JBSWY3DPEHPK3PXP" });
      expect(totp).toBeInstanceOf(TotpOtpAlgorithm);
    });
  });
});


// HOTP Tests
describe("HotpOtpAlgorithm", () => {
  const validSecret = "JBSWY3DPEHPK3PXP"; // "Hello!" in Base32

  describe("Initialization", () => {
    it("should throw if secret is missing", () => {
      expect(() => new HotpOtpAlgorithm({ secret: "", counter: 0 }))
        .toThrow(OtpError);
    });

    it("should throw if digits < 4 or > 10", () => {
      expect(() => new HotpOtpAlgorithm({ secret: validSecret, counter: 1, digits: 3 }))
        .toThrow("Digits must be between 4 and 10");
      expect(() => new HotpOtpAlgorithm({ secret: validSecret, counter: 1, digits: 11 }))
        .toThrow("Digits must be between 4 and 10");
    });

    it("should throw for invalid Base32 secret", () => {
      expect(() => new HotpOtpAlgorithm({ secret: "###", counter: 1 }))
        .toThrow("Invalid Base32 secret encoding");
    });

    it("should initialize with defaults properly", () => {
      const hotp = new HotpOtpAlgorithm({ secret: validSecret, counter: 1 });
      expect(hotp).toBeInstanceOf(HotpOtpAlgorithm);
    });
  });

  describe("OTP Generation", () => {
    it("should generate correct HOTP (RFC 4226 test vector #0)", () => {
      const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"
      const hotp = new HotpOtpAlgorithm({
        secret,
        counter: 0,
        digits: 6,
        algorithm: "SHA-1",
      });
      const otp = hotp.generate(undefined, 0);
      expect(otp).toBe("755224");
    });

    it("should generate correct HOTP for counter 1", () => {
      const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
      const hotp = new HotpOtpAlgorithm({
        secret,
        counter: 1,
        digits: 6,
        algorithm: "SHA-1",
      });
      const otp = hotp.generate(undefined, 1);
      expect(otp).toBe("287082");
    });

    it("should generate OTP with correct number of digits", () => {
      const hotp = new HotpOtpAlgorithm({
        secret: validSecret,
        counter: 1,
        digits: 8,
      });
      const otp = hotp.generate();
      expect(otp).toHaveLength(8);
      expect(/^\d+$/.test(otp)).toBe(true);
    });
  });

  describe("OTP Verification", () => {
    it("should verify valid OTP for exact counter", () => {
      const hotp = new HotpOtpAlgorithm({
        secret: validSecret,
        counter: 1,
      });
      const otp = hotp.generate(undefined, 1);
      const result = hotp.verify(otp, undefined, { counter: 1 });
      expect(result.valid).toBe(true);
      expect(result.delta).toBe(0);
    });

    it("should return invalid for wrong OTP", () => {
      const hotp = new HotpOtpAlgorithm({
        secret: validSecret,
        counter: 1,
      });
      const result = hotp.verify("123456", undefined, { counter: 1 });
      expect(result.valid).toBe(false);
    });

    it("should verify within counter window", () => {
      const hotp = new HotpOtpAlgorithm({
        secret: validSecret,
        counter: 1,
      });
      const otpAtCounter3 = hotp.generate(undefined, 3);
      const result = hotp.verify(otpAtCounter3, undefined, { counter: 1, window: 5 });
      expect(result.valid).toBe(true);
      expect(result.delta).toBe(2);
    });

    it("should throw for invalid window value", () => {
      const hotp = new HotpOtpAlgorithm({
        secret: validSecret,
        counter: 1,
      });
      expect(() => hotp.verify("123456", undefined, { window: -1 }))
        .toThrow("Window must be a non-negative integer");
    });
  });

  describe("Determinism & Consistency", () => {
    it("should always generate same OTP for same secret and counter", () => {
      const hotp1 = new HotpOtpAlgorithm({ secret: validSecret, counter: 5 });
      const hotp2 = new HotpOtpAlgorithm({ secret: validSecret, counter: 5 });
      const otp1 = hotp1.generate();
      const otp2 = hotp2.generate();
      expect(otp1).toBe(otp2);
    });

    it("should generate different OTPs for different counters", () => {
      const hotp = new HotpOtpAlgorithm({ secret: validSecret, counter: 0 });
      const otp1 = hotp.generate(undefined, 1);
      const otp2 = hotp.generate(undefined, 2);
      expect(otp1).not.toBe(otp2);
    });
  });
});

describe("TotpOtpAlgorithm", () => {
  const rfcSecretSha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  it("should initialize with defaults", () => {
    const totp = new TotpOtpAlgorithm({ secret: rfcSecretSha1 });
    expect(totp).toBeInstanceOf(TotpOtpAlgorithm);
  });

  it("should throw for invalid period", () => {
    expect(() => new TotpOtpAlgorithm({ secret: rfcSecretSha1, period: 0 }))
      .toThrow("Period must be a positive integer");
  });

  it("should throw for invalid epoch", () => {
    expect(() => new TotpOtpAlgorithm({ secret: rfcSecretSha1, epoch: -1 }))
      .toThrow("Epoch must be a non-negative integer");
  });

  it("should match RFC 6238 SHA-1 test vectors", () => {
    const totp = new TotpOtpAlgorithm({
      secret: rfcSecretSha1,
      digits: 8,
      algorithm: "SHA-1",
      period: 30,
      epoch: 0,
    });

    const vectors = [
      { timestampSec: 59, otp: "94287082" },
      { timestampSec: 1111111109, otp: "07081804" },
      { timestampSec: 1111111111, otp: "14050471" },
      { timestampSec: 1234567890, otp: "89005924" },
      { timestampSec: 2000000000, otp: "69279037" },
      { timestampSec: 20000000000, otp: "65353130" },
    ];

    for (const vector of vectors) {
      expect(totp.generate(undefined, vector.timestampSec * 1000)).toBe(vector.otp);
    }
  });

  it("should verify valid OTP at exact time step", () => {
    const totp = new TotpOtpAlgorithm({
      secret: rfcSecretSha1,
      digits: 8,
      algorithm: "SHA-1",
    });

    const timestamp = 1111111111000;
    const otp = totp.generate(undefined, timestamp);
    const result = totp.verify(otp, undefined, { timestamp });
    expect(result.valid).toBe(true);
    expect(result.delta).toBe(0);
  });

  it("should verify OTP within time window", () => {
    const totp = new TotpOtpAlgorithm({
      secret: rfcSecretSha1,
      digits: 8,
      algorithm: "SHA-1",
      period: 30,
    });

    const serverTime = 1234567890000;
    const clientDriftedTime = serverTime + 30000;
    const otp = totp.generate(undefined, clientDriftedTime);

    const result = totp.verify(otp, undefined, {
      timestamp: serverTime,
      window: 1,
    });

    expect(result.valid).toBe(true);
    expect(result.delta).toBe(1);
  });

  it("should reject invalid OTP", () => {
    const totp = new TotpOtpAlgorithm({ secret: rfcSecretSha1, digits: 8 });
    const result = totp.verify("00000000", undefined, {
      timestamp: 1234567890000,
    });
    expect(result.valid).toBe(false);
  });

  it("should throw for negative window", () => {
    const totp = new TotpOtpAlgorithm({ secret: rfcSecretSha1 });
    expect(() => totp.verify("123456", undefined, { window: -1 }))
      .toThrow("Window must be a non-negative integer");
  });

  it("should throw when timestamp is earlier than epoch", () => {
    const totp = new TotpOtpAlgorithm({ secret: rfcSecretSha1, epoch: 1000 });
    expect(() => totp.generate(undefined, 500))
      .toThrow(OtpError);
  });
});
