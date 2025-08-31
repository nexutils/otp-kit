import { RandomOtpAlgorithm } from "../src/algorithms/random.algorithm";

describe("RandomOtpAlgorithm", () => {
  describe("Valid OTP Generation", () => {
    it("should generate an OTP of default length (6) when no length is provided", () => {
      const otpGenerator = new RandomOtpAlgorithm({ charset: "numeric" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(6);
      expect(/^\d{6}$/.test(otp)).toBe(true);
    });

    it("should generate a numeric OTP of given length", () => {
      const otpGenerator = new RandomOtpAlgorithm({ length: 4, charset: "numeric" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(4);
      expect(/^\d{4}$/.test(otp)).toBe(true);
    });

    it("should generate an alphabetic OTP of given length", () => {
      const otpGenerator = new RandomOtpAlgorithm({ length: 5, charset: "alphabetic" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(5);
      expect(/^[a-zA-Z]{5}$/.test(otp)).toBe(true);
    });

    it("should generate an alphanumeric OTP of given length", () => {
      const otpGenerator = new RandomOtpAlgorithm({ length: 8, charset: "alphanumeric" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(8);
      expect(/^[a-zA-Z0-9]{8}$/.test(otp)).toBe(true);
    });

    it("should generate a hex OTP", () => {
      const otpGenerator = new RandomOtpAlgorithm({ length: 6, charset: "hex" });
      const otp = otpGenerator.generate();
      expect(otp).toHaveLength(6);
      expect(/^[0-9a-f]+$/.test(otp)).toBe(true);
    });

    it("should generate an OTP from a custom charset", () => {
      const otpGenerator = new RandomOtpAlgorithm({
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
      expect(() => new RandomOtpAlgorithm({ length: 0, charset: "numeric" }))
        .toThrow("Invalid OTP length");
      expect(() => new RandomOtpAlgorithm({ length: -5, charset: "numeric" }))
        .toThrow("Invalid OTP length");
    });

    it("should throw if customCharset is an empty string", () => {
      expect(() =>
        new RandomOtpAlgorithm({ length: 6, charset: "custom", customCharset: "" })
      ).toThrow("Custom charset is required when charset is 'custom'");
    });
  });

  describe("Randomness Checks", () => {
    it("should generate different OTPs on consecutive calls", () => {
      const otpGenerator = new RandomOtpAlgorithm({ length: 6, charset: "numeric" });
      const otp1 = otpGenerator.generate();
      const otp2 = otpGenerator.generate();
      expect(otp1).not.toEqual(otp2);
    });
  });
});
