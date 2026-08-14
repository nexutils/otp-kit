"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TotpOtpAlgorithm = void 0;
const base32_decode_1 = __importDefault(require("base32-decode"));
const hotp_algorithm_1 = require("./hotp.algorithm");
const DEFAULT_PERIOD_SECONDS = 30;
const DEFAULT_EPOCH_MS = 0;
/**
 * RFC 6238 Time-based One-Time Password (TOTP) implementation.
 */
class TotpOtpAlgorithm {
    constructor(opts) {
        this.opts = opts;
        if (!opts.secret) {
            throw new hotp_algorithm_1.OtpError("Secret is required");
        }
        const period = opts.period ?? DEFAULT_PERIOD_SECONDS;
        const epoch = opts.epoch ?? DEFAULT_EPOCH_MS;
        if (!Number.isInteger(period) || period <= 0) {
            throw new hotp_algorithm_1.OtpError("Period must be a positive integer (seconds)");
        }
        if (!Number.isInteger(epoch) || epoch < 0) {
            throw new hotp_algorithm_1.OtpError("Epoch must be a non-negative integer (milliseconds)");
        }
        // Validate Base32 early for clearer constructor errors.
        try {
            const key = Buffer.from((0, base32_decode_1.default)(normalizeBase32Secret(opts.secret), "RFC4648"));
            if (key.length === 0) {
                throw new hotp_algorithm_1.OtpError("Invalid Base32 secret encoding");
            }
        }
        catch {
            throw new hotp_algorithm_1.OtpError("Invalid Base32 secret encoding");
        }
        this.period = period;
        this.epoch = epoch;
        this.hotp = new hotp_algorithm_1.HotpOtpAlgorithm({
            secret: opts.secret,
            counter: 0,
            digits: opts.digits,
            algorithm: opts.algorithm,
        });
    }
    generate(secret, movingFactor = Date.now()) {
        const timestampMs = normalizeTimestamp(movingFactor);
        const counter = this.counterForTimestamp(timestampMs);
        return this.hotp.generate(undefined, counter);
    }
    verify(input, secret, opts) {
        if (!input || !/^\d+$/.test(input.trim())) {
            return { valid: false };
        }
        const timestampMs = normalizeTimestamp(opts?.timestamp ?? Date.now());
        const window = opts?.window ?? 0;
        if (!Number.isInteger(window) || window < 0) {
            throw new hotp_algorithm_1.OtpError("Window must be a non-negative integer");
        }
        const baseCounter = this.counterForTimestamp(timestampMs);
        for (let delta = -window; delta <= window; delta++) {
            const shiftedCounter = baseCounter + BigInt(delta);
            if (shiftedCounter < 0n) {
                continue;
            }
            const result = this.hotp.verify(input, undefined, {
                counter: shiftedCounter,
                window: 0,
            });
            if (result.valid) {
                return {
                    valid: true,
                    delta: delta === 0 ? 0 : delta,
                };
            }
        }
        return { valid: false };
    }
    counterForTimestamp(timestampMs) {
        if (timestampMs < this.epoch) {
            throw new hotp_algorithm_1.OtpError("Timestamp cannot be earlier than epoch");
        }
        const seconds = Math.floor((timestampMs - this.epoch) / 1000);
        const counter = Math.floor(seconds / this.period);
        return BigInt(counter);
    }
}
exports.TotpOtpAlgorithm = TotpOtpAlgorithm;
function normalizeTimestamp(value) {
    const numberValue = typeof value === "bigint" ? Number(value) : value;
    if (!Number.isFinite(numberValue) || numberValue < 0) {
        throw new hotp_algorithm_1.OtpError("Timestamp must be a non-negative finite number");
    }
    if (!Number.isSafeInteger(numberValue)) {
        throw new hotp_algorithm_1.OtpError("Timestamp must be a safe integer");
    }
    return numberValue;
}
function normalizeBase32Secret(secret) {
    return secret.replace(/[\s-]+/g, "").replace(/=+$/g, "").toUpperCase();
}
//# sourceMappingURL=totp.algorithm.js.map