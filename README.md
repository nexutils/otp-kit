# OTP Kit

A lightweight and extensible library for generating and verifying One-Time Passwords (OTPs).  
Supports **random OTPs** (numeric, alphanumeric, custom charset), **HOTP** ([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)), and **TOTP** ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)).

[![npm version](https://img.shields.io/npm/v/otp-kit)](https://www.npmjs.com/package/otp-kit)
[![npm downloads](https://img.shields.io/npm/dm/otp-kit)](https://www.npmjs.com/package/otp-kit)
[![license](https://img.shields.io/npm/l/otp-kit)](./LICENSE)

---

## ✨ Features
- Generate OTPs with **numeric**, **alphabetic**, **alphanumeric**, or **custom charsets**
- Configurable OTP length (default: 6)
- **HOTP** (counter-based) and **TOTP** (time-based) generation & verification, per RFC 4226 / RFC 6238
- Configurable digits, hash algorithm (`SHA-1`, `SHA-256`, `SHA-512`), period, and epoch
- Window-based verification to tolerate counter drift / clock skew (capped to prevent abuse)
- Secure verification using `crypto.timingSafeEqual` and unbiased `crypto.randomInt`/`crypto.randomBytes`
- Optional **expiry validation**

---

## 📦 Installation

```bash
npm install otp-kit
# or
yarn add otp-kit

```

## 🚀 Usage

```bash
import { OtpKit } from "otp-kit";

# Create a random numeric OTP generator (default length: 6)
const otpGenerator = OtpKit.create("random", { length: 6, charset: "numeric" });

const otp = otpGenerator.generate();
console.log(otp) # "879053"

# Verify OTP (with optional expiry)
const isValid = otpGenerator.verify("123456", otp, { expiresAt: Date.now() + 30000 });
console.log("Is OTP valid?", isValid); 
```

### HOTP (counter-based, RFC 4226)

```ts
import { OtpKit } from "otp-kit";

const hotp = OtpKit.create("hotp", {
  secret: "JBSWY3DPEHPK3PXP", // Base32-encoded shared secret
  counter: 1,                 // moving factor, managed by your app
  digits: 6,                  // optional, default 6
  algorithm: "SHA-1",         // optional, default "SHA-1"
});

const otp = hotp.generate();
console.log(otp); // e.g. "287082"

// Verify against a counter, optionally allowing a forward window
// to tolerate the client and server counters drifting apart.
const result = hotp.verify(otp, undefined, { counter: 1, window: 5 });
console.log(result); // { valid: true, delta: 0 }
```

> After a successful verification, persist `counter + delta + 1` as the new counter — HOTP counters must always move forward to prevent replay of a used code.

### TOTP (time-based, RFC 6238)

```ts
import { OtpKit } from "otp-kit";

const totp = OtpKit.create("totp", {
  secret: "JBSWY3DPEHPK3PXP", // Base32-encoded shared secret
  digits: 6,                  // optional, default 6
  algorithm: "SHA-1",         // optional, default "SHA-1"
  period: 30,                 // optional, seconds per time step, default 30
});

const otp = totp.generate();
console.log(otp); // e.g. "123456", valid for the current 30s step

// Verify against the current time, optionally allowing a window of
// time steps before/after to tolerate clock drift.
const result = totp.verify(otp, undefined, { window: 1 });
console.log(result); // { valid: true, delta: 0 }
```

> `secret` is bound when the instance is created — passing a `secret` to `generate()`/`verify()` throws, rather than silently using the wrong key. Create a new `OtpKit` instance per secret (e.g. per user).

## ⚙️ Options

### `RandomOtpOptions`

| Option         | Type                                               | Default  | Description                                      |
|----------------|----------------------------------------------------|----------|--------------------------------------------------|
| length       | `number`                                           | `6`      | Length of the OTP                                |
| charset      | `"numeric" \| "alphabetic" \| "alphanumeric" \| "custom"` | `"numeric"` | Defines which characters can be used in OTP      |
| customCharset| `string`                                           | `undefined` | Required when `charset = "custom"`                |

---

### `HotpOptions`

| Option    | Type                                    | Default   | Description                                  |
|-----------|------------------------------------------|-----------|-----------------------------------------------|
| secret    | `string`                                 | required  | Base32-encoded shared secret                   |
| counter   | `number \| bigint`                       | required  | Moving counter value (must be a non-negative integer) |
| digits    | `number`                                 | `6`       | OTP length, must be between `4` and `10`       |
| algorithm | `"SHA-1" \| "SHA-256" \| "SHA-512"`      | `"SHA-1"` | HMAC hash algorithm                            |

`hotp.verify(input, secret?, opts?)` accepts:

| Option  | Type               | Default            | Description                                                        |
|---------|--------------------|--------------------|----------------------------------------------------------------------|
| counter | `number \| bigint` | instance `counter` | Counter to verify against                                           |
| window  | `number`           | `0`                | Number of counters to check forward, `0`–`10`                       |

---

### `TotpOptions`

| Option    | Type                                    | Default   | Description                                  |
|-----------|------------------------------------------|-----------|-----------------------------------------------|
| secret    | `string`                                 | required  | Base32-encoded shared secret                   |
| digits    | `number`                                 | `6`       | OTP length, must be between `4` and `10`       |
| algorithm | `"SHA-1" \| "SHA-256" \| "SHA-512"`      | `"SHA-1"` | HMAC hash algorithm                            |
| period    | `number`                                 | `30`      | Time step size, in seconds                     |
| epoch     | `number`                                 | `0`       | Unix epoch offset, in milliseconds             |

`totp.verify(input, secret?, opts?)` accepts:

| Option    | Type               | Default      | Description                                                      |
|-----------|--------------------|--------------|--------------------------------------------------------------------|
| timestamp | `number \| bigint` | `Date.now()` | Timestamp (ms) to verify against                                   |
| window    | `number`           | `0`          | Number of time steps to check before/after, `0`–`10`               |

---

### Charset Modes

| Mode          | Characters Allowed      | Example OTP   |
|---------------|-------------------------|---------------|
| numeric     | `0-9`                   | `483920`      |
| alphabetic  | `a-zA-Z`                | `AbCdEf`      |
| alphanumeric| `0-9a-zA-Z`             | `a9B3c2`      |
| custom      | User-defined characters | `ABCDE` |

✅ Example with **custom charset**:
```ts
const otpGenerator = OtpKit.create("random", {
  length: 5,
  charset: "custom",
  customCharset: "ABCDE"
  });
console.log(otpGenerator.generate()); // Example output: BCAAD

```

## 📄 License

[MIT](https://github.com/nexutils/otp-kit/blob/main/LICENSE)