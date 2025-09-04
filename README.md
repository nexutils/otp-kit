# OTP Kit

A lightweight and extensible library for generating and verifying One-Time Passwords (OTPs).  
Supports **random OTPs** (numeric, alphanumeric, custom charset), with planned support for **TOTP** and **HOTP**.

---

## ✨ Features
- Generate OTPs with **numeric**, **alphabetic**, **alphanumeric**, or **custom charsets**
- Configurable OTP length (default: 6)
- Secure verification using `crypto.timingSafeEqual`
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

## ⚙️ Options

### `RandomOtpOptions`

| Option         | Type                                               | Default  | Description                                      |
|----------------|----------------------------------------------------|----------|--------------------------------------------------|
| length       | `number`                                           | `6`      | Length of the OTP                                |
| charset      | `"numeric" \| "alphabetic" \| "alphanumeric" \| "custom"` | `"numeric"` | Defines which characters can be used in OTP      |
| customCharset| `string`                                           | `undefined` | Required when `charset = "custom"`                |

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
const otpGenerator = new RandomOtpAlgorithm({
  length: 5,
  charset: "custom",
  customCharset: "ABCDE"
});
console.log(otpGenerator.generate()); // Example output: BCAAD

```

## 📄 License

[MIT](https://github.com/nexutils/otp-kit/blob/main/LICENSE)