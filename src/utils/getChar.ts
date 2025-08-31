import { Charset } from "../algorithms/base.algorithm";


export function getChars(charset: Charset, customChars?: string): string {
  switch (charset) {
    case "numeric":
      return "0123456789";

    case "alphabetic":
      return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    case "alphanumeric":
      return "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    case "hex":
      return "0123456789abcdef";

    case "custom":
      if (!customChars || customChars.length === 0) {
        throw new Error("customChars must be provided when charset is 'custom'");
      }

      return customChars;

    default:
      throw new Error(`Unsupported charset: ${charset}`);
  }
}