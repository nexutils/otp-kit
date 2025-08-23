export interface OtpAlgorithm {
  generate(secret?: string, movingFactor?: number | bigint): string;
  verify(input: string, secret?: string, opts?: any): boolean | number;
}

export interface RandomOtpOptions {
  length?: number;
  digits?: boolean;
  lowerCaseAlphabets?: boolean;
  upperCaseAlphabets?: boolean;
  specialChars?: boolean;
}
