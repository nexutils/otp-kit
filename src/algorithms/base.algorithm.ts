export interface OtpAlgorithm {
  generate(secret?: string, movingFactor?: number | bigint): string;
  verify(input: string, secret?: string, opts?: any): boolean | number;
}

export type Charset =
  | "numeric"   
  | "alphabetic"  
  | "alphanumeric" 
  | "hex"
  | "custom"; 



export interface RandomOtpOptionsBase {
  length?: number;
  charset?: Charset;
  customCharset?: string; 
}


interface RandomOtpOptionsWithCustom extends RandomOtpOptionsBase {
  charset: "custom";
  customCharset: string;
}

interface RandomOtpOptionsWithoutCustom extends RandomOtpOptionsBase {
  charset: Exclude<Charset, "custom">;
  customCharset?: never;
}

export type RandomOtpOptions = RandomOtpOptionsWithCustom | RandomOtpOptionsWithoutCustom;
