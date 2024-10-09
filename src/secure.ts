import { K2Error, ServiceError } from "@frogfish/k2error";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

export class Secure {
  // Define the number of salt rounds for hashing
  private static bycriptSaltRounds: number = 10;
  // Define a secret key for JWT (this should ideally be stored securely, like in environment variables)
  private static jwtSecret: string = "your-secure-secret-key"; // Replace with your own secret key or get from environment variables
  private static jwtExpires: string = "1h";

  /**
   * Hashes a plain text password using bcrypt.
   * @param text - The plain text password to hash.
   * @returns A promise that resolves to the hashed password.
   */
  public static async bcrypt(text: string): Promise<string> {
    try {
      const salt = await bcrypt.genSalt(this.bycriptSaltRounds);
      const hash = await bcrypt.hash(text, salt);
      return hash;
    } catch (error) {
      throw new K2Error(
        ServiceError.SYSTEM_ERROR,
        "Error creating a cryptographic hash",
        "u5074w8o5m6zk52f758j",
        undefined
      );
    }
  }

  /**
   * Verifies if the given plain text password matches the hashed password.
   * @param plainText - The plain text password to verify.
   * @param hashedPassword - The hashed password stored in the database.
   * @returns A promise that resolves to true if the passwords match, or false otherwise.
   */
  public static async bcryptVerify(
    plainText: string,
    hashedText: string
  ): Promise<boolean> {
    try {
      const isMatch = await bcrypt.compare(plainText, hashedText);
      return isMatch;
    } catch (error) {
      throw new K2Error(
        ServiceError.SYSTEM_ERROR,
        "Error verifying a cryptographic hash",
        "v9xbp4vp586fg754j55e",
        undefined
      );
    }
  }

  /**
   * Generates a JWT token for a given payload.
   * @param payload - The payload to encode in the JWT.
   * @param expiresIn - The expiration time for the token (e.g., '1h' for 1 hour).
   * @returns A JWT token.
   */
  public static JWT(
    payload: object,
    expiresIn: string = this.jwtExpires
  ): string {
    try {
      const token = jwt.sign(payload, this.jwtSecret, { expiresIn });
      return token;
    } catch (error) {
      throw new K2Error(
        ServiceError.SYSTEM_ERROR,
        "Error generating JWT",
        "1ipqc5cl550259183q06",
        undefined
      );
    }
  }

  /**
   * Verifies a JWT token and decodes the payload if valid.
   * @param token - The JWT token to verify.
   * @returns The decoded payload if the token is valid, or an error if invalid.
   */
  public static JWTVerify(token: string): object | string {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);
      return decoded; // Returns the decoded payload
    } catch (error) {
      throw new K2Error(
        ServiceError.SYSTEM_ERROR,
        "Invalid or expired token",
        "h51mw3h9d22dzz0m6d87",
        undefined
      );
    }
  }
}
