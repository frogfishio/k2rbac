import { BaseDocument, K2DB } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";
import { Ticket } from "./types";
import { K2CreateResponse, K2DeleteResponse } from "./k2types";
import debugLib from "debug";
import { Auth } from "./auth";
import bcrypt from "bcrypt";
const debug = debugLib("k2:rbac:user");

export interface UserDocument extends BaseDocument {}

export class User {
  private static bycriptSaltRounds: number = 10;

  constructor(private db: K2DB, private ticket: Ticket) {}

  public async createUserByEmailAndPassword(
    email: string,
    password: string
  ): Promise<K2CreateResponse> {
    Auth.allow(this.ticket, ["system"], "v00rhnpvfq3c0iftypxs");
    await this.validateEmail(email);
    await this.validatePassword(password);
    const passwordHash = await User.bcrypt(password);

    try {
      return await this.db.create("_users", this.ticket.account, {
        email,
        password: passwordHash,
      });
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Failed to create user",
        "ugfv212d399975i0904l",
        undefined
      );
    }
  }

  public async get(id: string): Promise<UserDocument> {
    try {
      Auth.allow(this.ticket, ["system", "admin"], "uqg1tpsptlm2c4jwj0f7");
      return (await this.db.get("_users", id)) as UserDocument;
    } catch (error) {
      const err: K2Error = error as K2Error;
      if (err.error === ServiceError.FORBIDDEN) {
        // cater for "self" access
        if (this.ticket.user === id) {
          return (await this.db.get("_users", id)) as UserDocument;
        } else {
          throw error;
        }
      } else {
        throw error;
      }
    }
  }

  public async find(
    query: any,
    skip?: number,
    limit?: number
  ): Promise<UserDocument[]> {
    try {
      Auth.allow(this.ticket, ["system", "admin"], "vk0govi50srii8t5g57j");
      return (await this.db.find(
        "_users",
        query,
        skip,
        limit
      )) as UserDocument[];
    } catch (error) {
      const err: K2Error = error as K2Error;
      if (err.error === ServiceError.FORBIDDEN) {
        // cater for "self" access
        query._uuid = this.ticket.user;
        return (await this.db.find(
          "_users",
          query,
          skip,
          limit
        )) as UserDocument[];
      } else {
        throw error;
      }
    }
  }

  public async delete(id: string): Promise<K2DeleteResponse> {
    try {
      Auth.allow(this.ticket, ["system", "admin"], "s32xod35nda11la5ool5");
      return await this.db.delete("_users", id);
    } catch (error) {
      const err: K2Error = error as K2Error;
      if (err.error === ServiceError.FORBIDDEN) {
        // cater for "self" access
        if (this.ticket.user === id) {
          return await this.db.delete("_users", id);
        } else {
          throw error;
        }
      } else {
        throw error;
      }
    }
  }

  public async authenticateByEmailAndPassword(
    email: string,
    password: string
  ): Promise<{ id: string }> {
    const user = (await this.db.findOne("_users", {
      email,
    })) as UserDocument;

    if (!user) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `User ${email} not found`,
        "kae0644rh475d12gacct",
        undefined
      );
    }

    const isValid = await User.bcryptVerify(password, user.password);
    if (!isValid) {
      throw new K2Error(
        ServiceError.AUTH_ERROR,
        "Invalid email or password",
        "04eyjdnj7mwfno5v6xz0",
        undefined
      );
    }

    return { id: user._uuid };
  }

  public async generateOTP(username: string): Promise<string> {
    const user = (await this.db.findOne("_users", {
      username,
    })) as UserDocument;

    if (!user) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `User ${username} not found`,
        "8abc67dknop0981r45jv",
        undefined
      );
    }

    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const timestamp = Date.now();

    // Store OTP and timestamp in the user's record
    await this.db.update("_users", user._uuid, {
      otp,
      otpTimestamp: timestamp,
    });

    return otp;
  }

  public async update(
    id: string,
    data: Partial<UserDocument>
  ): Promise<{ updated: number }> {
    try {
      Auth.allow(this.ticket, ["system", "admin"], "bo64xz0ki7s8r1u85ro4");

      // TODO: Add validation and all the data logic such as password hashing
      // OTP as well. move complexity from handlers to data layer
      return await this.db.update("_users", id, data);
    } catch (error) {
      // allow for self update
      const err: K2Error = error as K2Error;
      if (err.error === ServiceError.FORBIDDEN) {
        if (this.ticket.user === id) {
          return await this.db.update("_users", id, data);
        } else {
          throw error;
        }
      } else {
        throw error;
      }
    }

    // public async updatePasswordByEmail(
    //   email: string,
    //   newPassword: string,
    //   { oldPassword, otp }: { oldPassword?: string; otp?: string }
    // ): Promise<void> {
    //   const user = (await this.db.findOne("_users", {
    //     email,
    //   })) as UserDocument;

    //   if (!user) {
    //     throw new K2Error(
    //       ServiceError.NOT_FOUND,
    //       `User ${email} not found`,
    //       "41f2akd901jsiwkq0kxm",
    //       undefined
    //     );
    //   }

    //   let isAuthenticated = false;

    //   if (oldPassword) {
    //     isAuthenticated = await Secure.bcryptVerify(
    //       oldPassword,
    //       user.passwordHash
    //     );
    //   } else if (otp) {
    //     if (user.otp !== otp) {
    //       isAuthenticated = false;
    //     } else {
    //       isAuthenticated = await this.validateOTP(otp, user.otpTimestamp);
    //     }
    //   }

    //   if (!isAuthenticated) {
    //     throw new K2Error(
    //       ServiceError.AUTH_ERROR,
    //       "Invalid old password or OTP",
    //       "f82m7k9x92kql09ahvzz",
    //       undefined
    //     );
    //   }

    //   await this.validatePassword(newPassword);

    //   const newPasswordHash = await Secure.bcrypt(newPassword);

    //   await this.db.update("_users", user._uuid, {
    //     passwordHash: newPasswordHash,
    //     otp: null, // Clear OTP after use
    //     otpTimestamp: null,
    //   });
  }

  public async count(): Promise<{ count: number }> {
    Auth.allow(this.ticket, ["system", "admin"], "908lywg5p6bz0s2j24j5");
    return this.db.count("_users", {});
  }

  /*********** helpers *************/

  private async validateEmail(email: string) {
    if (!email) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Email is required",
        "jsn7m263148b721db0xg",
        undefined
      );
    }

    const existingUser = await this.db.findOne("_users", { email });
    if (existingUser) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Email is already taken",
        "jsn7m36314jb721db0xg",
        undefined
      );
    }
  }

  private async validatePassword(password: string) {
    if (!password) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Password is required",
        "aaf7m263148b721db0xg",
        undefined
      );
    }

    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (
      password.length < minLength ||
      !hasUpperCase ||
      !hasLowerCase ||
      !hasDigit ||
      !hasSpecialChar
    ) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character",
        "p1jz9xm3vwbyn5k6cfr8",
        undefined
      );
    }
  }

  private async validateOTP(otp: string, timestamp: number): Promise<boolean> {
    if (!otp || !timestamp) {
      return false;
    }

    const otpExpiryTime = 5 * 60 * 1000; // 5 minutes
    const isExpired = Date.now() - timestamp > otpExpiryTime;

    return true;
  }

  /**
   * Hashes a plain text password using bcrypt.
   * @param text - The plain text password to hash.
   * @returns A promise that resolves to the hashed password.
   */
  private static async bcrypt(text: string): Promise<string> {
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
  private static async bcryptVerify(
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
}
