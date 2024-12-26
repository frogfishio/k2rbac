import { BaseDocument, K2DB } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";
import { Ticket } from "./types";
import debugLib from "debug";
import { Secure } from "./secure";
import { K2CreateResponse, K2DeleteResponse } from "./k2types";
const debug = debugLib("k2:rbac:user");

export interface UserDocument extends BaseDocument {
}

export class User {
  constructor(private db: K2DB, private ticket: Ticket) {}

  public async createUser(
    username: string,
    password: string
  ): Promise<K2CreateResponse> {
    await this.validateUsername(username);
    await this.validatePassword(password);
    const passwordHash = await Secure.bcrypt(password);

    try {
      return await this.db.create("_users", this.ticket.account, {
        username,
        passwordHash,
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
    return (await this.db.get("_users", id)) as UserDocument;
  }

  public async delete(id: string): Promise<K2DeleteResponse> {
    return await this.db.delete("_users", id);
  }

  public async authenticate(
    username: string,
    password: string
  ): Promise<UserDocument> {
    const user = (await this.db.findOne("_users", {
      username,
    })) as UserDocument;

    if (!user) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `User ${username} not found`,
        "kae0644rh475d12gacct",
        undefined
      );
    }

    const isValid = await Secure.bcryptVerify(password, user.passwordHash);
    if (!isValid) {
      throw new K2Error(
        ServiceError.AUTH_ERROR,
        "Invalid username or password",
        "04eyjdnj7mwfno5v6xz0",
        undefined
      );
    }

    return user;
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

  public async updatePassword(
    username: string,
    newPassword: string,
    { oldPassword, otp }: { oldPassword?: string; otp?: string }
  ): Promise<void> {
    const user = (await this.db.findOne("_users", {
      username,
    })) as UserDocument;

    if (!user) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `User ${username} not found`,
        "41f2akd901jsiwkq0kxm",
        undefined
      );
    }

    let isAuthenticated = false;

    if (oldPassword) {
      isAuthenticated = await Secure.bcryptVerify(
        oldPassword,
        user.passwordHash
      );
    } else if (otp) {
      if (user.otp !== otp) {
        isAuthenticated = false;
      } else {
        isAuthenticated = await this.validateOTP(otp, user.otpTimestamp);
      }
    }

    if (!isAuthenticated) {
      throw new K2Error(
        ServiceError.AUTH_ERROR,
        "Invalid old password or OTP",
        "f82m7k9x92kql09ahvzz",
        undefined
      );
    }

    await this.validatePassword(newPassword);

    const newPasswordHash = await Secure.bcrypt(newPassword);

    await this.db.update("_users", user._uuid, {
      passwordHash: newPasswordHash,
      otp: null, // Clear OTP after use
      otpTimestamp: null,
    });
  }

  /*********** helpers *************/

  private async validateUsername(username: string) {
    const existingUser = await this.db.findOne("_users", { username });
    if (existingUser) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Username is already taken",
        "jsn7m36314jb721db0xg",
        undefined
      );
    }
  }

  private async validatePassword(password: string) {
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
}
