import bcrypt from "bcrypt";
import crypto from "crypto";
import { BaseDocument, K2DB } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";
import { Ticket } from "./types";
import debugLib from "debug";
const debug = debugLib("k2:rbac:user");

// Define the structure of a User document
export interface UserDocument extends BaseDocument {
  identifiedBy: string; // Store the primary authentication credential
  method: string; // The method used to process the `identifiedBy` (e.g., bcrypt)
  identities: Identity[]; // Array of identities (e.g., email, username)
  restrictedMode: boolean; // Flag for restricted mode
  otp?: string; // Store OTP temporarily
  otpExpiresAt?: number; // Store OTP expiration timestamp (UTC)
}

export interface Identity {
  type: string; // E.g., "email", "username"
  value: string; // The actual identifier value
}

// User-related operations
export class User {
  constructor(private db: K2DB, private ticket: Ticket) {}

  // Create a new user with given authentication method and identities
  public async createUser(
    identifiedBy: string,
    method: string,
    identities: Identity[] = []
  ): Promise<UserDocument> {
    try {
      if (!identifiedBy || !method) {
        throw new K2Error(
          ServiceError.VALIDATION_ERROR,
          "identifiedBy and method are required for creating a user.",
          "user_create_validation"
        );
      }

      // Process the identifiedBy value (e.g., hash the password if bcrypt is used)
      const processedIdentifiedBy = await this.storeAuthValue(
        identifiedBy,
        method
      );

      // Create the new user object
      const newUser: Partial<UserDocument> = {
        identifiedBy: processedIdentifiedBy,
        method,
        identities,
        restrictedMode: false, // Default to unrestricted mode
      };

      // Store user in the database
      const result = await this.db.create(
        "_users",
        this.ticket.account,
        newUser
      );

      const createdUser = await this.db.findOne("_users", { _uuid: result.id });

      return createdUser as UserDocument;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to create user - ${
          error instanceof Error ? error.message : error
        }`,
        "user_create_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Retrieve a user by their unique ID
  public async getById(userId: string): Promise<UserDocument | null> {
    try {
      const user = await this.db.get("_users", userId);
      return user as UserDocument;
    } catch (error) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `User not found - ${error instanceof Error ? error.message : error}`,
        "user_get_by_id",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Retrieve a user by an identity (e.g., email, username)
  public async getByIdentity(
    type: string,
    value: string
  ): Promise<UserDocument | null> {
    try {
      // Find user by identity type and value
      const user = await this.db.findOne("_users", {
        "identities.type": type,
        "identities.value": value,
      });
      if (!user) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          `User not found by identity - ${type}: ${value}`,
          "user_get_by_identity_empty",
          undefined
        );
      }
      return user as UserDocument;
    } catch (error) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `User not found by identity - ${type}: ${value}`,
        "user_get_by_identity",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Find users based on given criteria
  public async find(
    criteria: any,
    limit?: number,
    start?: number
  ): Promise<UserDocument[]> {
    try {
      const params: any = {
        where: criteria,
      };

      if (limit) {
        params.limit = limit;
      }

      if (start) {
        params.skip = start;
      }

      return (await this.db.find("_users", params)) as UserDocument[];
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to find users - ${
          error instanceof Error ? error.message : error
        }`,
        "user_find_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Authenticate a user with identifiedBy value (e.g., password) and method
  public async authenticate(
    identifiedBy: string,
    method: string,
    userId: string
  ): Promise<boolean> {
    try {
      // Retrieve the user by ID
      const user = await this.getById(userId);
      if (!user)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "User not found",
          "user_auth_user_not_found"
        );

      // Validate the provided identifiedBy value against the stored one
      const isValid = await this.verifyAuthValue(
        identifiedBy,
        user.identifiedBy,
        method
      );

      return isValid;
    } catch (error) {
      throw new K2Error(
        ServiceError.AUTH_ERROR,
        `Authentication failed - ${
          error instanceof Error ? error.message : error
        }`,
        "user_authenticate_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Process the authentication value based on the method (e.g., hash a password)
  private async storeAuthValue(value: string, method: string): Promise<string> {
    try {
      switch (method) {
        case "bcrypt":
          const saltRounds = 10;
          return await bcrypt.hash(value, saltRounds);
        // Add more cases as needed for other authentication methods
        default:
          throw new K2Error(
            ServiceError.INVALID_REQUEST,
            `Unsupported authentication method: ${method}`,
            "user_store_auth_value_invalid_method"
          );
      }
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to store authentication value - ${
          error instanceof Error ? error.message : error
        }`,
        "user_store_auth_value_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Validate the provided value against the stored value based on the method
  private async verifyAuthValue(
    providedValue: string,
    storedValue: string,
    method: string
  ): Promise<boolean> {
    try {
      switch (method) {
        case "bcrypt":
          return await bcrypt.compare(providedValue, storedValue);
        // Add more cases as needed for other authentication methods
        default:
          throw new K2Error(
            ServiceError.INVALID_REQUEST,
            `Unsupported authentication method: ${method}`,
            "user_verify_auth_value_invalid_method"
          );
      }
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to verify authentication value - ${
          error instanceof Error ? error.message : error
        }`,
        "user_verify_auth_value_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Generate and store OTP for a user
  public async createOtp(userId: string): Promise<string> {
    try {
      const user = await this.getById(userId);
      if (!user)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "User not found",
          "user_create_otp_user_not_found"
        );

      // Generate a 6-digit OTP and set expiration (e.g., 5 minutes from now)
      const otp = crypto.randomBytes(3).toString("hex");
      const otpExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes from now

      // Store the OTP and its expiration time
      user.otp = otp;
      user.otpExpiresAt = otpExpiresAt;

      await this.db.update("_users", userId, user);

      return otp;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to create OTP - ${
          error instanceof Error ? error.message : error
        }`,
        "user_create_otp_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Check if user is in restricted mode
  public async isRestricted(userId: string): Promise<boolean> {
    try {
      const user = await this.getById(userId);
      if (!user)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "User not found",
          "user_is_restricted_user_not_found"
        );

      return user.restrictedMode;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to check restricted mode - ${
          error instanceof Error ? error.message : error
        }`,
        "user_is_restricted_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Set restricted mode for a user
  public async setRestrictedMode(
    userId: string,
    status: boolean
  ): Promise<boolean> {
    try {
      const user = await this.getById(userId);
      if (!user) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "User not found",
          "user_set_restricted_mode_user_not_found"
        );
      }

      user.restrictedMode = status;
      await this.db.update("_users", userId, user);
      return true;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to set restricted mode to ${status} - ${
          error instanceof Error ? error.message : error
        }`,
        "user_set_restricted_mode_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Clear OTP after verification (to be called by external service after validation)
  public async clearOtp(userId: string): Promise<boolean> {
    try {
      const user = await this.getById(userId);
      if (!user)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "User not found",
          "user_clear_otp_user_not_found"
        );

      delete user.otp;
      delete user.otpExpiresAt;
      // user.otp = undefined;
      // user.otpExpiresAt = undefined;

      console.log(`>>>>>>>>>>>>> ${JSON.stringify(user)}`);

      await this.db.update("_users", userId, user, true);
      return true;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to clear OTP - ${
          error instanceof Error ? error.message : error
        }`,
        "user_clear_otp_error",
        error instanceof Error ? error : undefined
      );
    }
  }
}
