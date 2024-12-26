// src/Auth.ts

import jwt from "jsonwebtoken";
import { Ticket } from "./types"; // Import Ticket interface
import ms from "ms";
import crypto from "crypto";
import debugLib from "debug";
import { Account, AccountDocument } from "./account"; // Import Account class
import { Role, RoleDocument } from "./role"; // Import Role class
import { K2DB } from "@frogfish/k2db/db";

const debug = debugLib("k2:rbac:auth");

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";
const JWT_EXPIRATION = process.env.JWT_EXPIRATION || "15m";
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || "your_jwt_refresh_secret_key";
const JWT_REFRESH_EXPIRATION = process.env.JWT_REFRESH_EXPIRATION || "7d";
const TICKET_EXPIRATION = process.env.JWT_EXPIRATION || "15m";

// Parse TICKET_EXPIRATION to milliseconds
const ticketExpirationInMillis = ms(TICKET_EXPIRATION);

interface TokenPayload {
  userId: string;
  roles: string[]; // Array of role IDs (not codes)
  restrictedMode: boolean;
}

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export class Auth {
  private db: K2DB; // K2Data for database access
  private account: Account; // Instance of Account class
  private role: Role; // Instance of Role class

  constructor(db: K2DB, ticket: Ticket) {
    this.db = db;
    this.account = new Account(this.db, ticket);
    this.role = new Role(this.db, ticket);
  }

  // // Authenticate a user by identity and password/method
  // public async authenticate(
  //   identityType: string, // e.g., "email" or "username"
  //   identityValue: string,
  //   identifiedBy: string, // e.g., password
  //   method: string // e.g., "bcrypt"
  // ): Promise<AuthTokens | null> {
  //   const user = await this.getUserByIdentity(identityType, identityValue);

  //   if (!user) {
  //     throw new Error("Invalid credentials");
  //   }

  //   // Authenticate the user using the provided method (e.g., bcrypt)
  //   const isValid = await user.authenticate(identifiedBy, method, user._uuid);

  //   if (!isValid) {
  //     throw new Error("Invalid credentials");
  //   }

  //   // If accountId is specified, verify that the user belongs to the account
  //   if (accountId) {
  //     const account = await this.account.getById(accountId);
  //     if (!account || !account.userRoles[user._uuid]) {
  //       throw new Error("User does not belong to the specified account");
  //     }
  //   } else {
  //     // If no accountId is specified, retrieve all accounts the user belongs to
  //     // For simplicity, assume a user belongs to a single account
  //     // Modify as needed to support multiple accounts per user
  //     const accounts = await this.getAccountsForUser(user._uuid);
  //     if (accounts.length === 0) {
  //       throw new Error("User does not belong to any account");
  //     }
  //     accountId = accounts[0]._uuid; // Select the first account
  //   }

  //   // Retrieve roles for the user within the account
  //   const roles = await this.account.getUserRoles(accountId, user._uuid);

  //   // Aggregate permissions from roles
  //   const permissions = await this.getPermissionsForRoles(roles);

  //   // After successful authentication, create a JWT payload
  //   const payload: TokenPayload = {
  //     userId: user._uuid,
  //     accountId,
  //     roles,
  //     restrictedMode: user.restrictedMode,
  //   };

  //   return this.generateTokens(payload);
  // }

  // // Helper function to retrieve user by identity
  // private async getUserByIdentity(
  //   identityType: string,
  //   identityValue: string
  // ): Promise<User | null> {
  //   const userClass = new User(this.db, Auth.getSystemTicket());
  //   const user = await userClass.getByIdentity(identityType, identityValue);
  //   return user;
  // }

  // Helper function to generate JWT access and refresh tokens
  private generateTokens(payload: TokenPayload): AuthTokens {
    const accessToken = jwt.sign(payload, JWT_SECRET, {
      expiresIn: JWT_EXPIRATION,
    });
    const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, {
      expiresIn: JWT_REFRESH_EXPIRATION,
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  // // Inflate JWT into a Ticket (used for authorization in backend)
  // public async validateToken(token: string): Promise<Ticket | null> {
  //   try {
  //     const payload = jwt.verify(token, JWT_SECRET) as TokenPayload;
  //     const permissions = await this.getPermissionsForRoles(payload.roles);

  //     const ticket: Ticket = {
  //       user: payload.userId,
  //       account: payload.accountId,
  //       permissions,
  //       restricted: payload.restrictedMode,
  //       expiresAt: Date.now() + ticketExpirationInMillis,
  //     };

  //     return Auth.checksumTicket(ticket);
  //   } catch (err) {
  //     debug(`Token validation failed: ${err}`);
  //     return null; // Token validation failed
  //   }
  // }

  // // Helper function to get accounts a user belongs to
  // private async getAccountsForUser(userId: string): Promise<AccountDocument[]> {
  //   try {
  //     const accounts = await this.db.find("_accounts", {
  //       where: {
  //         [`userRoles.${userId}`]: { $exists: true },
  //       },
  //     });
  //     return accounts as AccountDocument[];
  //   } catch (error) {
  //     debug(`Failed to retrieve accounts for user ${userId}: ${error}`);
  //     throw new K2Error(
  //       ServiceError.SERVICE_ERROR,
  //       `Failed to retrieve accounts for user - ${
  //         error instanceof Error ? error.message : "Unknown error"
  //       }`,
  //       "auth_get_accounts_for_user_error",
  //       error instanceof Error ? error : undefined
  //     );
  //   }
  // }

  // Helper function to get permissions based on role IDs
  private async getPermissionsForRoles(roles: string[]): Promise<string[]> {
    const permissionsSet = new Set<string>();

    for (const roleId of roles) {
      const roleDoc: RoleDocument | null = await this.role.get(roleId);
      if (roleDoc) {
        roleDoc.permissions.forEach((permission) =>
          permissionsSet.add(permission)
        );
      } else {
        debug(`Role not found: ${roleId}`);
      }
    }

    return Array.from(permissionsSet);
  }

  // // Refresh tokens with refreshToken
  // public async refreshTokens(refreshToken: string): Promise<AuthTokens | null> {
  //   try {
  //     const payload = jwt.verify(
  //       refreshToken,
  //       JWT_REFRESH_SECRET
  //     ) as TokenPayload;
  //     return this.generateTokens({
  //       userId: payload.userId,
  //       accountId: payload.accountId,
  //       roles: payload.roles,
  //       restrictedMode: payload.restrictedMode,
  //     });
  //   } catch (err) {
  //     debug(`Token refresh failed: ${err}`);
  //     return null; // Token refresh failed
  //   }
  // }

  // Ticket checksum logic (same as in your original implementation)
  static checksumTicket(ticket: Ticket): Ticket {
    const data =
      ticket.user +
      ticket.account +
      JSON.stringify(ticket.permissions) +
      ticket.restricted.toString() +
      ticket.expiresAt.toString();
    const hash = crypto.createHash("sha256").update(data).digest("hex");
    ticket.checksum = hash;
    return ticket;
  }

  static getSystemTicket(): Ticket {
    const expiresAt = Date.now() + ticketExpirationInMillis;
    return Auth.checksumTicket({
      user: "system",
      account: "system",
      permissions: ["system"],
      restricted: false,
      expiresAt,
    });
  }

  // Verify ticket utility
  static verifyTicket(ticket: Ticket): boolean {
    if (!ticket || !ticket.checksum) return false;
    const computedHash = crypto
      .createHash("sha256")
      .update(
        ticket.user +
          ticket.account +
          JSON.stringify(ticket.permissions) +
          ticket.restricted.toString() +
          ticket.expiresAt.toString()
      )
      .digest("hex");
    return computedHash === ticket.checksum;
  }

  // Get an invalid ticket
  static getInvalidTicket(): Ticket {
    return {
      user: "invalid",
      account: "invalid",
      permissions: [],
      restricted: true,
      expiresAt: Date.now(),
      checksum: "",
    };
  }
}
