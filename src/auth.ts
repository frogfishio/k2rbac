// src/Auth.ts

import jwt from "jsonwebtoken";
import { Ticket } from "./types"; // Import Ticket interface
import ms from "ms";
import crypto from "crypto";
import debugLib from "debug";
import { Account, AccountDocument } from "./account"; // Import Account class
import { Role, RoleDocument } from "./role"; // Import Role class
import { K2DB } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";

const debug = debugLib("k2:rbac:auth");

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";
const JWT_EXPIRATION = process.env.JWT_EXPIRATION || "15m";
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || "your_jwt_refresh_secret_key";
const JWT_REFRESH_EXPIRATION = process.env.JWT_REFRESH_EXPIRATION || "7d";
const TICKET_EXPIRATION = process.env.JWT_EXPIRATION || "15m";

const MAX_USER_ACCOUNTS_BUFFER = 1000;

// Parse TICKET_EXPIRATION to milliseconds
const ticketExpirationInMillis = ms(TICKET_EXPIRATION);

export interface TokenPayload {
  userId: string;
  roles: string[]; // Array of role IDs (not codes)
  restrictedMode: boolean;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export class Auth {
  private rolesAPI: Role; // Instance of Role class
  private accountAPI: Account; // Instance of Account class

  private static roles?: { [key: string]: string[] };
  private static userAccounts: { [key: string]: string } = {};
  private static userAccountsBuffer: Array<string> = [];

  constructor(db: K2DB, ticket: Ticket) {
    this.rolesAPI = new Role(db, ticket);
    this.accountAPI = new Account(db, ticket);
  }

  public async getTicket(token: string): Promise<Ticket> {
    let payload;

    if (!token) {
      throw new K2Error(
        ServiceError.INVALID_TOKEN,
        "Token not provided",
        "x34evca67aq8gr3hiu1u"
      );
    }

    try {
      payload = jwt.verify(token, JWT_SECRET) as TokenPayload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new K2Error(
          ServiceError.INVALID_TOKEN,
          "Token expired",
          "aoapi6lrv4m8rti6c7wq"
        );
      }

      throw new K2Error(
        ServiceError.INVALID_TOKEN,
        `Invalid token: ${error}: Token: ${token}`,
        "l2u8lwwbiiam7gfdsw5m"
      );
    }

    const permissions = await this.getRolePermissions(payload.roles);
    const accountId = await this.getUserAccount(payload.userId);

    const ticket: Ticket = {
      user: payload.userId,
      account: accountId,
      permissions,
      restricted: payload.restrictedMode,
      expiresAt: Date.now() + ticketExpirationInMillis,
    };

    return Auth.checksumTicket(ticket);
  }

  /*** PUBLIC STATIC HELPERS ******************************************* */

  public static allow(
    ticket: Ticket,
    permissions: string[],
    trace?: string
  ): boolean {
    if (!ticket || !ticket.permissions) {
      throw new K2Error(
        ServiceError.FORBIDDEN,
        "Permission denied",
        trace || "fdezixsvfrg1xjqal6ar"
      );
    }

    for (const permission of permissions) {
      if (ticket.permissions.includes(permission)) {
        return true;
      }
    }

    throw new K2Error(
      ServiceError.FORBIDDEN,
      `Permission denied: ${JSON.stringify(ticket)}`,
      trace || "09ij3rc687wc0ltqbf6a"
    );
  }

  // Refresh tokens with refreshToken
  public static refreshTokens(refreshToken: string): AuthTokens {
    if (!refreshToken) {
      throw new K2Error(
        ServiceError.INVALID_TOKEN,
        "Refresh token not provided",
        "joyseq1qufiem09stojx"
      );
    }

    const payload = jwt.verify(
      refreshToken,
      JWT_REFRESH_SECRET
    ) as TokenPayload;
    return Auth.generateTokens(payload);
  }

  // Helper function to generate JWT access and refresh tokens
  public static generateTokens(payload: TokenPayload): AuthTokens {
    if (!payload) {
      throw new K2Error(
        ServiceError.INVALID_TOKEN,
        "Token payload not provided",
        "efo0gsdgy9smd3e3xhn1"
      );
    }

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

  public static getSystemTicket(): Ticket {
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
  public static verifyTicket(ticket: Ticket): boolean {
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

  /*** PRIVATE HELPERS ****************************************** */

  // Ticket checksum logic (same as in your original implementation)
  private static checksumTicket(ticket: Ticket): Ticket {
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

  private cacheUserAccount(userId: string, accountId: string) {
    if (Auth.userAccountsBuffer.length >= MAX_USER_ACCOUNTS_BUFFER) {
      delete Auth.userAccounts[Auth.userAccountsBuffer.shift() as string];
    }
    Auth.userAccounts[userId] = accountId;
    Auth.userAccountsBuffer.push(userId);
  }

  private async getUserAccount(userId: string): Promise<string> {
    if (Auth.userAccounts[userId]) {
      return Auth.userAccounts[userId];
    }

    const result = await this.accountAPI.findOne({ _owner: userId });

    if (!result) {
      throw new Error("User account not found");
    }

    this.cacheUserAccount(userId, result._uuid);
    return result._uuid;
  }

  private async cacheRoles() {
    Auth.roles = { system: ["system"], admin: ["admin"], member: ["member"] };
    const result = await this.rolesAPI.find({});
    for (const role of result) {
      Auth.roles[role._uuid] = role.permissions;
    }
  }

  // Helper function to get permissions based on role ID
  private async getRolePermissions(roles: string[]): Promise<string[]> {
    if (!Auth.roles) {
      await this.cacheRoles();
    }

    Auth.roles = Auth.roles || {};

    const map: { [key: string]: boolean } = {};
    for (const role of roles) {
      if (Auth.roles[role]) {
        Auth.roles[role].forEach((permission) => {
          map[permission] = true;
        });
      }
    }

    return Object.keys(map);
  }
}
