// src/Account.ts

import { BaseDocument, K2DB } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";

import { checkPermission } from "./util"; // Importing the permission check utility function
import { Ticket } from "./types"; // Import the Ticket type
// import { Auth } from "./auth";

import debugLib from "debug";
const debug = debugLib("k2:rbac:account");

// Define the structure of an Account document
export interface AccountDocument extends BaseDocument {
  userRoles: { [userId: string]: string[] }; // Mapping of user IDs to their role IDs
}

export class Account {
  private readonly systemAccountName = "system";
  private readonly systemRoleId = "system";
  // private ticket: Ticket;

  constructor(private db: K2DB, private ticket: Ticket) {
    // if (!Auth.verifyTicket(ticket)) {
    //   this.ticket = Auth.getInvalidTicket();
    // } else {
    //   this.ticket = ticket;
    // }
  }

  // Create a new account (not related to the hardcoded system account)
  public async create(
    userId: string,
    roles: Array<string>
  ): Promise<AccountDocument> {
    //checkPermission(this.ticket, "account_create"); // Permission check before action
    try {
      const newAccount: Partial<AccountDocument> = {
        userRoles: {
          [userId]: roles,
        },
      };

      const result = await this.db.create(
        "_accounts",
        this.ticket.account,
        newAccount
      );

      debug(`>>>> ${JSON.stringify(result)}`);
      const rac = await this.db.get("_accounts", result.id);
      return rac as AccountDocument;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.VALIDATION_ERROR,
        `Failed to create account - ${errorMessage}`,
        "acc_create"
      );
    }
  }

  // Retrieve an account by its unique ID
  public async getById(accountId: string): Promise<AccountDocument | null> {
    //checkPermission(this.ticket, "account_read"); // Permission check before action
    try {
      const result: any = await this.db.get("_accounts", accountId);
      return result as AccountDocument;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `Account not found - ${errorMessage}`,
        "acc_get_by_id"
      );
    }
  }

  public async removeAccount(accountId: string): Promise<{ deleted: number }> {
    // Check permission before performing the delete operation
    //checkPermission(this.ticket, "account_delete");

    try {
      return await this.db.delete("_accounts", accountId);
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to remove account - ${errorMessage}`,
        "acc_remove"
      );
    }
  }

  // Add a user to an account with specific roles
  public async addUser(
    accountId: string,
    userId: string,
    roleIds: string[]
  ): Promise<boolean> {
    //checkPermission(this.ticket, "account_add_user"); // Permission check before action
    try {
      const account = await this.getById(accountId);
      if (!account) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Account not found",
          "acc_add_user_not_found"
        );
      }

      account.userRoles[userId] = roleIds;
      await this.db.update("_accounts", accountId, account);
      return true;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to add user to account - ${errorMessage}`,
        "acc_add_user"
      );
    }
  }

  // Remove a user from an account
  public async removeUser(accountId: string, userId: string): Promise<boolean> {
    //checkPermission(this.ticket, "account_remove_user"); // Permission check before action
    try {
      const account = await this.getById(accountId);
      if (!account) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Account not found",
          "acc_remove_user_not_found"
        );
      }

      delete account.userRoles[userId];
      await this.db.update("_accounts", accountId, account);
      return true;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to remove user from account - ${errorMessage}`,
        "acc_remove_user"
      );
    }
  }

  // Add roles to a user within an account
  public async addRolesToUser(
    accountId: string,
    userId: string,
    roleIds: string[]
  ): Promise<boolean> {
    //checkPermission(this.ticket, "account_add_roles"); // Permission check before action
    try {
      const account = await this.getById(accountId);
      if (!account) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Account not found",
          "acc_add_roles_to_user_not_found"
        );
      }

      if (!account.userRoles[userId]) {
        account.userRoles[userId] = [];
      }

      // Merge unique roles
      account.userRoles[userId] = Array.from(
        new Set([...account.userRoles[userId], ...roleIds])
      );
      await this.db.update("_accounts", accountId, account);
      return true;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to add roles to user - ${errorMessage}`,
        "acc_add_roles_to_user"
      );
    }
  }

  // Remove roles from a user within an account
  public async removeRolesFromUser(
    accountId: string,
    userId: string,
    roleIdsToRemove: string[]
  ): Promise<boolean> {
    //checkPermission(this.ticket, "account_remove_roles"); // Permission check before action
    try {
      const account = await this.getById(accountId);
      if (!account) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Account not found",
          "acc_remove_roles_from_user_not_found"
        );
      }

      if (!account.userRoles[userId]) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "User not found in account",
          "acc_remove_roles_from_user_user_not_found"
        );
      }

      // Remove specified roles
      account.userRoles[userId] = account.userRoles[userId].filter(
        (roleId) => !roleIdsToRemove.includes(roleId)
      );

      // If user has no roles left, remove them from the account
      if (account.userRoles[userId].length === 0) {
        delete account.userRoles[userId];
      }

      await this.db.update("_accounts", accountId, account);
      return true;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to remove roles from user - ${errorMessage}`,
        "acc_remove_roles_from_user"
      );
    }
  }

  // Check if a given user and role is the system account
  public isSystem(userId: string, roleId: string): boolean {
    return userId === this.systemRoleId && roleId === this.systemRoleId;
  }

  // Find accounts based on given criteria
  public async find(
    criteria: any,
    limit?: number,
    start?: number
  ): Promise<AccountDocument[]> {
    //checkPermission(this.ticket, "account_read"); // Permission check before action
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

      return (await this.db.find("_accounts", params)) as AccountDocument[];
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to find accounts - ${errorMessage}`,
        "acc_find"
      );
    }
  }
}
