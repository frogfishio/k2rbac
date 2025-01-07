// src/Account.ts

import { BaseDocument, K2DB } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";
import { Ticket } from "./types"; // Import the Ticket type
import debugLib from "debug";
import { K2CreateResponse, K2DeleteResponse } from "./k2types";
import { Auth } from "./auth";
// import { Util } from "../util";

const debug = debugLib("k2:rbac:account");

// Define the structure of an Account document
export interface AccountDocument extends BaseDocument {
  userRoles: { [userId: string]: string[] }; // Mapping of user IDs to their role IDs
}

export class Account {
  private readonly systemAccountName = "system";
  private readonly systemRoleId = "system";

  constructor(private db: K2DB, private ticket: Ticket) {}

  // Create a new account (not related to the hardcoded system account)
  public async create(
    userId: string,
    roles: Array<string>
  ): Promise<K2CreateResponse> {
    Auth.allow(this.ticket, ["system"], "dh1mbjbe3f84gks8fd0r");
    try {
      const newAccount: Partial<AccountDocument> = {
        userRoles: {
          [userId]: roles,
        },
      };

      return await this.db.create("_accounts", userId, newAccount);
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.VALIDATION_ERROR,
        `Failed to create account - ${errorMessage}`,
        "99vi55e253701zw4ypdv"
      );
    }
  }

  public async update(
    accountId: string,
    data: any
  ): Promise<{ updated: number }> {
    Auth.allow(this.ticket, ["system", "admin"], "dbq2y9cpgp4p3rf0pwol");
    const account = await this.get(accountId);
    return await this.db.update("_accounts", account._uuid, data);
  }

  // Retrieve an account by its unique ID
  public async get(accountId: string): Promise<AccountDocument> {
    Auth.allow(this.ticket, ["system", "admin"], "hd879ns6aqd9yxnv7ygx");
    try {
      const result: any = await this.db.get("_accounts", accountId);
      if (!result) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          `Account not found - ${accountId}`,
          "de9741z8avb4ylxtobhs"
        );
      }
      return result as AccountDocument;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `Account not found - ${errorMessage}`,
        "56e586ootqm45jnv6vzl"
      );
    }
  }

  public async delete(accountId: string): Promise<K2DeleteResponse> {
    Auth.allow(this.ticket, ["system", "admin"], "9ru9hqhyry8ue30r8e5n");
    try {
      const account = await this.get(accountId);
      return await this.db.delete("_accounts", account._uuid);
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to remove account - ${errorMessage}`,
        "f6p95a1kht5qztkvef2v"
      );
    }
  }

  public async findOne(query: any): Promise<AccountDocument> {
    Auth.allow(this.ticket, ["system", "admin"], "m9cnhmxkft3rkkasfkgf");
    const account = await this.db.findOne("_accounts", query);

    if (account) {
      return account as AccountDocument;
    } else {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `Account not found`,
        "s6v5wnchZZu5gjqw763x"
      );
    }
  }

  // Find accounts based on given criteria
  public async find(
    criteria: any,
    limit?: number,
    start?: number
  ): Promise<AccountDocument[]> {
    Auth.allow(this.ticket, ["system", "admin"], "wsn8xmm48b1bdvr59v4t");
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
        "w3976sjst487t058575g"
      );
    }
  }
}
