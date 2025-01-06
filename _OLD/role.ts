import { BaseDocument, K2DB } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";
import debugLib from "debug";
import { Ticket } from "./types";
import { z } from "zod";
import {
  K2CreateResponse,
  K2DeleteResponse,
  K2UpdateResponse,
} from "./k2types";

const debug = debugLib("k2:rbac:role");

// Define regex for permission format: alphanumeric, lowercase, can contain underscores, but can't start with a number
const permissionRegex = /^[a-z][a-z0-9_]*$/;

// Define the structure of a Role document using Zod for validation
const roleSchema = z.object({
  name: z.string().min(1, { message: "Role name cannot be empty" }),
  code: z.string().optional(),
  permissions: z
    .array(
      z
        .string()
        .min(1, { message: "Permission cannot be empty" })
        .regex(permissionRegex, {
          message:
            "Invalid permission format. Must be lowercase, alphanumeric, and can't start with a number.",
        })
    )
    .nonempty({ message: "Permissions array cannot be empty" })
    .refine((permissions) => new Set(permissions).size === permissions.length, {
      message: "Duplicate permissions are not allowed",
    }),
});

// Define the structure of a Role document (Zod will validate it)
export interface RoleDocument extends BaseDocument {
  name: string;
  code?: string;
  permissions: string[]; // List of permissions (tags)
}

export class Role {
  private readonly systemRoleId = "system";
  private readonly systemPermission = "system";

  constructor(private db: K2DB, private ticket: Ticket) {}

  // Create a new role (not related to the hardcoded system role)
  public async create(
    name: string,
    permissions: string[] = [],
    code?: string
  ): Promise<K2CreateResponse> {
    try {
      const newRole: Partial<RoleDocument> = {
        name,
        permissions,
        code,
      };

      // Validate the role document using Zod before saving
      roleSchema.parse(newRole);

      // Perform the async check for unique code
      if (code) {
        const found = await this.db.findOne("_roles", { code: code });
        if (found) {
          throw new K2Error(
            ServiceError.ALREADY_EXISTS,
            `Role with code "${code}" already exists`,
            "code_uniqueness_error"
          );
        }
      }

      debug(`Creating : ${JSON.stringify(newRole, null, 2)}`);

      return await this.db.create("_roles", this.ticket.account, newRole);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new K2Error(
          ServiceError.VALIDATION_ERROR,
          `Validation failed: ${error.errors
            .map((err) => err.message)
            .join(", ")}`,
          "validation_error"
        );
      }
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to create role - ${
          error instanceof Error ? error.message : error
        }`,
        "ehrkhmaxk92kfyjv7ksl",
        error instanceof Error ? error : undefined
      );
    }
  }

  async get(roleId: string): Promise<RoleDocument> {
    const role: RoleDocument = (await this.db.get(
      "_roles",
      roleId
    )) as RoleDocument;
    return role;
  }

  // Retrieve a role by its unique code (mnemonic), used
  // only during configuration/init and hardcoded situations
  public async getByCode(roleCode: string): Promise<RoleDocument | null> {
    try {
      const role = await this.db.findOne("_roles", { code: roleCode });
      if (!role) {
        throw new K2Error(
          ServiceError.NOT_FOUND,
          `Role ${roleCode} not found`,
          "85okz2s8ctfvxh9i50jm",
          undefined
        );
      }
      return role as RoleDocument;
    } catch (error) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `Role not found - ${error instanceof Error ? error.message : error}`,
        "j88wfv5j7euo1rk91m45",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Update a role's data
  public async update(
    roleId: string,
    data: Partial<RoleDocument>
  ): Promise<K2UpdateResponse> {
    try {
      // Validate the role data using Zod before updating
      roleSchema.partial().parse(data); // Use partial schema for partial updates

      // Check if the code is being updated and if so, ensure it's unique
      if (data.code) {
        const found = await this.db.findOne("_roles", { code: data.code });
        if (found && found._uuid !== roleId) {
          throw new K2Error(
            ServiceError.ALREADY_EXISTS,
            `Role with code "${data.code}" already exists`,
            "code_uniqueness_error"
          );
        }
      }

      return await this.db.update("_roles", roleId, data);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new K2Error(
          ServiceError.VALIDATION_ERROR,
          `Validation failed: ${error.errors
            .map((err) => err.message)
            .join(", ")}`,
          "validation_error"
        );
      }
      throw new K2Error(
        ServiceError.SYSTEM_ERROR,
        `Failed to update role - ${
          error instanceof Error ? error.message : error
        }`,
        "0wmno8pfpzt6z318xvtj",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Delete a role by its ID
  public async delete(roleId: string): Promise<K2DeleteResponse> {
    try {
      return await this.db.delete("_roles", roleId);
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to delete role - ${
          error instanceof Error ? error.message : error
        }`,
        "p4oprd6g3cq798w46qq1",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Find roles based on given criteria
  public async find(
    criteria: any,
    limit?: number,
    skip?: number
  ): Promise<RoleDocument[]> {
    try {
      const params: any = {
        where: criteria,
      };

      if (limit) {
        params.limit = limit;
      }

      if (skip) {
        params.skip = skip;
      }

      return (await this.db.find("_roles", params)) as RoleDocument[];
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to find roles - ${
          error instanceof Error ? error.message : error
        }`,
        "miiwrp553251te51e40p",
        error instanceof Error ? error : undefined
      );
    }
  }
}
