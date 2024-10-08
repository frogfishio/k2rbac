// src/Role.ts

import { K2Data } from "@frogfish/k2db";
import { BaseDocument } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";
import debugLib from "debug";
import { Ticket } from "./types";
const debug = debugLib("k2:rbac:role");

// Define the structure of a Role document
export interface RoleDocument extends BaseDocument {
  name: string;
  code?: string;
  permissions: string[]; // List of permissions (tags)
}

export class Role {
  private readonly systemRoleId = "system";
  private readonly systemPermission = "system";

  constructor(private db: K2Data, private ticket: Ticket) {}

  // Create a new role (not related to the hardcoded system role)
  public async create(
    name: string,
    permissions: string[] = [],
    code?: string
  ): Promise<RoleDocument> {
    try {
      const newRole: Partial<RoleDocument> = {
        name,
        permissions,
      };

      if (code) {
        // TODO: check for code uniqueness
        newRole.code = code;
      }

      debug(`Creating : ${JSON.stringify(newRole, null, 2)}`);

      const result = await this.db.create("_roles", newRole);
      const role = await this.db.findOne("_roles", { _uuid: result.id });
      return role as RoleDocument;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to create role - ${
          error instanceof Error ? error.message : error
        }`,
        "role_create_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Retrieve a role by its unique ID
  public async getById(roleId: string): Promise<RoleDocument | null> {
    try {
      const role = await this.db.get("_roles", roleId);
      return role as RoleDocument;
    } catch (error) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `Role not found - ${error instanceof Error ? error.message : error}`,
        "role_get_by_id_error",
        error instanceof Error ? error : undefined
      );
    }
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
          "role_get_by_code_error_nil",
          undefined
        );
      }
      return role as RoleDocument;
    } catch (error) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `Role not found - ${error instanceof Error ? error.message : error}`,
        "role_get_by_code_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Update a role's name
  public async updateRoleName(
    roleId: string,
    newName: string
  ): Promise<boolean> {
    try {
      const role = await this.getById(roleId);
      if (!role)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Role not found",
          "role_update_name_not_found"
        );

      role.name = newName;
      await this.db.update("_roles", roleId, role);
      return true;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to update role name - ${
          error instanceof Error ? error.message : error
        }`,
        "role_update_name_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Add permissions to a role
  public async addPermissions(
    roleId: string,
    permissions: string[]
  ): Promise<boolean> {
    try {
      const role = await this.getById(roleId);
      if (!role)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Role not found",
          "role_add_permissions_not_found"
        );

      // Avoid duplicates by adding only unique permissions
      role.permissions = Array.from(
        new Set([...role.permissions, ...permissions])
      );
      await this.db.update("_roles", roleId, role);
      return true;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to add permissions to role - ${
          error instanceof Error ? error.message : error
        }`,
        "role_add_permissions_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Remove permissions from a role
  public async removePermissions(
    roleId: string,
    permissionsToRemove: string[]
  ): Promise<boolean> {
    try {
      const role = await this.getById(roleId);
      if (!role)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Role not found",
          "role_remove_permissions_not_found"
        );

      role.permissions = role.permissions.filter(
        (permission) => !permissionsToRemove.includes(permission)
      );
      await this.db.update("_roles", roleId, role);
      return true;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to remove permissions from role - ${
          error instanceof Error ? error.message : error
        }`,
        "role_remove_permissions_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Delete a role by its ID
  public async delete(roleId: string): Promise<boolean> {
    try {
      const role = await this.getById(roleId);
      if (!role)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Role not found",
          "role_delete_not_found"
        );

      await this.db.delete("_roles", roleId);
      return true;
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to delete role - ${
          error instanceof Error ? error.message : error
        }`,
        "role_delete_error",
        error instanceof Error ? error : undefined
      );
    }
  }

  // Check if a given role is the system role
  public isSystem(roleId: string): boolean {
    return roleId === this.systemRoleId;
  }

  // Check if a role has a specific permission
  public async hasPermission(
    roleId: string,
    permission: string
  ): Promise<boolean> {
    try {
      const role = await this.getById(roleId);
      if (!role)
        throw new K2Error(
          ServiceError.NOT_FOUND,
          "Role not found",
          "role_has_permission_not_found"
        );
      return role.permissions.includes(permission);
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        `Failed to check role permission - ${
          error instanceof Error ? error.message : error
        }`,
        "role_has_permission_error",
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
        "role_find_error",
        error instanceof Error ? error : undefined
      );
    }
  }
}
