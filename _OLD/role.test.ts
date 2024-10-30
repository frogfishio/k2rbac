// role.test.ts

import { K2DB, DatabaseConfig } from "@frogfish/k2db/db";
import { Auth } from "../src/auth";
import { Ticket } from "../src/types";
import { Role, RoleDocument } from "../src/role";
import { K2Error, ServiceError } from "@frogfish/k2error";
import {
  K2CreateResponse,
  K2UpdateResponse,
  K2DeleteResponse,
} from "../src/k2types";

describe("Role Class", () => {
  const dbName = "test"; // Define the test database name

  // Define a minimal database configuration
  const config: DatabaseConfig = {
    name: dbName,
    hosts: [
      {
        host: "localhost",
        port: 27017, // Default MongoDB port
      },
    ],
  };

  const systemTicket: Ticket = Auth.getSystemTicket(); // Authorization ticket
  let dbInstance: K2DB; // Variable to hold the K2DB instance
  let roleInstance: Role; // Variable to hold the Role instance

  beforeAll(async () => {
    // Initialize the K2DB instance and establish a connection
    dbInstance = new K2DB(config);
    await dbInstance.init();

    // Instantiate Role class using K2DB and Ticket
    roleInstance = new Role(dbInstance, systemTicket);
  });

  afterAll(async () => {
    // Clean up the test database and close the connection
    await dbInstance.dropDatabase();
    await dbInstance.close();
  });

  describe("create() method", () => {
    it("should create a new role successfully", async () => {
      // Create a new role
      const roleName = "admin";
      const permissions = ["read", "write"];

      const createResponse: K2CreateResponse = await roleInstance.create(
        roleName,
        permissions
      );

      // Validate that the role is created successfully
      expect(createResponse).toBeDefined();
      expect(createResponse).toHaveProperty("id");

      // Retrieve the created role using the id
      const createdRole = await roleInstance.get(createResponse.id);

      expect(createdRole).toBeDefined();
      expect(createdRole.name).toBe(roleName);
      expect(createdRole.permissions).toEqual(permissions);
    });

    it("should throw a validation error if permissions are invalid", async () => {
      const roleName = "invalidRole";
      const invalidPermissions = ["Invalid Permission"];

      await expect(
        roleInstance.create(roleName, invalidPermissions)
      ).rejects.toThrow(K2Error);

      await expect(
        roleInstance.create(roleName, invalidPermissions)
      ).rejects.toHaveProperty("serviceError", ServiceError.VALIDATION_ERROR);
    });

    it("should throw an error if role creation fails due to code uniqueness", async () => {
      // First, create a role with a specific code
      const roleName = "uniqueRole";
      const permissions = ["read"];
      const code = "unique_code";

      await roleInstance.create(roleName, permissions, code);

      // Attempt to create another role with the same code
      await expect(
        roleInstance.create("anotherRole", ["write"], code)
      ).rejects.toThrow(K2Error);

      await expect(
        roleInstance.create("anotherRole", ["write"], code)
      ).rejects.toHaveProperty("serviceError", ServiceError.ALREADY_EXISTS);
    });
  });

  describe("get() method", () => {
    it("should retrieve an existing role by ID", async () => {
      // Create a new role first
      const roleName = "viewer";
      const permissions = ["read"];
      const createResponse = await roleInstance.create(roleName, permissions);

      // Now retrieve the role
      const retrievedRole = await roleInstance.get(createResponse.id);

      expect(retrievedRole).toBeDefined();
      expect(retrievedRole.name).toBe(roleName);
      expect(retrievedRole.permissions).toEqual(permissions);
    });

    it("should throw an error when trying to retrieve a non-existent role", async () => {
      const invalidRoleId = "nonexistentid";

      await expect(roleInstance.get(invalidRoleId)).rejects.toThrow(K2Error);
      await expect(roleInstance.get(invalidRoleId)).rejects.toHaveProperty(
        "serviceError",
        ServiceError.NOT_FOUND
      );
    });
  });

  describe("update() method", () => {
    it("should update an existing role successfully", async () => {
      // Create a new role first
      const roleName = "editor";
      const permissions = ["read"];
      const createResponse = await roleInstance.create(roleName, permissions);

      // Update the role's permissions
      const updatedData: Partial<RoleDocument> = {
        permissions: ["read", "write"],
      };

      const updateResponse: K2UpdateResponse = await roleInstance.update(
        createResponse.id,
        updatedData
      );

      expect(updateResponse).toBeDefined();
      expect(updateResponse).toHaveProperty("updated", 1);

      // Retrieve the updated role
      const updatedRole = await roleInstance.get(createResponse.id);

      expect(updatedRole.permissions).toEqual(updatedData.permissions);
    });

    it("should throw a validation error when updating with invalid data", async () => {
      // Create a new role first
      const roleName = "testRole";
      const permissions = ["read"];
      const createResponse = await roleInstance.create(roleName, permissions);

      // Attempt to update with invalid permissions
      const invalidData: Partial<RoleDocument> = {
        permissions: [""], // Empty permission
      };

      await expect(
        roleInstance.update(createResponse.id, invalidData)
      ).rejects.toThrow(K2Error);

      await expect(
        roleInstance.update(createResponse.id, invalidData)
      ).rejects.toHaveProperty("serviceError", ServiceError.VALIDATION_ERROR);
    });

    it("should throw an error when updating a role with a duplicate code", async () => {
      // Create two roles
      const roleName1 = "roleOne";
      const roleName2 = "roleTwo";
      const code1 = "code_one";
      const code2 = "code_two";
      const permissions = ["read"];

      const createResponse1 = await roleInstance.create(
        roleName1,
        permissions,
        code1
      );
      const createResponse2 = await roleInstance.create(
        roleName2,
        permissions,
        code2
      );

      // Attempt to update roleTwo's code to code_one (duplicate)
      const duplicateCodeData: Partial<RoleDocument> = {
        code: code1,
      };

      await expect(
        roleInstance.update(createResponse2.id, duplicateCodeData)
      ).rejects.toThrow(K2Error);

      await expect(
        roleInstance.update(createResponse2.id, duplicateCodeData)
      ).rejects.toHaveProperty("serviceError", ServiceError.ALREADY_EXISTS);
    });
  });

  describe("delete() method", () => {
    it("should delete an existing role successfully", async () => {
      // Create a new role first
      const roleName = "tempRole";
      const permissions = ["read"];
      const createResponse = await roleInstance.create(roleName, permissions);

      // Delete the role
      const deleteResponse: K2DeleteResponse = await roleInstance.delete(
        createResponse.id
      );

      expect(deleteResponse).toBeDefined();
      expect(deleteResponse).toHaveProperty("deleted", 1);

      // Try to get the deleted role
      await expect(roleInstance.get(createResponse.id)).rejects.toThrow(
        K2Error
      );
      await expect(roleInstance.get(createResponse.id)).rejects.toHaveProperty(
        "serviceError",
        ServiceError.NOT_FOUND
      );
    });

    it("should throw an error when deleting a non-existent role", async () => {
      const invalidRoleId = "nonexistentid";

      await expect(roleInstance.delete(invalidRoleId)).rejects.toThrow(K2Error);
      await expect(roleInstance.delete(invalidRoleId)).rejects.toHaveProperty(
        "serviceError",
        ServiceError.NOT_FOUND
      );
    });
  });

  describe("find() method", () => {
    it("should find roles based on criteria", async () => {
      // Create multiple roles
      await roleInstance.create("roleA", ["read"]);
      await roleInstance.create("roleB", ["write"]);
      await roleInstance.create("roleC", ["read", "write"]);

      // Find roles with 'read' permission
      const rolesWithRead = await roleInstance.find({
        permissions: "read",
      });

      expect(rolesWithRead.length).toBeGreaterThanOrEqual(2);

      // Find roles with name 'roleB'
      const rolesNamedB = await roleInstance.find({
        name: "roleB",
      });

      expect(rolesNamedB.length).toBe(1);
      expect(rolesNamedB[0].name).toBe("roleB");
    });

    it("should return an empty array when no roles match the criteria", async () => {
      const roles = await roleInstance.find({
        name: "nonexistentRole",
      });

      expect(roles).toBeDefined();
      expect(roles.length).toBe(0);
    });
  });

  describe("getByCode() method", () => {
    it("should retrieve a role by its code", async () => {
      // Create a role with a specific code
      const roleName = "specialRole";
      const permissions = ["special"];
      const code = "special_code";

      await roleInstance.create(roleName, permissions, code);

      // Retrieve the role by code
      const roleByCode = await roleInstance.getByCode(code);

      expect(roleByCode).toBeDefined();
      if (roleByCode) {
        expect(roleByCode.name).toBe(roleName);
        expect(roleByCode.code).toBe(code);
      }
    });

    it("should throw an error when role with given code does not exist", async () => {
      const invalidCode = "nonexistent_code";

      await expect(roleInstance.getByCode(invalidCode)).rejects.toThrow(
        K2Error
      );
      await expect(roleInstance.getByCode(invalidCode)).rejects.toHaveProperty(
        "serviceError",
        ServiceError.NOT_FOUND
      );
    });
  });
});
