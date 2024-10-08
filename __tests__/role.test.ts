// __tests__/role.test.ts

import { K2Data } from "@frogfish/k2db";
import { K2DB, DatabaseConfig } from "@frogfish/k2db/db";
import { Auth } from "../src/auth";
import { Ticket } from "../src/types";
import { Role, RoleDocument } from "../src/role";
import { K2Error } from "@frogfish/k2error"; // Import error classes

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
  let dataFacade: K2Data; // Variable to hold the K2Data facade
  let roleInstance: Role; // Variable to hold the Role instance

  beforeAll(async () => {
    // Initialize the K2DB instance and establish a connection
    dbInstance = new K2DB(config);
    await dbInstance.init();

    // Instantiate K2Data with K2DB instance and "system" as the owner
    dataFacade = new K2Data(dbInstance, systemTicket.account);

    // Instantiate Role class using K2Data and Ticket
    roleInstance = new Role(dataFacade, systemTicket);
  });

  afterAll(async () => {
    // Clean up the test database and close the connection
    await dbInstance.dropDatabase();
    await dbInstance.release(); // Release the K2DB connection
  });

  describe("create() method", () => {
    it("should create a new role successfully", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      const newRole = await roleInstance.create(roleName, permissions);

      expect(newRole).toBeDefined();
      expect(newRole.name).toBe(roleName);
      expect(newRole.permissions).toEqual(permissions);
    });

    it("should throw an error if role creation fails", async () => {
      jest
        .spyOn(dataFacade, "create")
        .mockRejectedValueOnce(new Error("Failed to create"));

      await expect(roleInstance.create("invalid-role")).rejects.toThrow(
        K2Error
      );

      jest.restoreAllMocks();
    });
  });

  describe("getById() method", () => {
    it("should retrieve a role by its ID", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      // First, create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Then retrieve the role by its ID
      const retrievedRole = await roleInstance.getById(newRole._uuid);

      expect(retrievedRole).toBeDefined();
      expect(retrievedRole?.name).toBe(roleName);
    });

    it("should throw an error if role ID does not exist", async () => {
      await expect(roleInstance.getById("invalid-id")).rejects.toThrow(K2Error);
    });
  });

  describe("getByCode() method", () => {
    it("should retrieve a role by its code", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];
      const code = "admin-code";

      // Create a role with a code
      const newRole = await roleInstance.create(roleName, permissions, code);

      // Retrieve the role by its code
      const retrievedRole = await roleInstance.getByCode(code);

      expect(retrievedRole).toBeDefined();
      expect(retrievedRole?.code).toBe(code);
    });

    it("should throw an error if the role code does not exist", async () => {
      await expect(roleInstance.getByCode("invalid-code")).rejects.toThrow(
        K2Error
      );
    });
  });

  describe("updateRoleName() method", () => {
    it("should update the role name successfully", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Update the role name
      const updated = await roleInstance.updateRoleName(
        newRole._uuid,
        "super-admin"
      );

      expect(updated).toBe(true);

      // Retrieve and verify the updated name
      const updatedRole = await roleInstance.getById(newRole._uuid);
      expect(updatedRole?.name).toBe("super-admin");
    });

    it("should throw an error if role does not exist", async () => {
      await expect(
        roleInstance.updateRoleName("invalid-id", "new-name")
      ).rejects.toThrow(K2Error);
    });
  });

  describe("addPermissions() method", () => {
    it("should add permissions to a role successfully", async () => {
      const roleName = "admin";
      const permissions = ["read"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Add new permissions
      const updated = await roleInstance.addPermissions(newRole._uuid, [
        "write",
        "execute",
      ]);

      expect(updated).toBe(true);

      // Retrieve and verify the updated permissions
      const updatedRole = await roleInstance.getById(newRole._uuid);
      expect(updatedRole?.permissions).toEqual(
        expect.arrayContaining(["read", "write", "execute"])
      );
    });

    it("should throw an error if role does not exist", async () => {
      await expect(
        roleInstance.addPermissions("invalid-id", ["write"])
      ).rejects.toThrow(K2Error);
    });
  });

  describe("removePermissions() method", () => {
    it("should remove permissions from a role successfully", async () => {
      const roleName = "admin";
      const permissions = ["read", "write", "execute"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Remove a permission
      const updated = await roleInstance.removePermissions(newRole._uuid, [
        "write",
      ]);

      expect(updated).toBe(true);

      // Retrieve and verify the updated permissions
      const updatedRole = await roleInstance.getById(newRole._uuid);
      expect(updatedRole?.permissions).not.toContain("write");
    });

    it("should throw an error if role does not exist", async () => {
      await expect(
        roleInstance.removePermissions("invalid-id", ["write"])
      ).rejects.toThrow(K2Error);
    });
  });

  describe("delete() method", () => {
    it("should delete a role successfully", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Delete the role
      const deleted = await roleInstance.delete(newRole._uuid);

      expect(deleted).toBe(true);

      // Verify the role is deleted
      await expect(roleInstance.getById(newRole._uuid)).rejects.toThrow(
        K2Error
      );
    });

    it("should throw an error if role does not exist", async () => {
      await expect(roleInstance.delete("invalid-id")).rejects.toThrow(K2Error);
    });
  });

  describe("hasPermission() method", () => {
    it("should return true if the role has the permission", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Check for a permission
      const hasPermission = await roleInstance.hasPermission(
        newRole._uuid,
        "write"
      );

      expect(hasPermission).toBe(true);
    });

    it("should return false if the role does not have the permission", async () => {
      const roleName = "admin";
      const permissions = ["read"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Check for a permission
      const hasPermission = await roleInstance.hasPermission(
        newRole._uuid,
        "write"
      );

      expect(hasPermission).toBe(false);
    });
  });

  describe("isSystem() method", () => {
    it("should return true if the role is the system role", () => {
      const isSystem = roleInstance.isSystem("system");
      expect(isSystem).toBe(true);
    });

    it("should return false if the role is not the system role", () => {
      const isSystem = roleInstance.isSystem("admin");
      expect(isSystem).toBe(false);
    });
  });
});
