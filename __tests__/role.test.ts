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
  let roleInstance: Role; // Variable to hold the Role instance

  beforeAll(async () => {
    // Initialize the K2DB instance and establish a connection
    dbInstance = new K2DB(config);
    await dbInstance.init();

    // Instantiate Role class using K2Data and Ticket
    roleInstance = new Role(dbInstance, systemTicket);
  });

  afterAll(async () => {
    // Clean up the test database and close the connection
    await dbInstance.dropDatabase();
    await dbInstance.release(); // Release the K2DB connection
  });

  beforeEach(async () => {
    // Optionally drop the entire roles collection or delete specific roles by code
    await dbInstance.deleteAll("_roles", {
      code: { $in: ["admin_code", "user_code"] },
    });
  });

  describe("create() method", () => {
    it("should create a new role successfully", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];
      const code = "admin_code";

      const newRole = await roleInstance.create(roleName, permissions, code);

      expect(newRole).toBeDefined();
      expect(newRole.name).toBe(roleName);
      expect(newRole.permissions).toEqual(permissions);
      expect(newRole.code).toBe(code);
    });

    it("should throw an error if role code is not unique", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];
      const code = "admin_code";

      // Create the first role
      await roleInstance.create(roleName, permissions, code);

      // Attempt to create another role with the same code
      await expect(
        roleInstance.create("another_role", ["execute"], code)
      ).rejects.toThrow(K2Error);
    });

    it("should throw a validation error for invalid permissions", async () => {
      await expect(
        roleInstance.create("admin", ["invalid_permission!"])
      ).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw a validation error if role name is empty", async () => {
      const roleName = ""; // Empty name
      const permissions = ["read", "write"];
      await expect(roleInstance.create(roleName, permissions)).rejects.toThrow(
        K2Error
      );
    });

    it("should throw a validation error if permissions array is empty", async () => {
      const roleName = "admin";
      const permissions: string[] = []; // Empty permissions array
      await expect(roleInstance.create(roleName, permissions)).rejects.toThrow(
        K2Error
      );
    });

    it("should throw a validation error if permissions array contains duplicates", async () => {
      const roleName = "admin";
      const permissions = ["read", "write", "read"]; // Duplicate 'read' permission
      await expect(roleInstance.create(roleName, permissions)).rejects.toThrow(
        K2Error
      );
    });
  });

  describe("get() method", () => {
    it("should retrieve a role by its ID", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      // First, create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Then retrieve the role by its ID
      const retrievedRole = await roleInstance.get(newRole._uuid);

      expect(retrievedRole).toBeDefined();
      expect(retrievedRole?.name).toBe(roleName);
    });

    it("should throw an error if role ID does not exist", async () => {
      await expect(roleInstance.get("invalid-id")).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw an error if role ID format is invalid", async () => {
      const invalidId = "invalid-id-format";
      await expect(roleInstance.get(invalidId)).rejects.toThrow(K2Error);
    });

    it("should throw an error if role ID is null", async () => {
      const invalidId = null;
      await expect(roleInstance.get(invalidId as any)).rejects.toThrow(K2Error);
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

    // New negative tests
    it("should throw an error if role code is null", async () => {
      const invalidCode = null;
      await expect(roleInstance.getByCode(invalidCode as any)).rejects.toThrow(
        K2Error
      );
    });

    it("should throw an error if role code is empty string", async () => {
      const invalidCode = "";
      await expect(roleInstance.getByCode(invalidCode)).rejects.toThrow(
        K2Error
      );
    });
  });

  describe("update() method", () => {
    it("should update the role name and permissions successfully", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Update the role data
      const updated = await roleInstance.update(newRole._uuid, {
        name: "super-admin",
        permissions: ["execute"],
      });

      expect(updated.updated).toBe(1);

      // Retrieve and verify the updated role
      const updatedRole = await roleInstance.get(newRole._uuid);
      expect(updatedRole?.name).toBe("super-admin");
      expect(updatedRole?.permissions).toEqual(["execute"]);
    });

    it("should throw an error if role does not exist", async () => {
      await expect(
        roleInstance.update("invalid-id", { name: "new-name" })
      ).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw a validation error if updating with empty name", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Attempt to update with empty name
      await expect(
        roleInstance.update(newRole._uuid, { name: "" })
      ).rejects.toThrow(K2Error);
    });

    it("should throw a validation error if updating with duplicate permissions", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];

      // Create a role
      const newRole = await roleInstance.create(roleName, permissions);

      // Attempt to update with duplicate permissions
      await expect(
        roleInstance.update(newRole._uuid, {
          permissions: ["read", "write", "read"],
        })
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if updating code to a code that already exists", async () => {
      const roleName1 = "admin";
      const permissions1 = ["read", "write"];
      const code1 = "admin_code";

      const roleName2 = "user";
      const permissions2 = ["read"];
      const code2 = "user_code";

      // Create two roles
      const role1 = await roleInstance.create(roleName1, permissions1, code1);
      const role2 = await roleInstance.create(roleName2, permissions2, code2);

      // Attempt to update role2's code to code1
      await expect(
        roleInstance.update(role2._uuid, { code: code1 })
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

      expect(deleted.deleted).toBe(1);

      // Verify the role is deleted
      await expect(roleInstance.get(newRole._uuid)).rejects.toThrow(K2Error);
    });

    it("should throw an error if role does not exist", async () => {
      await expect(roleInstance.delete("invalid-id")).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw an error if role ID format is invalid", async () => {
      const invalidId = "invalid-id-format";
      await expect(roleInstance.delete(invalidId)).rejects.toThrow(K2Error);
    });

    it("should throw an error if role ID is null", async () => {
      const invalidId = null;
      await expect(roleInstance.delete(invalidId as any)).rejects.toThrow(
        K2Error
      );
    });
  });

  // New describe block for find() method
  describe("find() method", () => {
    it("should find roles based on criteria", async () => {
      // Create roles
      const role1 = await roleInstance.create(
        "admin",
        ["read", "write"],
        "admin_code"
      );
      const role2 = await roleInstance.create("user", ["read"], "user_code");

      // Find roles with name 'admin'
      const roles = await roleInstance.find({ name: "admin" });
      expect(roles).toHaveLength(1);
      expect(roles[0].name).toBe("admin");
    });

    it("should return empty array if no roles match criteria", async () => {
      const roles = await roleInstance.find({ name: "nonexistent" });
      expect(roles).toHaveLength(0);
    });

    it("should throw an error if criteria is invalid", async () => {
      // Passing invalid criteria (e.g., null)
      await expect(roleInstance.find(null as any)).rejects.toThrow(K2Error);
    });

    it("should throw an error if limit is negative", async () => {
      await expect(roleInstance.find({}, -1)).rejects.toThrow(K2Error);
    });

    it("should throw an error if skip is negative", async () => {
      await expect(roleInstance.find({}, 10, -1)).rejects.toThrow(K2Error);
    });
  });
});
