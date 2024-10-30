import { K2DB, DatabaseConfig } from "@frogfish/k2db/db";
import { Auth } from "../src/auth";
import { Ticket } from "../src/types";
import { Role } from "../src/role";
import { K2Error } from "@frogfish/k2error";
import { v4 as uuidv4 } from "uuid"; // Import UUID for unique identifiers

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
    await dbInstance.release(); // Release the K2DB connection
  });

  beforeEach(async () => {
    // Clean up the entire roles collection before each test to ensure isolation
    await dbInstance.deleteAll("_roles", {}); // Remove all documents from _roles
  });

  /**
   * Helper function to generate unique role codes using UUID
   */
  const generateUniqueCode = (base: string = "code") => `${base}_${uuidv4()}`;

  /**
   * Helper function to create a role with optional parameters
   */
  interface CreateRoleOptions {
    name?: string;
    permissions?: string[];
    code?: string;
  }

  const createRole = async ({
    name = `role_${uuidv4()}`,
    permissions = ["read", "write"],
    code = generateUniqueCode("code"),
  }: CreateRoleOptions = {}) => {
    return await roleInstance.create(name, permissions, code);
  };

  describe("create() method", () => {
    it("should create a new role successfully", async () => {
      const roleName = "admin";
      const permissions = ["read", "write"];
      const code = generateUniqueCode("admin_code");

      const newRole = await roleInstance.create(roleName, permissions, code);

      expect(newRole).toBeDefined();
      expect(newRole.id).toBeDefined();
    });

    it("should throw an error if role code is not unique", async () => {
      const code = generateUniqueCode("admin_code");

      // Create the first role
      await createRole({ name: "admin", code });

      // Attempt to create another role with the same code
      await expect(
        createRole({ name: "another_role", permissions: ["execute"], code })
      ).rejects.toThrow(K2Error);
    });

    it("should throw a validation error for invalid permissions", async () => {
      const invalidPermissions = ["invalid_permission!"];
      const code = generateUniqueCode("invalid_perm_code");

      await expect(
        roleInstance.create("admin", invalidPermissions, code)
      ).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw a validation error if role name is empty", async () => {
      const roleName = ""; // Empty name
      const permissions = ["read", "write"];
      const code = generateUniqueCode("empty_name_code");

      await expect(
        roleInstance.create(roleName, permissions, code)
      ).rejects.toThrow(K2Error);
    });

    it("should throw a validation error if permissions array is empty", async () => {
      const roleName = "admin";
      const permissions: string[] = []; // Empty permissions array
      const code = generateUniqueCode("empty_permissions_code");

      await expect(
        roleInstance.create(roleName, permissions, code)
      ).rejects.toThrow(K2Error);
    });

    it("should throw a validation error if permissions array contains duplicates", async () => {
      const roleName = "admin";
      const permissions = ["read", "write", "read"]; // Duplicate 'read' permission
      const code = generateUniqueCode("duplicate_permissions_code");

      await expect(
        roleInstance.create(roleName, permissions, code)
      ).rejects.toThrow(K2Error);
    });
  });

  describe("get() method", () => {
    it("should retrieve a role by its ID", async () => {
      // Create a role
      const newRole = await createRole();
      
      // Retrieve the role by its ID
      const retrievedRole = await roleInstance.get(newRole.id);

      expect(retrievedRole).toBeDefined();
      expect(retrievedRole._uuid).toBeDefined();
    });

    it("should throw an error if role ID does not exist", async () => {
      const nonExistentId = uuidv4(); // Generate a random UUID

      await expect(roleInstance.get(nonExistentId)).rejects.toThrow(K2Error);
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
      const code = generateUniqueCode("admin-code");

      // Create a role with a code
      const newRole = await roleInstance.create(roleName, permissions, code);

      // Retrieve the role by its code
      const retrievedRole = await roleInstance.getByCode(code);

      expect(retrievedRole).toBeDefined();
      expect(retrievedRole?.code).toBe(code);
      expect(retrievedRole?.name).toBe(roleName);
      expect(retrievedRole?.permissions).toEqual(permissions);
    });

    it("should throw an error if the role code does not exist", async () => {
      const nonExistentCode = generateUniqueCode("nonexistent-code");

      await expect(roleInstance.getByCode(nonExistentCode)).rejects.toThrow(
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
      // Create a role
      const newRole = await createRole();

      // Update the role data
      const updated = await roleInstance.update(newRole.id, {
        name: "super-admin",
        permissions: ["execute"],
      });

      expect(updated.updated).toBe(1);

      // Retrieve and verify the updated role
      const updatedRole = await roleInstance.get(newRole.id);
      expect(updatedRole?.name).toBe("super-admin");
      expect(updatedRole?.permissions).toEqual(["execute"]);
    });

    it("should throw an error if role does not exist", async () => {
      const nonExistentId = uuidv4(); // Generate a random UUID

      await expect(
        roleInstance.update(nonExistentId, { name: "new-name" })
      ).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw a validation error if updating with empty name", async () => {
      // Create a role
      const newRole = await createRole();

      // Attempt to update with empty name
      await expect(
        roleInstance.update(newRole.id, { name: "" })
      ).rejects.toThrow(K2Error);
    });

    it("should throw a validation error if updating with duplicate permissions", async () => {
      // Create a role
      const newRole = await createRole();

      // Attempt to update with duplicate permissions
      await expect(
        roleInstance.update(newRole.id, {
          permissions: ["read", "write", "read"],
        })
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if updating code to a code that already exists", async () => {
      const code1 = generateUniqueCode("admin_code");
      const code2 = generateUniqueCode("user_code");

      // Create two roles with unique codes
      const role1 = await roleInstance.create(
        "admin",
        ["read", "write"],
        code1
      );
      const role2 = await roleInstance.create("user", ["read"], code2);

      // Attempt to update role2's code to role1's code
      await expect(
        roleInstance.update(role2.id, { code: code1 })
      ).rejects.toThrow(K2Error);
    });
  });

  describe("delete() method", () => {
    it("should delete a role successfully", async () => {
      // Create a role
      const newRole = await createRole();

      // Delete the role
      const deleted = await roleInstance.delete(newRole.id);

      expect(deleted.deleted).toBe(1);

      // Verify the role is deleted
      await expect(roleInstance.get(newRole.id)).rejects.toThrow(K2Error);
    });

    it("should throw an error if role does not exist", async () => {
      const nonExistentId = uuidv4(); // Generate a random UUID

      await expect(roleInstance.delete(nonExistentId)).rejects.toThrow(K2Error);
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
        generateUniqueCode("admin_code")
      );
      const role2 = await roleInstance.create(
        "user",
        ["read"],
        generateUniqueCode("user_code")
      );

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
