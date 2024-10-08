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
  });

  describe("create() method", () => {
    it("should create a new role successfully", async () => {
      // Create a new role
      const roleName = "admin";
      const permissions = ["read", "write"];

      const newRole = await roleInstance.create(roleName, permissions);

      // Validate that the role is created successfully
      expect(newRole).toBeDefined();
      expect(newRole.name).toBe(roleName);
      expect(newRole.permissions).toEqual(permissions);
    });

    it("should throw an error if role creation fails", async () => {
      // Spy on the create method to simulate a failure
      jest
        .spyOn(dataFacade, "create")
        .mockRejectedValueOnce(new Error("Failed to create"));

      await expect(roleInstance.create("invalid-role")).rejects.toThrow(
        K2Error
      );

      // Restore the original method after the test
      jest.restoreAllMocks();
    });
  });
});
