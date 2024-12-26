// __tests__/account.test.ts

import { K2DB, DatabaseConfig } from "@frogfish/k2db/db";
import { Auth } from "../src/auth";
import { Ticket } from "../src/types";
import { Account } from "../src/account";
import { K2Error } from "@frogfish/k2error"; // Import error classes

describe("Account Class", () => {
  const dbName = "test"; // Define the test database name

  // Configuration that works
  const config: DatabaseConfig = require("../dbconfig.json");

  const systemTicket: Ticket = Auth.getSystemTicket(); // Authorization ticket
  let dbInstance: K2DB; // Variable to hold the K2DB instance
  let accountInstance: Account; // Variable to hold the Account instance

  beforeAll(async () => {
    // Initialize the K2DB instance and establish a connection
    dbInstance = new K2DB(config);
    await dbInstance.init();

    // Instantiate Account class using K2Data and Ticket
    accountInstance = new Account(dbInstance, systemTicket);
  });

  afterAll(async () => {
    // Clean up the test database and close the connection
    await dbInstance.dropDatabase();
    await dbInstance.release(); // Release the K2DB connection
  });

  describe("create() method", () => {
    it("should create a new account successfully", async () => {
      const userId = "user123";
      const roles = ["admin", "editor"];

      const newAccount = await accountInstance.create(userId, roles);

      expect(newAccount).toBeDefined();
      expect(newAccount.id).toBeDefined();
    });

    it("should throw an error if account creation fails", async () => {
      jest
        .spyOn(dbInstance, "create")
        .mockRejectedValueOnce(new Error("Failed to create"));

      await expect(
        accountInstance.create("invalid-user", ["admin"])
      ).rejects.toThrow(K2Error);

      jest.restoreAllMocks();
    });
  });

  describe("getById() method", () => {
    it("should retrieve an account by its ID", async () => {
      const userId = "user123";
      const roles = ["admin"];

      const newAccount = await accountInstance.create(userId, roles);

      const retrievedAccount = await accountInstance.get(newAccount.id);

      expect(retrievedAccount).toBeDefined();
      expect(retrievedAccount?.userRoles[userId]).toEqual(roles);
    });

    it("should throw an error if account ID does not exist", async () => {
      await expect(accountInstance.get("invalid-id")).rejects.toThrow(K2Error);
    });
  });

  describe("addUser() method", () => {
    it("should add a user to the account with roles", async () => {
      const userId = "user123";
      const roles = ["admin"];

      const newAccount = await accountInstance.create(userId, roles);

      const newUserId = "user456";
      const newRoles = ["viewer"];

      const result = await accountInstance.addUser(
        newAccount.id,
        newUserId,
        newRoles
      );

      expect(result).toBe(true);

      const updatedAccount = await accountInstance.get(newAccount.id);
      expect(updatedAccount?.userRoles[newUserId]).toEqual(newRoles);
    });

    it("should throw an error if account does not exist", async () => {
      await expect(
        accountInstance.addUser("invalid-id", "user123", ["admin"])
      ).rejects.toThrow(K2Error);
    });
  });

  describe("removeUser() method", () => {
    it("should remove a user from the account", async () => {
      const userId = "user123";
      const roles = ["admin"];

      const newAccount = await accountInstance.create(userId, roles);

      const newUserId = "user456";
      await accountInstance.addUser(newAccount.id, newUserId, ["viewer"]);

      const result = await accountInstance.removeUser(newAccount.id, newUserId);

      expect(result).toBe(true);

      const updatedAccount = await accountInstance.get(newAccount.id);
      expect(updatedAccount?.userRoles[newUserId]).toBeUndefined();
    });

    it("should throw an error if account or user does not exist", async () => {
      await expect(
        accountInstance.removeUser("invalid-id", "user123")
      ).rejects.toThrow(K2Error);
    });
  });

  describe("addRolesToUser() method", () => {
    it("should add roles to a user in the account", async () => {
      const userId = "user123";
      const roles = ["admin"];

      const newAccount = await accountInstance.create(userId, roles);

      const result = await accountInstance.addRolesToUser(
        newAccount.id,
        userId,
        ["viewer"]
      );

      expect(result).toBe(true);

      const updatedAccount = await accountInstance.get(newAccount.id);
      expect(updatedAccount?.userRoles[userId]).toEqual(
        expect.arrayContaining(["admin", "viewer"])
      );
    });

    it("should throw an error if account or user does not exist", async () => {
      await expect(
        accountInstance.addRolesToUser("invalid-id", "user123", ["admin"])
      ).rejects.toThrow(K2Error);
    });
  });

  describe("removeRolesFromUser() method", () => {
    it("should remove roles from a user in the account", async () => {
      const userId = "user123";
      const roles = ["admin", "editor"];

      const newAccount = await accountInstance.create(userId, roles);

      const result = await accountInstance.removeRolesFromUser(
        newAccount.id,
        userId,
        ["editor"]
      );

      expect(result).toBe(true);

      const updatedAccount = await accountInstance.get(newAccount.id);
      expect(updatedAccount?.userRoles[userId]).toEqual(["admin"]);
    });

    it("should throw an error if account or user does not exist", async () => {
      await expect(
        accountInstance.removeRolesFromUser("invalid-id", "user123", ["admin"])
      ).rejects.toThrow(K2Error);
    });
  });

  describe("removeAccount() method", () => {
    it("should remove an account successfully", async () => {
      const userId = "user123";
      const roles = ["admin"];

      const newAccount = await accountInstance.create(userId, roles);

      const result = await accountInstance.delete(newAccount.id);

      expect(result).toStrictEqual({ deleted: 1 }); // Use toStrictEqual here

      await expect(accountInstance.get(newAccount.id)).rejects.toThrow(K2Error);
    });

    it("should throw an error if account does not exist", async () => {
      await expect(accountInstance.delete("invalid-id")).rejects.toThrow(
        K2Error
      );
    });
  });
});
