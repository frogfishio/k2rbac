// __tests__/user.test.ts

import { K2DB, DatabaseConfig } from "@frogfish/k2db/db";
import { Auth } from "../src/auth";
import { Ticket } from "../src/types";
import { User, UserDocument, IdentityType } from "../src/user";
import { K2Error } from "@frogfish/k2error"; // Import error classes

describe("User Class", () => {
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
  let userInstance: User; // Variable to hold the User instance

  beforeAll(async () => {
    // Initialize the K2DB instance and establish a connection
    dbInstance = new K2DB(config);
    await dbInstance.init();

    // Instantiate User class using K2Data and Ticket
    userInstance = new User(dbInstance, systemTicket);
  });

  afterAll(async () => {
    // Clean up the test database and close the connection
    await dbInstance.dropDatabase();
    await dbInstance.release(); // Release the K2DB connection
  });

  beforeEach(async () => {
    // Optionally drop the entire users collection
    await dbInstance.deleteAll("_users", {});
  });

  describe("createUser() method", () => {
    it("should create a new user successfully", async () => {
      const email = "test@example.com";
      const password = "password123";

      const newUser = await userInstance.createUser(
        IdentityType.EMAIL,
        email,
        password
      );

      expect(newUser).toBeDefined();
      expect(newUser.id).toBeDefined();
    });

    it("should throw an error if email is invalid", async () => {
      await expect(
        userInstance.createUser(IdentityType.EMAIL, "invalid-email", "password")
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if email is already registered", async () => {
      const email = "duplicate@example.com";
      const password = "password123";

      // Create user
      await userInstance.createUser(IdentityType.EMAIL, email, password);

      // Try creating again with the same email
      await expect(
        userInstance.createUser(IdentityType.EMAIL, email, password)
      ).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw an error if password is missing", async () => {
      const email = "nopassword@example.com";
      await expect(
        userInstance.createUser(IdentityType.EMAIL, email, "")
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if identity type is unsupported", async () => {
      const email = "unsupported@example.com";
      const password = "password123";
      const invalidType = "unsupported_type" as IdentityType;

      await expect(
        userInstance.createUser(invalidType, email, password)
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if identifier is missing", async () => {
      const password = "password123";
      await expect(
        userInstance.createUser(IdentityType.EMAIL, "", password)
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if password is too weak", async () => {
      const email = "weakpassword@example.com";
      const weakPassword = "123"; // Assuming password strength validation
      await expect(
        userInstance.createUser(IdentityType.EMAIL, email, weakPassword)
      ).rejects.toThrow(K2Error);
    });
  });

  describe("get() method", () => {
    it("should retrieve a user by ID", async () => {
      const email = "user1@example.com";
      const password = "password123";

      // First, create a user
      const newUser = await userInstance.createUser(
        IdentityType.EMAIL,
        email,
        password
      );

      // Then retrieve the user by its ID
      const retrievedUser = await userInstance.get(newUser.id);

      expect(retrievedUser).toBeDefined();
      expect(retrievedUser.identities[0].identifier).toBe(email);
    });

    it("should throw an error if user ID does not exist", async () => {
      await expect(userInstance.get("invalid-id")).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw an error if user ID format is invalid", async () => {
      const invalidId = "invalid-id-format";
      await expect(userInstance.get(invalidId)).rejects.toThrow(K2Error);
    });

    it("should throw an error if user ID is null", async () => {
      const invalidId = null;
      await expect(userInstance.get(invalidId as any)).rejects.toThrow(K2Error);
    });
  });

  describe("findByIdentifier() method", () => {
    it("should retrieve a user by identifier", async () => {
      const email = "findme@example.com";
      const password = "password123";

      // Create a user with an email
      await userInstance.createUser(IdentityType.EMAIL, email, password);

      // Retrieve the user by email
      const foundUser = await userInstance.findByIdentifier(
        IdentityType.EMAIL,
        email
      );

      expect(foundUser).toBeDefined();
      expect(foundUser?.identities[0].identifier).toBe(email);
    });

    it("should return null if the identifier does not exist", async () => {
      const foundUser = await userInstance.findByIdentifier(
        IdentityType.EMAIL,
        "nonexistent@example.com"
      );

      expect(foundUser).toBeNull();
    });

    // New negative tests
    it("should return null if identifier is null", async () => {
      const foundUser = await userInstance.findByIdentifier(
        IdentityType.EMAIL,
        null as any
      );

      expect(foundUser).toBeNull();
    });

    it("should throw an error if identity type is invalid", async () => {
      const invalidType = "invalid_type" as IdentityType;
      await expect(
        userInstance.findByIdentifier(invalidType, "test@example.com")
      ).rejects.toThrow(K2Error);
    });

    it("should return null if identifier is empty string", async () => {
      const foundUser = await userInstance.findByIdentifier(
        IdentityType.EMAIL,
        ""
      );

      expect(foundUser).toBeNull();
    });
  });

  describe("authenticate() method", () => {
    it("should authenticate a user with valid credentials", async () => {
      const email = "authuser@example.com";
      const password = "securePassword";

      // Create a user
      await userInstance.createUser(IdentityType.EMAIL, email, password);

      // Authenticate with correct credentials
      const authenticatedUser = await userInstance.authenticate(
        IdentityType.EMAIL,
        email,
        password
      );

      expect(authenticatedUser).toBeDefined();
      expect(authenticatedUser.identities[0].identifier).toBe(email);
    });

    it("should throw an error for invalid credentials", async () => {
      const email = "wrongauth@example.com";
      const password = "rightPassword";
      const wrongPassword = "wrongPassword";

      // Create a user
      await userInstance.createUser(IdentityType.EMAIL, email, password);

      // Attempt authentication with incorrect password
      await expect(
        userInstance.authenticate(IdentityType.EMAIL, email, wrongPassword)
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if the user is not found", async () => {
      await expect(
        userInstance.authenticate(
          IdentityType.EMAIL,
          "nonexistent@example.com",
          "password"
        )
      ).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw an error if identity type is invalid", async () => {
      const email = "invalidtype@example.com";
      const password = "password123";
      const invalidType = "invalid_type" as IdentityType;

      await expect(
        userInstance.authenticate(invalidType, email, password)
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if identifier is missing", async () => {
      const password = "password123";
      await expect(
        userInstance.authenticate(IdentityType.EMAIL, "", password)
      ).rejects.toThrow(K2Error);
    });

    it("should throw an error if identifiedBy (password) is missing", async () => {
      const email = "missingpassword@example.com";
      const password = "password123";

      // Create a user
      await userInstance.createUser(IdentityType.EMAIL, email, password);

      // Attempt authentication without password
      await expect(
        userInstance.authenticate(IdentityType.EMAIL, email, "")
      ).rejects.toThrow(K2Error);
    });
  });

  describe("delete() method", () => {
    it("should delete a user successfully", async () => {
      const email = "deletethis@example.com";
      const password = "password123";

      // Create a user
      const newUser = await userInstance.createUser(
        IdentityType.EMAIL,
        email,
        password
      );

      // Delete the user
      const deletionResult = await userInstance.delete(newUser.id);

      expect(deletionResult.deleted).toBe(1);

      // Verify the user is deleted
      await expect(userInstance.get(newUser.id)).rejects.toThrow(K2Error);
    });

    it("should throw an error if the user does not exist", async () => {
      await expect(userInstance.delete("invalid-id")).rejects.toThrow(K2Error);
    });

    // New negative tests
    it("should throw an error if user ID is null", async () => {
      const invalidId = null;
      await expect(userInstance.delete(invalidId as any)).rejects.toThrow(
        K2Error
      );
    });

    it("should throw an error if user ID format is invalid", async () => {
      const invalidId = "invalid-id-format";
      await expect(userInstance.delete(invalidId)).rejects.toThrow(K2Error);
    });
  });
});
