// __tests__/user.test.ts

import { K2DB, DatabaseConfig } from "@frogfish/k2db/db";
import { Auth } from "../src/auth";
import { Ticket } from "../src/types";
import { User, UserDocument } from "../src/user";
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

  describe("createUser() method", () => {
    it("should create a new user successfully", async () => {
      const identifiedBy = "password123";
      const method = "bcrypt";
      const identities = [{ type: "email", value: "test@example.com" }];

      const newUser = await userInstance.createUser(
        identifiedBy,
        method,
        identities
      );

      expect(newUser).toBeDefined();
      expect(newUser.identifiedBy).toBeDefined(); // This should be hashed
      expect(newUser.identities).toEqual(expect.arrayContaining(identities));
    });

    it("should throw an error if user creation fails", async () => {
      jest
        .spyOn(dbInstance, "create")
        .mockRejectedValueOnce(new Error("Failed to create"));

      await expect(
        userInstance.createUser("invalid-password", "bcrypt", [])
      ).rejects.toThrow(K2Error);

      jest.restoreAllMocks();
    });
  });

  describe("getById() method", () => {
    it("should retrieve a user by their ID", async () => {
      const identifiedBy = "password123";
      const method = "bcrypt";
      const identities = [{ type: "email", value: "test@example.com" }];

      const newUser = await userInstance.createUser(
        identifiedBy,
        method,
        identities
      );

      const retrievedUser = await userInstance.getById(newUser._uuid);

      expect(retrievedUser).toBeDefined();
      expect(retrievedUser?.identities).toEqual(
        expect.arrayContaining(identities)
      );
    });

    it("should throw an error if user ID does not exist", async () => {
      await expect(userInstance.getById("invalid-id")).rejects.toThrow(K2Error);
    });
  });

  describe("getByIdentity() method", () => {
    it("should retrieve a user by their identity", async () => {
      const identifiedBy = "password123";
      const method = "bcrypt";
      const identities = [{ type: "email", value: "test@example.com" }];

      await userInstance.createUser(identifiedBy, method, identities);

      const retrievedUser = await userInstance.getByIdentity(
        "email",
        "test@example.com"
      );

      expect(retrievedUser).toBeDefined();
      expect(retrievedUser?.identities[0].value).toBe("test@example.com");
    });

    it("should throw an error if the user identity does not exist", async () => {
      await expect(
        userInstance.getByIdentity("email", "nonexistent@example.com")
      ).rejects.toThrow(K2Error);
    });
  });

  describe("authenticate() method", () => {
    it("should authenticate a user successfully", async () => {
      const identifiedBy = "password123";
      const method = "bcrypt";
      const identities = [{ type: "email", value: "test@example.com" }];

      const newUser = await userInstance.createUser(
        identifiedBy,
        method,
        identities
      );

      const isAuthenticated = await userInstance.authenticate(
        identifiedBy,
        method,
        newUser._uuid
      );

      expect(isAuthenticated).toBe(true);
    });

    it("should return false if authentication fails", async () => {
      const identifiedBy = "wrongPassword";
      const method = "bcrypt";
      const identities = [{ type: "email", value: "test@example.com" }];

      const newUser = await userInstance.createUser(
        "password123",
        method,
        identities
      );

      const isAuthenticated = await userInstance.authenticate(
        identifiedBy,
        method,
        newUser._uuid
      );

      expect(isAuthenticated).toBe(false);
    });
  });

  describe("createOtp() method", () => {
    it("should generate and store OTP for the user", async () => {
      const identifiedBy = "password123";
      const method = "bcrypt";
      const identities = [{ type: "email", value: "test@example.com" }];

      const newUser = await userInstance.createUser(
        identifiedBy,
        method,
        identities
      );

      const otp = await userInstance.createOtp(newUser._uuid);

      expect(otp).toBeDefined();

      const updatedUser = await userInstance.getById(newUser._uuid);

      expect(updatedUser?.otp).toBe(otp);
      expect(updatedUser?.otpExpiresAt).toBeGreaterThan(Date.now());
    });
  });

  describe("setRestrictedMode() method", () => {
    it("should set restricted mode for a user", async () => {
      const identifiedBy = "password123";
      const method = "bcrypt";
      const identities = [{ type: "email", value: "test@example.com" }];

      const newUser = await userInstance.createUser(
        identifiedBy,
        method,
        identities
      );

      const result = await userInstance.setRestrictedMode(newUser._uuid, true);

      expect(result).toBe(true);

      const updatedUser = await userInstance.getById(newUser._uuid);

      expect(updatedUser?.restrictedMode).toBe(true);
    });
  });

  describe("clearOtp() method", () => {
    it("should clear the OTP for a user", async () => {
      const identifiedBy = "password123";
      const method = "bcrypt";
      const identities = [{ type: "email", value: "test@example.com" }];

      const newUser = await userInstance.createUser(
        identifiedBy,
        method,
        identities
      );

      await userInstance.createOtp(newUser._uuid); // Generate OTP

      const cleared = await userInstance.clearOtp(newUser._uuid);
      expect(cleared).toBe(true);

      const updatedUser = await userInstance.getById(newUser._uuid);

      expect(updatedUser?.otp).toBeUndefined();
      expect(updatedUser?.otpExpiresAt).toBeUndefined();
    });
  });
});
