// __tests__/secure.test.ts

import { Secure } from "../src/secure";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { K2Error } from "@frogfish/k2error"; // Import error classes

describe("Secure Class", () => {
  describe("bcrypt() method", () => {
    it("should hash a plain text password successfully", async () => {
      const password = "securePassword123";

      const hashedPassword = await Secure.bcrypt(password);

      expect(hashedPassword).toBeDefined();
      expect(bcrypt.compareSync(password, hashedPassword)).toBe(true); // Verify the hash matches the original password
    });

    it("should throw an error if hashing fails", async () => {
      jest.spyOn(bcrypt, "hash").mockImplementationOnce(() => {
        return Promise.reject(new Error("Hashing error"));
      });

      await expect(Secure.bcrypt("password")).rejects.toThrow(K2Error);

      jest.restoreAllMocks();
    });
  });

  describe("bcryptVerify() method", () => {
    it("should return true for matching password and hash", async () => {
      const password = "verifyPassword123";
      const hashedPassword = await Secure.bcrypt(password);

      const isMatch = await Secure.bcryptVerify(password, hashedPassword);

      expect(isMatch).toBe(true);
    });

    it("should return false for non-matching password and hash", async () => {
      const password = "verifyPassword123";
      const wrongPassword = "wrongPassword";
      const hashedPassword = await Secure.bcrypt(password);

      const isMatch = await Secure.bcryptVerify(wrongPassword, hashedPassword);

      expect(isMatch).toBe(false);
    });

    it("should throw an error if verification fails", async () => {
      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => {
        return Promise.reject(new Error("Verification error"));
      });

      await expect(
        Secure.bcryptVerify("password", "hashedPassword")
      ).rejects.toThrow(K2Error);

      jest.restoreAllMocks();
    });
  });

  describe("JWT() method", () => {
    it("should generate a valid JWT token", () => {
      const payload = { userId: "12345" };
      const token = Secure.JWT(payload);

      expect(token).toBeDefined();

      const decoded = jwt.verify(token, "your-secure-secret-key"); // Using the same secret for verification
      expect(decoded).toMatchObject(payload);
    });

    it("should throw an error if JWT generation fails", () => {
      jest.spyOn(jwt, "sign").mockImplementationOnce(() => {
        throw new Error("JWT generation error");
      });

      const payload = { userId: "12345" };

      expect(() => Secure.JWT(payload)).toThrow(K2Error);

      jest.restoreAllMocks();
    });
  });

  describe("JWTVerify() method", () => {
    it("should verify a valid JWT token and return the payload", () => {
      const payload = { userId: "12345" };
      const token = Secure.JWT(payload);

      const decoded = Secure.JWTVerify(token);

      expect(decoded).toMatchObject(payload);
    });

    it("should throw an error for an invalid token", () => {
      const invalidToken = "invalidToken";

      expect(() => Secure.JWTVerify(invalidToken)).toThrow(K2Error);
    });

    it("should throw an error for an expired token", () => {
      // Generate a token with a very short expiration time
      const payload = { userId: "12345" };
      const token = jwt.sign(payload, "your-secure-secret-key", {
        expiresIn: "1ms",
      });

      // Wait for the token to expire
      setTimeout(() => {
        expect(() => Secure.JWTVerify(token)).toThrow(K2Error);
      }, 10);
    });
  });
});
