import { BaseDocument, K2DB } from "@frogfish/k2db/db";
import { K2Error, ServiceError } from "@frogfish/k2error";
import { Ticket } from "./types";
import debugLib from "debug";
import { Secure } from "./secure";
const debug = debugLib("k2:rbac:user");

export enum IdentityType {
  EMAIL = "email",
  USER = "user",
}

enum IdentityMethod {
  BCRYPT = "bcrypt",
}

export interface UserDocument extends BaseDocument {
  identities: Identity[];
  restrictedMode: boolean;
}

export interface Identity {
  type: IdentityType;
  identifier: string;
  identifiedBy?: string;
  method?: string;
}

export class User {
  constructor(private db: K2DB, private ticket: Ticket) {}

  public async createUser(
    type: IdentityType,
    identifier: string,
    identifiedBy: string
  ): Promise<{ id: string }> {
    const identity = await this.createIdentity(type, identifier, identifiedBy);

    try {
      return await this.db.create("_users", this.ticket.account, {
        identities: [identity],
        restrictedMode: false,
      });
    } catch (error) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Failed to create user",
        "ugfv212d399975i0904l",
        undefined
      );
    }
  }

  async get(id: string): Promise<UserDocument> {
    const user = await this.db.get("_users", id);
    return this.stripIdentifiers(user as UserDocument);
  }

  async delete(id: string): Promise<{ deleted: number }> {
    return await this.db.delete("_users", id);
  }

  async findByIdentifier(
    type: IdentityType,
    identifier: string
  ): Promise<UserDocument | null> {
    const user = await this.db.findOne("_users", {
      "identities.type": type,
      "identities.identifier": identifier,
    });

    return user ? this.stripIdentifiers(user as UserDocument) : null;
  }

  async authenticate(
    type: IdentityType,
    identifier: string,
    identifiedBy: string
  ): Promise<UserDocument> {
    const user = (await this.db.findOne("_users", {
      "identities.type": type,
      "identities.identifier": identifier,
    })) as UserDocument;

    if (!user) {
      throw new K2Error(
        ServiceError.NOT_FOUND,
        `User ${identifier} not found`,
        "kae0644rh475d12gacct",
        undefined
      );
    }

    const identity = user.identities.find(
      (id: Identity) => id.type === type && id.identifier === identifier
    );

    if (!identity) {
      throw new K2Error(
        ServiceError.SYSTEM_ERROR,
        `Identity conflict`,
        "331yy8a7nolevo82td5u",
        undefined
      );
    }

    if ((await this.isValidIdentity(identity, identifiedBy)) !== true) {
      throw new K2Error(
        ServiceError.AUTH_ERROR,
        "Invalid identity",
        "04eyjdnj7mwfno5v6xz0",
        undefined
      );
    }

    return this.stripIdentifiers(user);
  }

  /*********** helpers *************/

  private async createIdentity(
    type: IdentityType,
    identifier: string,
    identifiedBy: string
  ): Promise<Identity> {
    const identity: Partial<Identity> = { type, identifier };

    if (type === IdentityType.EMAIL) {
      identity.method = IdentityMethod.BCRYPT;
      await this.validateEmail(identifier);
      identity.identifiedBy = await Secure.bcrypt(identifiedBy);
    }

    return identity as Identity;
  }

  private async isValidIdentity(
    identity: Identity,
    identifiedBy: string
  ): Promise<boolean> {
    switch (identity.method) {
      case IdentityMethod.BCRYPT:
        return await Secure.bcryptVerify(
          identifiedBy,
          identity.identifiedBy || ""
        );
    }

    throw new K2Error(
      ServiceError.AUTH_ERROR,
      "Invalid identity authorisation method",
      "6ue424dz4v1hyd9o8h8b",
      undefined
    );
  }

  private stripIdentifiers(user: UserDocument): UserDocument {
    for (const identity of user.identities) {
      delete identity.method;
      delete identity.identifiedBy;
    }

    return user;
  }

  private async validateEmail(email: string) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Invalid email format",
        "ev2633py5739q51hlpzz",
        undefined
      );
    }

    const existingUser = await this.db.findOne("_users", {
      "identities.identifier": email,
    });
    if (existingUser) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Email is already registered",
        "7x2715n26d5a9o5c6g3j",
        undefined
      );
    }
  }

  private async validateUsername(username: string) {
    const existingUser = await this.db.findOne("_users", {
      "identities.identifier": username,
    });
    if (existingUser) {
      throw new K2Error(
        ServiceError.SERVICE_ERROR,
        "Username is already taken",
        "jsn7m36314jb721db0xg",
        undefined
      );
    }
  }
}
