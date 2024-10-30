import { Ticket } from "./types";
import { Auth } from "./auth";
import { Role, RoleDocument } from "./role";
import { User } from "./user";
import {
  K2CreateResponse,
  K2DeleteResponse,
  K2UpdateResponse,
} from "./k2types";
import { Account } from "./account";
import { K2DB } from "@frogfish/k2db/db";

export class RBAC {
  private auth: Auth;
  private user: User;
  private role: Role;
  private account: Account;

  // async authenticateJWT(jwt: string): Promise<Ticket> {
  //   return Promise.reject();
  // }

  constructor(private db: K2DB, private ticket: Ticket) {
    this.auth = new Auth(db, ticket);
    this.user = new User(db, ticket);
    this.account = new Account(db, ticket);
    this.role = new Role(db, ticket);
  }

  //--- AUTH
  async registerUserWithEmailAndPassword(
    email: string,
    password: string
  ): Promise<{ id: string }> {
    return Promise.reject();
  }

  async authenticateUserWithEmailAndPassword(
    email: string,
    password: string
  ): Promise<{ id: string }> {
    return Promise.reject();
  }

  //--- ROLES
  async roles(filter: any, skip?: number, limit?: number) {
    return this.role.find(filter, skip, limit);
  }

  async createRole(
    name: string,
    permissions: Array<string>
  ): Promise<K2CreateResponse> {
    return await this.role.create(name, permissions);
  }

  async updateRole(
    roleId: string,
    data: RoleDocument
  ): Promise<K2UpdateResponse> {
    return await this.role.update(roleId, data);
  }

  async deleteRole(roleId: string): Promise<K2DeleteResponse> {
    return await this.role.delete(roleId);
  }

  //--- USERS
  async users(filter: any) {}
  async updateUser(userId: string, data: any): Promise<K2UpdateResponse> {
    return Promise.reject();
  }

  async deleteUser(userId: string): Promise<K2DeleteResponse> {
    return await this.user.delete(userId);
  }

  //--- ACCOUNTS
  async accounts(filter: any) {}
  async createAccount(
    userId: string,
    roles: Array<string>
  ): Promise<K2CreateResponse> {
    return await this.account.create(userId, roles);
  }
  async updateRolesForUser(
    accountId: string,
    userId: string,
    roles: Array<string>
  ) {}
  async addUserToAcccount(
    accountId: string,
    userId: string,
    roles: Array<string>
  ) {}
  async removeUserFromAccount(accountId: string, userId: string) {}
  async deleteAccount(accountId: string): Promise<K2DeleteResponse> {
    return await this.account.delete(accountId);
  }
}
