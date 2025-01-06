import { Ticket } from "./types";
import { Auth, AuthTokens, TokenPayload } from "./auth";
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
  private _ticket: Ticket;
  private _auth: Auth;
  private _user: User;
  private _role: Role;
  private _account: Account;

  // async authenticateJWT(jwt: string): Promise<Ticket> {
  //   return Promise.reject();
  // }

  constructor(private db: K2DB) {
    this._ticket = Auth.getSystemTicket();
    this._auth = new Auth(db, this._ticket);
    this._user = new User(db, this._ticket);
    this._account = new Account(db, this._ticket);
    this._role = new Role(db, this._ticket);
  }

  // //--- AUTH
  // async registerUserWithEmailAndPassword(
  //   email: string,
  //   password: string
  // ): Promise<AuthTokens> {
  //   const result = await this._user.createUserByEmailAndPassword(
  //     email,
  //     password
  //   );

  //   const roles: Array<string> = ["member"];

  //   // figure out if this is the first user, if so, add admin role
  //   const count = await this._user.count();

  //   if (count.count === 1) {
  //     // add admin role, otherwise add default (member) role
  //     // admin and memeber roles are used as flags to determine if user is admin or not,
  //     // and they come with a set of default permissions such as being able to to login
  //     // admin has the max power and can do anything, never add admin to new members
  //     // create fine-tuned roles for "administrative" users
  //     // admin role has only RBAC effect necessary to login and create other roles
  //     // so in a sense admin requires "member" role to login
  //     // member is a purely AUTH role that ONLY allows login
  //     // neither admin not mamber roles are actual roles in the system but flags
  //     // they are both role and permission and the only "hardcoded" roles in the system

  //     roles.push("admin");
  //   }

  //   const accountResult = await this._account.create(result.id, roles);

  //   // accountResult for future fiddling, adding roles, etc

  //   const payload = {
  //     userId: result.id,
  //     roles: roles,
  //     restrictedMode: true,
  //   };

  //   const ret: any = Auth.generateTokens(payload)
  //   ret.id = result.id
  //   return ret;
  // }

  // async authenticateUserWithEmailAndPassword(
  //   email: string,
  //   password: string
  // ): Promise<{ id: string }> {
  //   return Promise.reject();
  // }

  //--- ROLES
  async roles(filter: any, skip?: number, limit?: number) {
    // return this.role.find(filter, skip, limit);
  }

  // async createRole(
  //   name: string,
  //   permissions: Array<string>
  // ): Promise<K2CreateResponse> {
  //   return await this._role.create({ name: name, permissions: permissions });
  // }

  async updateRole(
    roleId: string,
    data: RoleDocument
  ): Promise<K2UpdateResponse> {
    return await this._role.update(roleId, data);
  }

  async deleteRole(roleId: string): Promise<K2DeleteResponse> {
    return await this._role.delete(roleId);
  }

  //--- USERS
  async users(filter: any) {
    return await this._user.find(filter);
  }
  async user(userId: string) {
    return await this._user.get(userId);
  }
  async updateUser(userId: string, data: any): Promise<K2UpdateResponse> {
    return Promise.reject();
  }

  async deleteUser(userId: string): Promise<K2DeleteResponse> {
    return await this._user.delete(userId);
  }

  //--- ACCOUNTS
  async accounts(filter: any) {}
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
}
