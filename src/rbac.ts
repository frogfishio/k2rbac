import { Ticket } from "./types";
import { Auth } from "./auth";
import { Role } from "./role";
import { User } from "./user";

export class RBAC {
  // async authenticateJWT(jwt: string): Promise<Ticket> {
  //   return Promise.reject();
  // }

  constructor(private auth: Auth, private user: User, private role: Role) {}

  //--- AUTH
  async registerUserWithEmailAndPassword(
    email: string,
    password: string,
    token: Ticket
  ): Promise<string> {
    return Promise.reject();
  }

  async authenticateUserWithEmailAndPassword(
    email: string,
    password: string,
    token: Ticket
  ): Promise<string> {
    return Promise.reject();
  }

  //--- ROLES
  roles(filter: any) {}
  createRole(permissions: Array<string>) {}
  updateRole(roleId: string, permissions: Array<string>) {}
  deleteRole(roleId: string) {}

  //--- USERS
  users(filter: any) {}
  addRolesToUser(userId: string, roles: Array<string>) {}
  removeRolesFromUser(userId: string, roles: Array<string>) {}
  updateUser(userId: string, data: any) {}
  deleteUser(userId: string) {}

  //--- account
  accounts(filter: any) {}
  createAccount(userId: string, roleIds: Array<string>) {}
  updateRole(roleId: string, permissions: Array<string>) {}
  deleteRole(roleId: string) {}
}
