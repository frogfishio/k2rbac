// src/types.ts

export interface Ticket {
  user: string;
  account: string; // UUID of the user
  permissions: string[]; // Flattened list of permissions derived from roles
  restricted: boolean; // Flag indicating restricted access mode
  token?: string; // Original JWT token for reference
  expiresAt: number; // Use a UTC timestamp (milliseconds since epoch)
  checksum?: string;
}
