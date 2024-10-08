import { Ticket } from "./types"; // Import the Ticket type

// Utility function to check if a ticket has the necessary permission
export function checkPermission(
  ticket: Ticket,
  requiredPermission: string
): void {

  // Check if the ticket is valid
  if (ticket.account === "invalid") {
    throw new Error("Invalid ticket");
  }

  // Check if the ticket has expired using a UTC timestamp
  const currentTimestamp = Date.now(); // Current UTC timestamp in milliseconds

  if (ticket.expiresAt && ticket.expiresAt < currentTimestamp) {
    throw new Error("Unauthorized: Ticket has expired");
  }

  // If the ticket has the 'system' permission, allow all actions
  if (ticket.permissions.includes("system")) return;

  // If the ticket doesn't have the required permission, throw an error
  if (!ticket.permissions.includes(requiredPermission)) {
    throw new Error(
      `Unauthorized: missing required permission - ${requiredPermission}`
    );
  }
}
