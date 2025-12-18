// admin.js – Staff / Admin Portal Logic

import {
    getAllTickets,
    updateTicketStatus,
    deleteTicket,
    requireAuth,
    requireAdmin
} from "./api.js";

// Protect page (must be logged in & admin)
requireAuth();
requireAdmin();

const tableBody = document.getElementById("ticket-table-body");

// Load all tickets for admin
async function loadAllTickets() {
    try {
        const tickets = await getAllTickets();
        tableBody.innerHTML = "";

        if (!tickets || tickets.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted">
                        No tickets found
                    </td>
                </tr>
            `;
            return;
        }

        tickets.forEach(ticket => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td class="ps-4">${ticket._id}</td>
                <td>${ticket.title}</td>
                <td>${ticket.category}</td>
                <td>
                    <span class="badge ${
                        ticket.status === "Resolved"
                            ? "bg-success"
                            : "bg-warning text-dark"
                    }">
                        ${ticket.status}
                    </span>
                </td>
                <td>${new Date(ticket.created_at).toLocaleDateString()}</td>
                <td>
                    <button
                        class="btn btn-success btn-sm me-2"
                        title="Resolve"
                        ${ticket.status === "Resolved" ? "disabled" : ""}
                        data-id="${ticket._id}"
                        data-action="resolve"

                    >
                        <i class="bi bi-check-lg"></i>
                    </button>

                    <button
                        class="btn btn-danger btn-sm"
                        title="Delete"
                        data-id="${ticket._id}"
                        data-action="delete"
                    >
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            `;

            tableBody.appendChild(row);
        });

    } catch (error) {
        console.error("Failed to load tickets:", error);
    }
}

// Handle table button clicks (event delegation)
tableBody.addEventListener("click", async (event) => {
    const button = event.target.closest("button");
    if (!button) return;

    const ticketId = button.getAttribute("data-id");
    const action = button.getAttribute("data-action");

    if (action === "resolve") {
        await handleResolve(ticketId);
    }

    if (action === "delete") {
        await handleDelete(ticketId);
    }
});

// Resolve ticket
async function handleResolve(ticketId) {
    try {
        await updateTicketStatus(ticketId, "resolved");
        await loadAllTickets(); // refresh table
    } catch (error) {
        console.error("Resolve failed:", error);
    }
}

// Delete ticket
async function handleDelete(ticketId) {
    const confirmed = confirm("Are you sure you want to delete this ticket?");
    if (!confirmed) return;

    try {
        await deleteTicket(ticketId);
        await loadAllTickets(); // refresh table
    } catch (error) {
        console.error("Delete failed:", error);
    }
}

// Initial load
loadAllTickets();
