import { getMyTickets } from './api.js';
import { deleteTicket } from './api.js';


// Security
if (typeof localStorage === "undefined" || !localStorage.getItem("access_token")) {
    alert("Please login");
    window.location.href = "login.html";
}

const tableBody = document.getElementById("ticket-table-body");

async function loadTickets() {
    try {
        const tickets = await getMyTickets();
        tableBody.innerHTML = "";

        if (tickets.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted">
                        No tickets found
                    </td>
                </tr>`;
            return;
        }

        tickets.forEach(t => {
            tableBody.innerHTML += `
                <tr data-id="${t._id}" style="cursor:pointer;">
                    <td>${t._id}</td>
                    <td>${t.title}</td>
                    <td>${t.category}</td>
                    <td>
                        <span class="badge ${
                            t.status==="open"? "bg-warning":
                            t.status==="in_progress"?"bg-info":
                            "bg-success"
                        }">
                        ${t.status.replace("_","").toUpperCase()}
                        </span>
                    </td>
                    <td>${t.created_at ? new Date(t.created_at).toLocaleDateString() : "-"}</td>
                    <td class="text-end">
                        <button class="btn btn-danger btn-sm delete-btn" data-id="${t._id}">
                            Delete
                        </button>
                    </td>
                </tr>`;
        });

    } catch (err) {
        console.error(err);
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-danger">
                    Failed to load tickets
                </td>
            </tr>`;
    }
}

loadTickets();

// Event Delegation (Handles both Row Clicks and Button Clicks)
tableBody.addEventListener("click", async (e) => {
    
    // 1. Check if the clicked element is the DELETE button
    if (e.target.classList.contains("delete-btn")) {
        const id = e.target.getAttribute("data-id");
        
        if (confirm("Are you sure you want to delete this ticket?")) {
            try {
                await deleteTicket(id);
                loadTickets(); // Refresh the table
            } catch (err) {
                alert("Failed to delete: " + err.message);
            }
        }
        return; // STOP here so we don't trigger the row click below
    }

    // 2. If it wasn't the button, check if it's a row (for navigation)
    const row = e.target.closest("tr");
    if (!row || !row.dataset.id) return;

    window.location.href = `ticket-detail.html?id=${row.dataset.id}`;
});