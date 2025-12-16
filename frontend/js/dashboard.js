import { getMyTickets } from './api.js';


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
                    <td colspan="5" class="text-center text-muted">
                        No tickets found
                    </td>
                </tr>`;
            return;
        }

        tickets.forEach(t => {
            tableBody.innerHTML += `
                <tr>
                    <td>${t.id}</td>
                    <td>${t.title}</td>
                    <td>${t.category}</td>
                    <td>
                        <span class="badge bg-${t.status === "Resolved" ? "success" : "danger"}">
                            ${t.status}
                        </span>
                    </td>
                    <td>${t.created_at || "-"}</td>
                </tr>`;
        });

    } catch (err) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-danger">
                    Failed to load tickets
                </td>
            </tr>`;
    }
}

loadTickets();


