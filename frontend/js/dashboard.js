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
            const ticketId = t._id?.$oid;
            
            tableBody.innerHTML += `
                <tr data-id="${t.ticket_id}" style="cursor:pointer;">
                    <td>${t.ticket_id}</td>
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

tableBody.addEventListener("click",(e)=>{
    const row=e.target.closest("tr");
    if(!row||!row.dataset.id) return;

    window.location.href= `ticket-detail.html?id=${row.dataset.id}`;
});

