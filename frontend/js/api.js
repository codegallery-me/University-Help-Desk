
// ⚙️ CONFIGURATION

const API_BASE_URL = "http://localhost:8000";

/**
 * Automatically adds the JWT Token to every request.
 * Redirects to login if the session expires (401 Error).
 */
async function apiCall(endpoint, method = "GET", data = null) {
    const url = `${API_BASE_URL}${endpoint}`;
    
    // Get Token from Local Storage
    const token = localStorage.getItem("access_token");

    // Set Default Headers
    const headers = {
        "Content-Type": "application/json"
    };

    // Attach Token if it exists
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    //  Configure Request
    const config = {
        method: method,
        headers: headers
    };

    if (data) {
        config.body = JSON.stringify(data);
    }

    try {
        // Execute Request
        const response = await fetch(url, config);

        // Handle 401 Unauthorized (Token Expired)
        if (response.status === 401) {
            console.warn("Session expired. Redirecting to login...");
            localStorage.removeItem("access_token");
            localStorage.removeItem("user_role");
            localStorage.removeItem("user_id");
            window.location.href = "login.html";
            return null;
        }

        //  Handle other errors (400, 500, etc.)
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `Error ${response.status}: ${response.statusText}`);
        }

        //  Return JSON
        // Some endpoints (like DELETE) might return empty bodies
        if (response.status === 204) return true;
        return await response.json();

    } catch (error) {
        console.error("API Error:", error);
        alert(error.message); // Simple alert for students to see errors
        throw error;
    }
}


// AUTHENTICATION MODULE (For Dev 1 & 2)

// frontend/js/api.js - UPDATED LOGIN FUNCTION

export async function login(email, password) {
    // 1. Create a URLSearchParams object to format the data correctly
    const details = new URLSearchParams();
    
    // IMPORTANT: FastAPI OAuth2 expects 'username' for the email field
    details.append('username', email); 
    details.append('password', password); 

    // 2. Send the request
    const response = await fetch(`${API_BASE_URL}/auth/token`, {
        method: "POST",
        // Do NOT set Content-Type: application/json
        // Browser will correctly set Content-Type: application/x-www-form-urlencoded
        body: details 
    });

    if (!response.ok) {
        // Handle common 400 errors from FastAPI (incorrect password, etc.)
        const errorDetail = await response.json();
        throw new Error(errorDetail.detail || "Login failed. Check credentials.");
    }
    
    return await response.json();
}

export async function register(userData) {
    return await apiCall("/auth/register", "POST", userData);
}

export function logout() {
    localStorage.clear();
    window.location.href = "login.html";
}


// TICKET MODULE (For Dev 3, 4, 5, 6)


export async function getMyTickets() {
    return await apiCall("/tickets/my_tickets", "GET");
}

export async function getAllTickets() {
    return await apiCall("/tickets/all", "GET");
}

export async function getTicketById(id) {
    return await apiCall(`/tickets/${id}`, "GET");
}

export async function createTicket(ticketData) {
    // ticketData = { title, description, category }
    return await apiCall("/tickets/", "POST", ticketData);
}

export async function updateTicketStatus(id, status) {
    return await apiCall(`/tickets/${id}`, "PATCH", { status });
}

export async function deleteTicket(id) {
    return await apiCall(`/tickets/${id}`, "DELETE");
}


// COMMENT MODULE (For Dev 7 & 8)


export async function getComments(ticketId) {
    return await apiCall(`/tickets/${ticketId}/comments`, "GET");
}

export async function addComment(ticketId, text) {
    return await apiCall(`/tickets/${ticketId}/comments`, "POST", { text });
}


//  UTILS


// Check if user is logged in (use this at top of protected pages)
export function requireAuth() {
    if (!localStorage.getItem("access_token")) {
        window.location.href = "login.html";
    }
}

// Check if user is Admin (use this for admin.html)
export function requireAdmin() {
    const role = localStorage.getItem("user_role"); //  must save this on login!
    if (role !== "admin") {
        alert("Access Denied: Admins only.");
        window.location.href = "dashboard.html";
    }
}