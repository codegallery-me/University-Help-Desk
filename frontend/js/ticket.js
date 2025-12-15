import { createTicket } from './api.js';

// 1. Security Check: Redirect if not logged in
if (!localStorage.getItem('access_token')) {
    alert("You must be logged in to create a ticket.");
    window.location.href = 'login.html';
}

document.addEventListener("DOMContentLoaded", () => {
    
    const form = document.getElementById("create-ticket-form");

    form.addEventListener("submit", async (e) => {
        // 2. STOP page reload
        e.preventDefault();

        // 3. Collect Data
        const title = document.getElementById("title").value.trim();
        const category = document.getElementById("category").value;
        const description = document.getElementById("description").value.trim();

        if (!title || !category || !description) {
            alert("Please fill in all fields.");
            return;
        }

        const ticketData = {
            title: title,
            category: category,
            description: description
        };

        try {
            // 4. Send Data using our Helper Function
            // (This automatically adds the Token and handles base URL)
            const result = await createTicket(ticketData);

            // 5. Success!
            console.log("Ticket Created:", result);
            alert("Ticket created successfully!");
            window.location.href = "dashboard.html";

        } catch (error) {
            console.error("Failed to create ticket:", error);
            alert("Error: " + error.message);
        }
    });
});