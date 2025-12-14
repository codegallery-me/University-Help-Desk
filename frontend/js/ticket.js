import { createTicket } from "./api.js";

document.addEventListener("DOMContentLoaded", () => {
  const token = localStorage.getItem("access_token");
  if (!token) {
    alert("You must be logged in to view this page.");
    window.location.href = "login.html"; // Send them back to login
    return; // Stop the script
  }

  const form = document.getElementById("create-ticket-form");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();


    // 2️ Collect form data
    const ticketData = {
      title: document.getElementById("title").value.trim(),
      category: document.getElementById("category").value,
      description: document.getElementById("description").value.trim(),
    };

    // 3️ Basic validation
    if (!ticketData.title || !ticketData.category || !ticketData.description) {
      alert("Please fill in all fields.");
      return;
    }

    try {
      // 4️ Call backend API (POST /tickets/)
      const response = await fetch("http://localhost:8000/tickets/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + token,
        },
        body: JSON.stringify(ticketData),
      });

            if (response.ok) {
                alert("Ticket created successfully!");
                window.location.href = "dashboard.html"; // Go back to dashboard
            } else {
                const errorData = await response.json();
                alert("Error: " + (errorData.detail || "Failed to create ticket"));
                
                // If token expired, force logout
                if (response.status === 401) {
                    window.location.href = "login.html";
                }
            }

        } catch (error) {
            console.error("Error:", error);
            alert("Server error. Is the backend running?");
        }
    });
});