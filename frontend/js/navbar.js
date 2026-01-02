/**
 * NAVBAR COMPONENT
 * Injects the navigation bar into any page with <div id="navbar-placeholder"></div>
 */

import { logout } from './api.js';

export function loadNavbar() {
    const placeholder = document.getElementById('navbar-placeholder');
    if (!placeholder) return;

    // Check User Role
    const role = localStorage.getItem('user_role'); // 'student' or 'admin'
    const token = localStorage.getItem('access_token');
    
    let links = '';

    // Build Links based on Role
    if (token) {
        // Common Links
        links += `
            <li class="nav-item">
                <a class="nav-link" href="dashboard.html">My Tickets</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="create-ticket.html">Create Ticket</a>
            </li>
        `;

        // Admin Only Links
        if (role === 'admin') {
            links += `
                <li class="nav-item">
                    <a class="nav-link fw-bold text-warning" href="admin.html">Admin Panel</a>
                </li>
            `;
        }

        // Logout Button
        links += `
            <li class="nav-item ms-lg-3">
                <button id="nav-logout-btn" class="btn-logout">Logout</button>
            </li>
        `;
    } else {
        // Guest Links
        links += `
            <li class="nav-item">
                <a class="nav-link" href="login.html">Login</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="register.html">Register</a>
            </li>
        `;
    }

    // The HTML Template (Bootstrap Navbar)
    const navbarHTML = `
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm mb-4">
            <div class="container">
                <a class="navbar-brand fw-bold" href="#">🎓 UniSupport</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav ms-auto">
                        ${links}
                    </ul>
                </div>
            </div>
        </nav>
    `;

    // Inject into page
    placeholder.innerHTML = navbarHTML;

    // Attach Logout Event Listener (if button exists)
    const logoutBtn = document.getElementById('nav-logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            logout();
        });
    }
}