# 🚀 Help Desk Platform v2 -- Enterprise Upgrade

![Project Status](https://img.shields.io/badge/status-active-success.svg)
![Python Version](https://img.shields.io/badge/python-3.12-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688.svg)
![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248.svg)

---

## Summary

This PR introduces the **v2 "Enterprise" Upgrade**, significantly
enhancing the platform's security, interactivity, and administrative
capabilities. The system transitions from a basic CRUD application into
a **production-ready Help Desk** with real-time updates, role-based
automation, and analytics.

------------------------------------------------------------------------

## ✨ Key Features Added

### 🔐 Security & Authentication

-   **Google OAuth2**: Secure sign-in using Google Accounts (replaces
    basic local authentication).
-   **Password Reset Flow**: Email-based password reset using SMTP
    (`fastapi-mail`).
-   **Role-Based Access Control (RBAC)**: Strict separation between
    **Student** and **Admin** APIs.

### ⚡ Real-Time Interactivity

-   **WebSockets**: Real-time updates via a WebSocket connection
    manager.
-   **Live Dashboard**: Ticket status changes and new comments appear
    instantly without page refresh.

### 🛠️ Advanced Admin Tools

-   **Audit Logging**: Logs critical Admin actions (e.g., *Deleted
    Ticket #101*) for compliance.
-   **Bulk Actions**: Batch ticket operations (Resolve, Delete, Change
    Status).
-   **Canned Responses**: Save and reuse predefined admin replies.
-   **Data Export**: Download ticket reports as **CSV** or **Excel**.
-   **Department Filtering**: Admin access restricted by department (IT,
    Facility, etc.).

### 📊 Analytics & SLAs

-   **Visual Charts**: Chart.js dashboards:
    -   Ticket Status Distribution
    -   Tickets by Category
-   **SLA Timers**: High-priority tickets show countdowns and pulse red
    when nearing the **4-hour SLA**.

### 💡 User Experience (UX)

-   **Smart Suggestions**: FAQ/self-service recommendations while typing
    ticket subjects.
-   **Feedback System**: Users can rate resolved tickets (1--5 stars)
    and leave reviews.

------------------------------------------------------------------------

## 📦 Technical Changes

### Backend

-   Added `pandas` and `openpyxl` for report generation.
-   Added Google authentication libraries for OAuth2 token verification.
-   Refactored `main.py` to properly serialize MongoDB `ObjectId` values
    and prevent 500 errors.

### Frontend

-   Integrated **Chart.js** via CDN.
-   Refactored `dashboard.js` and `admin.html` to support
    WebSocket-driven updates.

------------------------------------------------------------------------

## 🧪 Testing Instructions

1.  **Google Login**
    -   Sign in or sign up using a Google account.
2.  **Real-Time Updates**
    -   Open the dashboard in two windows (Admin & Student).
    -   Update a ticket in one window and verify instant updates in the
        other.
3.  **SLA Validation**
    -   Create a **High Priority** ticket and observe the SLA countdown
        and warning indicators.
4.  **Export Reports**
    -   Click **Export Report** in the Admin panel and verify CSV/Excel
        downloads.
5.  **Bulk Actions**
    -   Select multiple tickets and apply **Mark Resolved** or other
        bulk actions.

------------------------------------------------------------------------

## ⚠️ Deployment Notes

-   Update the `.env` file with the following variables:

        GOOGLE_CLIENT_ID=your_google_client_id
        MAIL_USERNAME=your_email
        MAIL_PASSWORD=your_email_password

-   Install new dependencies:

    ``` bash
    pip install -r requirements.txt
    ```

------------------------------------------------------------------------

## 📌 Version

**v2 -- Enterprise Edition**


## 📸 Screenshots

| Login Page | Student Dashboard |
|:---:|:---:|
| ![Login Page](screenshots/login.png) | ![Dashboard](screenshots/dashboard.png) |

| Create Ticket | Ticket Details |
|:---:|:---:|
| ![Create Ticket](screenshots/create-ticket.png) | ![Admin Dashboard](screenshots/admin.png) |
## 🚀 Getting Started

---

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites
* Python 3.10+
* MongoDB Account (or local instance)
* Git

### 1. Clone the Repository
```bash
git clone [https://github.com/codegallery-me/University-Help-Desk.git](https://github.com/codegallery-me/University-Help-Desk.git)
cd University-Help-Desk
