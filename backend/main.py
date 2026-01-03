from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List
from bson import ObjectId
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import secrets # to generate random passwords for google users
import os
from dotenv import load_dotenv
from models import UserUpdate
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from pydantic import EmailStr
import pandas as pd
from io import BytesIO
from fastapi.responses import StreamingResponse
from models import TicketFeedback
from models import BulkActionRequest
from bson import Regex
from database import faq_collection
from models import FAQItem
from database import canned_responses_collection
from models import CannedResponse

# Import your DB and Models
from database import users_collection, tickets_collection, comments_collection, audit_collection
from models import (
    UserCreate, UserInDB, UserUpdate,
    TicketCreate, TicketInDB, 
    CommentCreate, CommentInDB, 
    PasswordResetRequest, PasswordResetConfirm
)

# --- CONFIG ---
SECRET_KEY = "CHANGE_THIS_SECRET_KEY" # Make sure this matches config.py if you use it
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI-Mail configuration
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

mail_conf = ConnectionConfig(
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD,
    MAIL_FROM=MAIL_USERNAME,
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

app = FastAPI()

# 1. Load Environment Variables
load_dotenv()

# 2. Get the Client ID securely
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

# Safety Check: Stop server start-up if ID is missing
if not GOOGLE_CLIENT_ID:
    raise ValueError("❌ CRITICAL ERROR: GOOGLE_CLIENT_ID is missing from .env file")

# CORS (Allow Frontend) - must be set immediately after FastAPI()!
origins = [
    "http://localhost",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501",
    "http://localhost:5501",
    "https://university-support.netlify.app",  # Netlify frontend
    "https://university-help-desk.onrender.com" # Render backend (for preflight, if needed)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Or use ["*"] for debugging
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- HELPERS ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await users_collection.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return UserInDB(**user)

# --- AUDIT LOG HELPER ---
async def log_action(action: str, user: UserInDB, details: str, target_id: str = None):
    """
    Records an administrative action in the database.
    """
    log_entry = {
        "action": action,
        "performed_by": user.email,
        "target_id": target_id,
        "details": details,
        "timestamp": datetime.utcnow()
    }
    await audit_collection.insert_one(log_entry)

# AUTH ENDPOINTS

@app.post("/auth/register")
async def register(user: UserCreate):
    """
    Registers a new user (Student or Admin).
    """
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_dict = user.dict()
    user_dict["hashed_password"] = get_password_hash(user_dict.pop("password"))
    
    await users_collection.insert_one(user_dict)
    return {"msg": "User created successfully"}

@app.post("/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Handles user login. MUST return 'role' and 'user_id'.
    """
    user = await users_collection.find_one({"email": form_data.username})
    
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # Create Token
    access_token = create_access_token(
        data={"sub": user["email"], "role": user["role"]}
    )
    
    # Return everything the frontend needs
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "role": user["role"],
        "user_id": str(user["_id"]) 
    }


# TICKET ENDPOINTS


@app.post("/tickets/", response_model=TicketInDB)
async def create_ticket(ticket: TicketCreate, current_user: UserInDB = Depends(get_current_user)):
    ticket_data = ticket.dict()
    ticket_data["owner_id"] = str(current_user.id)
    ticket_data["owner_name"] = current_user.full_name
    ticket_data["status"] = "open"
    ticket_data["created_at"] = datetime.utcnow()

    new_ticket = await tickets_collection.insert_one(ticket_data)
    created_ticket = await tickets_collection.find_one({"_id": new_ticket.inserted_id})
    return TicketInDB(**created_ticket)

@app.get("/tickets/my_tickets", response_model=List[TicketInDB])
async def read_my_tickets(current_user: UserInDB = Depends(get_current_user)):
    tickets = await tickets_collection.find({"owner_id": str(current_user.id)}).to_list(100)
    return tickets

@app.get("/tickets/all", response_model=List[TicketInDB])
async def read_all_tickets(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admins only.")
    tickets = await tickets_collection.find().to_list(100)
    return tickets

@app.get("/tickets/{id}", response_model=TicketInDB)
async def read_ticket(id: str, current_user: UserInDB = Depends(get_current_user)):
    try:
        obj_id = ObjectId(id)
    except:
        raise HTTPException(status_code=400, detail="Invalid Ticket ID format")
    ticket = await tickets_collection.find_one({"_id": obj_id})
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket

@app.patch("/tickets/{id}")
async def update_ticket_status(id: str, status_update: dict, current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only.")
    try:
        obj_id = ObjectId(id)
    except:
        raise HTTPException(status_code=400, detail="Invalid Ticket ID")

    new_status = status_update.get("status")
    if new_status not in ["open", "resolved", "in_progress"]:
         raise HTTPException(status_code=400, detail="Invalid status")

    result = await tickets_collection.update_one({"_id": obj_id}, {"$set": {"status": new_status}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Ticket not found or no change made")
    return {"msg": "Status updated successfully"}

# 📝 AUDIT LOG
    await log_action("UPDATE_STATUS", current_user, f"Changed status to {new_status}", str(obj_id))
    
    return {"msg": "Status updated successfully"}

@app.delete("/tickets/{id}")
async def delete_ticket(id: str, current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only.")
    try:
        obj_id = ObjectId(id)
    except:
        raise HTTPException(status_code=400, detail="Invalid Ticket ID")
    result = await tickets_collection.delete_one({"_id": obj_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return {"msg": "Ticket deleted successfully"}

# 📝 AUDIT LOG
    await log_action("DELETE_TICKET", current_user, "Deleted ticket permanently", str(obj_id))

    return {"msg": "Ticket deleted successfully"}

# COMMENT ENDPOINTS

@app.post("/tickets/{ticket_id}/comments", response_model=CommentInDB)
async def create_comment(ticket_id: str, comment: CommentCreate, current_user: UserInDB = Depends(get_current_user)):
    try:
        t_obj_id = ObjectId(ticket_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid Ticket ID")

    ticket = await tickets_collection.find_one({"_id": t_obj_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    comment_data = comment.dict()
    comment_data["ticket_id"] = ticket_id
    comment_data["owner_id"] = str(current_user.id)
    comment_data["owner_name"] = current_user.full_name
    comment_data["created_at"] = datetime.utcnow()

    new_comment = await comments_collection.insert_one(comment_data)
    created_comment = await comments_collection.find_one({"_id": new_comment.inserted_id})
    return created_comment

@app.get("/tickets/{ticket_id}/comments", response_model=List[CommentInDB])
async def read_comments(ticket_id: str):
    comments = await comments_collection.find({"ticket_id": ticket_id}).to_list(100)
    return comments

@app.post("/auth/google")
async def google_login(token_data: dict):
    """
    Securely verifies Google Token and logs in (or registers) the user.
    """
    token = token_data.get("token")
    
    try:
        # 🛡️ SECURITY STEP 1: Verify the token with Google's servers
        # This checks the signature and ensures the token hasn't been tampered with.
        # It ALSO checks that the 'aud' (audience) matches YOUR_CLIENT_ID.
        idinfo = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )

        # 🛡️ SECURITY STEP 2: Issuer Check
        # Ensure the token really came from Google (accounts.google.com)
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        # 3. Get User Info
        email = idinfo['email']
        name = idinfo.get('name', 'Google User')
        
        # 4. Check Database
        user = await users_collection.find_one({"email": email})

        if not user:
            # Register new user
            # We generate a 32-byte random password so no one can bruteforce it
            random_password = secrets.token_urlsafe(32)
            
            new_user = {
                "email": email,
                "full_name": name,
                "hashed_password": get_password_hash(random_password), 
                "role": "student", 
                "auth_provider": "google"
            }
            result = await users_collection.insert_one(new_user)
            user = await users_collection.find_one({"_id": result.inserted_id})

        # 5. Create JWT (Session Token)
        access_token = create_access_token(
            data={"sub": user["email"], "role": user["role"]}
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user["role"],
            "user_id": str(user["_id"])
        }

    except ValueError as e:
        # Log the error for the admin to see, but give a generic error to the user
        print(f"⚠️ Google Auth Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid Google Token or Security Check Failed"
        )
    
# USER PROFILE ENDPOINTS 

@app.get("/users/me", response_model=UserInDB)
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    """
    Get current user details
    """
    return current_user

@app.patch("/users/me")
async def update_user_me(user_update: UserUpdate, current_user: UserInDB = Depends(get_current_user)):
    """
    Update current user's profile (Name, Phone)
    """
    update_data = {k: v for k, v in user_update.dict().items() if v is not None}
    
    if len(update_data) >= 1:
        await users_collection.update_one(
            {"_id": current_user.id}, 
            {"$set": update_data}
        )
    
    return {"msg": "Profile updated successfully"}


# PASSWORD RESET FLOW

@app.post("/auth/forgot-password")
async def forgot_password(request: PasswordResetRequest):
    user = await users_collection.find_one({"email": request.email})
    if not user:
        # Security: Don't reveal if user exists or not
        return {"msg": "If email exists, a reset link has been sent."}

    # 1. Create a special Reset Token (Valid for 15 mins)
    reset_token = create_access_token(
        data={"sub": user["email"], "type": "reset"}
    )

    # 2. Build the Reset Link (Point to your Frontend)
    # CHANGE THIS URL for Production (e.g., https://university-support.netlify.app)
    base_url = "http://localhost:5501" 
    reset_link = f"{base_url}/frontend/reset-password.html?token={reset_token}"

    # 3. Send Email
    message = MessageSchema(
        subject="Reset Your UniSupport Password",
        recipients=[request.email],
        body=f"""
        <h3>Password Reset Request</h3>
        <p>Click the link below to reset your password. This link expires in 30 minutes.</p>
        <a href="{reset_link}" style="padding: 10px 20px; background: #0d6efd; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
        <p>If you did not request this, please ignore this email.</p>
        """,
        subtype=MessageType.html
    )

    fm = FastMail(mail_conf)
    await fm.send_message(message)

    return {"msg": "If email exists, a reset link has been sent."}

@app.post("/auth/reset-password")
async def reset_password_confirm(data: PasswordResetConfirm):
    try:
        # 1. Verify Token
        payload = jwt.decode(data.token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        token_type = payload.get("type")

        if email is None or token_type != "reset":
            raise HTTPException(status_code=400, detail="Invalid reset token")
        
        # 2. Update Password
        new_hash = get_password_hash(data.new_password)
        await users_collection.update_one(
            {"email": email},
            {"$set": {"hashed_password": new_hash}}
        )
        return {"msg": "Password updated successfully"}

    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    

@app.get("/admin/logs")
async def read_audit_logs(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only.")
    
    logs = await audit_collection.find().sort("timestamp", -1).to_list(100)
    for log in logs:
        log["_id"] = str(log["_id"])
    return logs


# EXPORT ENDPOINT

@app.get("/admin/export/{format}")
async def export_tickets(format: str, current_user: UserInDB = Depends(get_current_user)):
    """
    Exports all tickets as CSV or Excel.
    Format must be 'csv' or 'xlsx'.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only.")

    # 1. Fetch Data
    tickets = await tickets_collection.find().to_list(1000) # Limit to 1000 for safety

    # 2. Convert to Clean Dictionary (Flatten Data)
    data = []
    for t in tickets:
        data.append({
            "Ticket ID": str(t["_id"]),
            "Title": t.get("title", ""),
            "Category": t.get("category", ""),
            "Status": t.get("status", "").upper(),
            "Priority": t.get("priority", "Low"),
            "Owner Name": t.get("owner_name", ""),
            "Owner Email": t.get("owner_email", ""), # Ensure you save this in DB if needed
            "Created At": t.get("created_at", "").strftime("%Y-%m-%d %H:%M:%S") if t.get("created_at") else ""
        })

    # 3. Create DataFrame
    df = pd.DataFrame(data)

    # 4. Generate File
    stream = BytesIO()
    
    if format == "csv":
        df.to_csv(stream, index=False)
        media_type = "text/csv"
        filename = "tickets_report.csv"
        
    elif format == "xlsx":
        # Requires 'openpyxl' installed
        df.to_excel(stream, index=False, engine='openpyxl')
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        filename = "tickets_report.xlsx"
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'csv' or 'xlsx'")

    stream.seek(0) # Reset pointer to start of file

    # 5. Return Download Response
    return StreamingResponse(
        stream, 
        media_type=media_type, 
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.post("/tickets/{ticket_id}/feedback")
async def rate_ticket(ticket_id: str, feedback: TicketFeedback, current_user: UserInDB = Depends(get_current_user)):
    """
    Allows a student to rate a resolved ticket.
    """
    try:
        obj_id = ObjectId(ticket_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid Ticket ID")

    # Fetch Ticket
    ticket = await tickets_collection.find_one({"_id": obj_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    # Security Checks
    # Only the student who owns the ticket can rate it
    if str(ticket["owner_id"]) != str(current_user.id):
         raise HTTPException(status_code=403, detail="You can only rate your own tickets.")
    
    # Can only rate if Resolved
    if ticket["status"] != "resolved":
        raise HTTPException(status_code=400, detail="You can only rate resolved tickets.")

    # Validate Rating
    if not (1 <= feedback.rating <= 5):
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")

    update_data = {
        "rating": feedback.rating,
        "feedback_comment": feedback.comment,
        "rated_at": datetime.utcnow()
    }
    
    await tickets_collection.update_one({"_id": obj_id}, {"$set": update_data})

    return {"msg": "Thank you for your feedback!"}



@app.post("/admin/tickets/bulk")
async def bulk_ticket_action(request: BulkActionRequest, current_user: UserInDB = Depends(get_current_user)):
    """
    Perform actions on multiple tickets at once.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only.")

    # Convert string IDs to ObjectIds
    try:
        object_ids = [ObjectId(tid) for tid in request.ticket_ids]
    except:
        raise HTTPException(status_code=400, detail="Invalid Ticket IDs")

    if not object_ids:
        raise HTTPException(status_code=400, detail="No tickets selected")

    # EXECUTE ACTION
    if request.action == "delete":
        result = await tickets_collection.delete_many({"_id": {"$in": object_ids}})
        count = result.deleted_count
        log_msg = f"Bulk deleted {count} tickets"
        action_type = "BULK_DELETE"

    elif request.action in ["resolve", "open", "in_progress"]:
        # Map frontend action names to DB status if needed, usually same
        status_map = {"resolve": "resolved", "open": "open", "in_progress": "in_progress"}
        new_status = status_map[request.action]
        
        result = await tickets_collection.update_many(
            {"_id": {"$in": object_ids}},
            {"$set": {"status": new_status}}
        )
        count = result.modified_count
        log_msg = f"Bulk updated {count} tickets to {new_status}"
        action_type = "BULK_UPDATE"
    
    else:
        raise HTTPException(status_code=400, detail="Invalid action")

    # 📝 AUDIT LOG (One entry for the whole batch)
    await log_action(action_type, current_user, log_msg, f"{len(object_ids)} items")

    return {"msg": f"Successfully processed {count} tickets."}


@app.get("/faq/search")
async def search_faq(q: str):
    """
    Search for FAQs that match the query string.
    """
    if not q or len(q) < 3:
        return []

    # Case-insensitive search using Regex
    regex_query = {"$regex": q, "$options": "i"}
    
    # Search in Question OR Keywords
    results = await faq_collection.find({
        "$or": [
            {"question": regex_query},
            {"keywords": {"$in": [Regex(q, "i")]}} 
        ]
    }).to_list(5)

    # Convert ObjectId
    for item in results:
        item["_id"] = str(item["_id"])
    
    return results

@app.post("/faq/seed")
async def seed_faqs():
    """
    Run this ONCE to add dummy data for testing.
    """
    sample_data = [
        {
            "question": "How to connect to University Wi-Fi?",
            "answer": "Go to settings, select 'Uni-Secure', and login with your Student ID and Password.",
            "keywords": ["wifi", "internet", "connection", "network"],
            "category": "IT"
        },
        {
            "question": "I forgot my Student Portal Password",
            "answer": "Click 'Forgot Password' on the login page or visit the IT desk in Building A.",
            "keywords": ["password", "login", "access", "account"],
            "category": "IT"
        },
        {
            "question": "Where is the library?",
            "answer": "The main library is located in Block C, 2nd Floor. Open 8 AM - 8 PM.",
            "keywords": ["library", "books", "location"],
            "category": "Facility"
        }
    ]
    await faq_collection.insert_many(sample_data)
    return {"msg": "FAQ data added!"}

@app.post("/admin/canned-responses")
async def create_canned_response(response: CannedResponse, current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    
    await canned_responses_collection.insert_one(response.dict())
    return {"msg": "Response saved"}

@app.get("/admin/canned-responses")
async def get_canned_responses(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
        
    responses = await canned_responses_collection.find().to_list(100)
    # Convert _id to string
    for r in responses:
        r["_id"] = str(r["_id"])
    return responses

@app.delete("/admin/canned-responses/{id}")
async def delete_canned_response(id: str, current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    
    await canned_responses_collection.delete_one({"_id": ObjectId(id)})
    return {"msg": "Deleted"}