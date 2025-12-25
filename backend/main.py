from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List
from bson import ObjectId

# Import your DB and Models
from database import users_collection, tickets_collection, comments_collection
from models import UserCreate, UserInDB, TicketCreate, TicketInDB, CommentCreate, CommentInDB

# --- CONFIG ---
SECRET_KEY = "CHANGE_THIS_SECRET_KEY" # Make sure this matches config.py if you use it
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# CORS (Allow Frontend)
origins = [
    "http://localhost",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "https://university-support.netlify.app",  # Netlify frontend
    "https://university-help-desk.onrender.com" # Render backend (for preflight, if needed)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Use the list above
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- HELPERS ---
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