from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List

# Import your DB and Models
from database import users_collection, tickets_collection, comments_collection
from models import UserCreate, UserInDB, TicketCreate, TicketInDB, CommentCreate, CommentInDB

# --- CONFIG ---
SECRET_KEY = "CHANGE_THIS_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# CORS (Allow Frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For development allow all
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

# --- AUTH ENDPOINTS ---

@app.post("/auth/register")
async def register(user: UserCreate):
    # 1. Check if user exists
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # 2. Hash password & Save
    user_dict = user.dict()
    user_dict["hashed_password"] = get_password_hash(user_dict.pop("password"))
    
    await users_collection.insert_one(user_dict)
    return {"msg": "User created successfully"}

@app.post("/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # Create Token
    access_token = create_access_token(data={"sub": user["email"], "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer", "role": user["role"]}

# --- TICKET ENDPOINTS ---

@app.post("/tickets/", response_model=TicketInDB)
async def create_ticket(ticket: TicketCreate, current_user: UserInDB = Depends(get_current_user)):
    new_ticket = TicketInDB(
        **ticket.dict(),
        owner_id=str(current_user.id) # Link to User
    )
    result = await tickets_collection.insert_one(new_ticket.dict(by_alias=True))
    created_ticket = await tickets_collection.find_one({"_id": result.inserted_id})
    return TicketInDB(**created_ticket)

@app.get("/tickets/my_tickets", response_model=List[TicketInDB])
async def read_my_tickets(current_user: UserInDB = Depends(get_current_user)):
    # Find tickets where owner_id matches current user
    tickets = await tickets_collection.find({"owner_id": str(current_user.id)}).to_list(100)
    return tickets

@app.get("/tickets/all", response_model=List[TicketInDB])
async def read_all_tickets(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    tickets = await tickets_collection.find().to_list(100)
    return tickets

# --- COMMENT ENDPOINTS ---
@app.post("/tickets/{ticket_id}/comments", response_model=CommentInDB)
async def create_comment(ticket_id: str, comment: CommentCreate, current_user: UserInDB = Depends(get_current_user)):
    new_comment = CommentInDB(
        **comment.dict(),
        ticket_id=ticket_id,
        owner_id=str(current_user.id),
        owner_name=current_user.full_name
    )
    await comments_collection.insert_one(new_comment.dict(by_alias=True))
    return new_comment

@app.get("/tickets/{ticket_id}/comments", response_model=List[CommentInDB])
async def get_comments(ticket_id: str):
    comments = await comments_collection.find({"ticket_id": ticket_id}).to_list(100)
    return comments