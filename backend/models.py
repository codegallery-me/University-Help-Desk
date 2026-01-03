from pydantic import BaseModel, Field, EmailStr, BeforeValidator
from typing import Optional, List
from typing_extensions import Annotated
from datetime import datetime

# 1. Helper to turn ObjectId -> String
PyObjectId = Annotated[str, BeforeValidator(str)]

# --- User Models ---
class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    role: str = "student"  # 'student' or 'admin'

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    hashed_password: str

# --- Ticket Models ---
class TicketCreate(BaseModel):
    title: str
    description: str
    category: str  # 'it', 'facility', 'academic'

class TicketInDB(TicketCreate):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    status: str = "open"
    owner_id: str  # We store the User ID as a string here
    created_at: datetime = Field(default_factory=datetime.utcnow)

# --- Comment Models ---
class CommentCreate(BaseModel):
    text: str

class CommentInDB(CommentCreate):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    ticket_id: str
    owner_id: str
    owner_name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserUpdate(BaseModel):
    full_name: str | None = None
    phone_number: str | None = None

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class TicketFeedback(BaseModel):
    rating: int # 1 to 5
    comment: str | None = None


class BulkActionRequest(BaseModel):
    ticket_ids: List[str]
    action: str  # "resolve", "delete", "open", "in_progress"

class FAQItem(BaseModel):
    question: str
    answer: str
    keywords: List[str] # e.g., ["wifi", "internet", "connection"]
    category: str

class CannedResponse(BaseModel):
    title: str    # e.g., "Wi-Fi Reset"
    content: str  # e.g., "Please go to Settings > Network > Forget..."

class CannedResponseInDB(CannedResponse):
    id: str = Field(alias="_id")