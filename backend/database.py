import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

# Get DB URL from .env or use local default
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")

client = AsyncIOMotorClient(MONGO_URL)
db = client.unisupport_db  # This creates the DB automatically

# Collections (Like Tables)
users_collection = db.get_collection("users")
tickets_collection = db.get_collection("tickets")
comments_collection = db.get_collection("comments")