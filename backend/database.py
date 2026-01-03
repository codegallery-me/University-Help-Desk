import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# 1. Load the .env file
load_dotenv()

# 2. Get the MONGO_URI variable
MONGO_URL = os.getenv("MONGO_URI")

# Safety Check: If the variable is missing, warn the developer
if not MONGO_URL:
    print("❌ Error: MONGO_URI is missing from .env file!")

# 3. Connect using the variable
client = AsyncIOMotorClient(MONGO_URL)

db = client.university_help_desk
users_collection = db.users
tickets_collection = db.tickets
comments_collection = db.comments
audit_collection = db["audit_logs"]
faq_collection = db.get_collection("faq")
canned_responses_collection = db.get_collection("canned_responses")