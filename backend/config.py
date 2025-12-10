import os
from dotenv import load_dotenv

load_dotenv()

# --- JWT Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "hZiD7df5KHwqd3SHE2cdrRyGahoJ1ArDuGwGNAVxxXS") # CHANGE THIS!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30