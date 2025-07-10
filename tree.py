from dotenv import load_dotenv
import os
from pathlib import Path

# Adjust this if you ever move admin_user.py into a subfolder
project_root = Path(__file__).resolve().parent
load_dotenv(dotenv_path=project_root / ".env")

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")
from pymongo import MongoClient
client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

print("MongoDB URI:", MONGO_URI)
print("MongoDB DB:", MONGO_DB)
print("Collections:", db.list_collection_names())