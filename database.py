from pymongo import MongoClient
import time

MONGO_URL = "mongodb://localhost:27017"
DATABASE_NAME = "user_db"

try:
    client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    # Test connection
    client.server_info()
    db = client[DATABASE_NAME]
    print("✅ MongoDB connected successfully")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    db = None

def init_db():
    if db is None:
        print("❌ Cannot initialize database - no connection")
        return
        
    try:
        # Indexes for users collection
        db["users"].create_index("username", unique=True)
        db["users"].create_index("email", unique=True)
        
        # Indexes for refresh tokens
        db["refresh_tokens"].create_index("token", unique=True)
        db["refresh_tokens"].create_index("expires_at", expireAfterSeconds=0)
        
        # Indexes for token blacklist
        db["token_blacklist"].create_index("token", unique=True)
        db["token_blacklist"].create_index("expires_at", expireAfterSeconds=0)
        
        print("✅ Database indexes created successfully")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")