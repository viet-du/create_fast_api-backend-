from app.database import db
from .utils import oid_str, oid_str_list
from bson import ObjectId
from app.auth import hash_password
from datetime import datetime

async def create_user(username: str, email: str, password: str, role="user"):
    doc = {
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "created_at": datetime.utcnow()
    }
    res = db["users"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return oid_str(doc)

async def get_user_by_username(username: str):
    doc = db["users"].find_one({"username": username})
    return oid_str(doc)

async def get_user_by_id(id_str: str):
    try:
        oid = ObjectId(id_str)
    except:
        return None
    doc = db["users"].find_one({"_id": oid})
    return oid_str(doc)

async def list_users():
    docs = list(db["users"].find({}))
    return oid_str_list(docs)

async def update_user(id_str: str, data: dict):
    if "password" in data and data["password"]:
        data["password_hash"] = hash_password(data.pop("password"))
    update_doc = {k: v for k, v in data.items() if v is not None}

    db["users"].update_one({"_id": ObjectId(id_str)}, {"$set": update_doc})
    return await get_user_by_id(id_str)

async def delete_user(id_str: str):
    result = db["users"].delete_one({"_id": ObjectId(id_str)})
    return result.deleted_count