from datetime import datetime
from bson import ObjectId
import json

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, ObjectId):
            return str(obj)
        return super().default(obj)

def oid_str(doc):
    if doc is None:
        return None
    
    new_doc = doc.copy()
    
    # Chuyển tất cả ObjectId thành string
    if "_id" in new_doc:
        new_doc["_id"] = str(new_doc["_id"])
    
    # Chuyển tất cả datetime thành ISO string
    for key, value in new_doc.items():
        if isinstance(value, datetime):
            new_doc[key] = value.isoformat()
        elif isinstance(value, ObjectId):
            new_doc[key] = str(value)
    
    return new_doc

def oid_str_list(docs):
    return [oid_str(d) for d in docs]