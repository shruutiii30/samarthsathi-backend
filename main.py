from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt

#uvicorn server:app --reload

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL')
if not mongo_url:
    raise RuntimeError('MONGO_URL not set in environment')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'smart_sathi')]

app = FastAPI()
api_router = APIRouter(prefix="/api")

SECRET_KEY = os.environ.get('JWT_SECRET', 'smartsathi-secret-key-2025')
security = HTTPBearer()

# Models
class UserRegister(BaseModel):
    name: str
    mobile: str
    password: str
    language: str = "hindi"
    gender: Optional[str] = None

class UserLogin(BaseModel):
    mobile: str
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    mobile: str
    language: str
    gender: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class InteractionCreate(BaseModel):
    user_id: str
    topic: str
    input_mode: str  # voice, text, gesture
    completion_time: Optional[float] = None
    steps_done: Optional[int] = None
    videos_watched: Optional[int] = None
    field_data: Optional[dict] = None

class Interaction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    topic: str
    input_mode: str
    completion_time: Optional[float] = None
    steps_done: Optional[int] = None
    videos_watched: Optional[int] = None
    field_data: Optional[dict] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AdminAnalytics(BaseModel):
    total_users: int
    most_viewed_guides: List[dict]
    avg_completion_time: float
    most_used_language: str
    common_input_mode: str
    total_interactions: int

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def create_token(user_id: str, mobile: str) -> str:
    exp = datetime.utcnow() + timedelta(days=7)
    payload = {
        'user_id': user_id,
        'mobile': mobile,
        'exp': int(exp.timestamp())
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user_doc = await db.users.find_one({"id": user_id}, {"password_hash": 0, "_id": 0})
        if not user_doc:
            raise HTTPException(status_code=401, detail="User not found")
        return user_doc
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# Routes
# @api_router.post("/auth/register")
# async def register(user_data: UserRegister):
#     # Check if mobile already exists
#     existing = await db.users.find_one({"mobile": user_data.mobile})
#     if existing:
#         raise HTTPException(status_code=400, detail="Mobile number already registered")
    
#     user = User(
#         name=user_data.name,
#         mobile=user_data.mobile,
#         language=user_data.language,
#         gender=user_data.gender
#     )
    
#     doc = user.model_dump()
#     doc['password_hash'] = hash_password(user_data.password)
#     # store created_at as ISO string for consistency
#     doc['created_at'] = doc['created_at'].isoformat()
    
#     await db.users.insert_one(doc)
    
#     token = create_token(user.id, user.mobile)
#     # return stored document without password
#     user_return = doc.copy()
#     user_return.pop('password_hash', None)
#     return {"token": token, "user": user_return}

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    existing = await db.users.find_one({"mobile": user_data.mobile})
    if existing:
        raise HTTPException(status_code=400, detail="Mobile number already registered")
    
    user = User(
        name=user_data.name,
        mobile=user_data.mobile,
        language=user_data.language,
        gender=user_data.gender
    )
    
    doc = user.model_dump()
    doc['password_hash'] = hash_password(user_data.password)
    doc['created_at'] = doc['created_at'].isoformat()

    # Force MongoDB to use UUID instead of ObjectId
    doc['_id'] = doc['id']

    await db.users.insert_one(doc)

    token = create_token(user.id, user.mobile)

    # clean return object
    user_return = {k: v for k, v in doc.items() if k not in ('password_hash', '_id')}

    return {"token": token, "user": user_return}


@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user_doc = await db.users.find_one({"mobile": credentials.mobile})
    if not user_doc or not verify_password(credentials.password, user_doc.get('password_hash', '')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user_doc['id'], user_doc['mobile'])
    # remove internal fields before returning
    user_safe = {k: v for k, v in user_doc.items() if k not in ('password_hash', '_id')}
    return {"token": token, "user": user_safe}

@api_router.post("/interactions")
async def save_interaction(interaction: InteractionCreate, user=Depends(get_current_user)):
    interaction_obj = Interaction(**interaction.model_dump())
    doc = interaction_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    await db.interactions.insert_one({**doc, "_id": user.id})

    return {"success": True, "interaction_id": interaction_obj.id}

class FormFieldResponse(BaseModel):
    user_id: str
    form_name: str
    field_name: str
    response: str
    language: str
    time_taken: float
    input_mode: str

@api_router.post("/interactions/form-field")
async def save_form_field_response(field_response: FormFieldResponse, user=Depends(get_current_user)):
    doc = field_response.model_dump()
    doc['id'] = str(uuid.uuid4())
    doc['timestamp'] = datetime.now(timezone.utc).isoformat()
    
    await db.form_field_responses.insert_one(doc)
    return {"success": True}

@api_router.get("/interactions/user/{user_id}")
async def get_user_interactions(user_id: str, user=Depends(get_current_user)):
    interactions = await db.interactions.find({"user_id": user_id}, {"_id": 0}).to_list(1000)
    return interactions

@api_router.get("/admin/analytics")
async def get_analytics():
    total_users = await db.users.count_documents({})
    total_interactions = await db.interactions.count_documents({})
    
    # Most viewed guides
    pipeline = [
        {"$group": {"_id": "$topic", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    most_viewed = await db.interactions.aggregate(pipeline).to_list(5)
    most_viewed_guides = [{"topic": item["_id"], "count": item["count"]} for item in most_viewed]
    
    # Average completion time
    avg_pipeline = [
        {"$match": {"completion_time": {"$ne": None}}},
        {"$group": {"_id": None, "avg_time": {"$avg": "$completion_time"}}}
    ]
    avg_result = await db.interactions.aggregate(avg_pipeline).to_list(1)
    avg_completion_time = avg_result[0]["avg_time"] if avg_result else 0
    
    # Most used language
    lang_pipeline = [
        {"$group": {"_id": "$language", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 1}
    ]
    lang_result = await db.users.aggregate(lang_pipeline).to_list(1)
    most_used_language = lang_result[0]["_id"] if lang_result else "hindi"
    
    # Common input mode
    mode_pipeline = [
        {"$group": {"_id": "$input_mode", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 1}
    ]
    mode_result = await db.interactions.aggregate(mode_pipeline).to_list(1)
    common_input_mode = mode_result[0]["_id"] if mode_result else "text"
    
    return AdminAnalytics(
        total_users=total_users,
        most_viewed_guides=most_viewed_guides,
        avg_completion_time=round(avg_completion_time, 2),
        most_used_language=most_used_language,
        common_input_mode=common_input_mode,
        total_interactions=total_interactions
    )

@api_router.get("/admin/export")
async def export_data():
    interactions = await db.interactions.find({}, {"_id": 0}).to_list(10000)
    return {"data": interactions}

# Include router and middleware
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
    