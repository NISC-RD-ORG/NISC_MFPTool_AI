from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pathlib import Path
import shutil
import logging
import os
import json
import sqlite3
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# JWT Configuration
SECRET_KEY = "your-secret-key-change-this-in-production"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer()

# Database configuration
DB_PATH = Path(__file__).parent / "mfptool.db"

# Pydantic models
class LoginRequest(BaseModel):
    account: str
    password: str

class UserResponse(BaseModel):
    uid: int
    account: str
    type: int
    name: str

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_account(account: str):
    """Get user by account from database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE account = ?", (account,))
    user = cursor.fetchone()
    conn.close()
    return user

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        account: str = payload.get("sub")
        if account is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_account(account)
    if user is None:
        raise credentials_exception
    return user

def init_database():
    """Initialize database with users table and default admin user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                uid INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                type INTEGER NOT NULL,
                name TEXT NOT NULL
            )
        ''')
        
        # Check if admin user already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE account = 'admin'")
        admin_exists = cursor.fetchone()[0] > 0
        
        if not admin_exists:
            # Insert default admin user
            hashed_password = hash_password("nisc27978831")
            cursor.execute('''
                INSERT INTO users (uid, account, password, type, name)
                VALUES (1, 'admin', ?, 2, '管理者')
            ''', (hashed_password,))
            logger.info("Default admin user created")
        else:
            logger.info("Admin user already exists")
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False

@app.get("/initdb")
async def init_db():
    """Initialize database endpoint"""
    try:
        success = init_database()
        if success:
            # Get user count for verification
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            conn.close()
            
            logger.info("Database initialized successfully")
            return {
                "message": "Database initialized successfully",
                "database_path": str(DB_PATH),
                "user_count": user_count
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to initialize database")
    except Exception as e:
        logger.error(f"Error in init_db endpoint: {e}")
        raise HTTPException(status_code=500, detail=f"Database initialization failed: {str(e)}")

@app.get("/listtools")
async def list_tools(current_user = Depends(get_current_user)):
    """List all tools in hierarchical structure"""
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        if not tools_path.exists():
            return {"tools": [], "message": "Tools directory not found"}
        
        all_tools = []
        # Traverse the new structure: model/category/subcategory/tool
        for model_dir in tools_path.iterdir():
            if not model_dir.is_dir():
                continue
                
            for category_dir in model_dir.iterdir():
                if not category_dir.is_dir():
                    continue
                    
                for subcategory_dir in category_dir.iterdir():
                    if not subcategory_dir.is_dir():
                        continue
                        
                    for tool_dir in subcategory_dir.iterdir():
                        if tool_dir.is_dir():
                            # Check if this directory contains content.md
                            content_file = tool_dir / "content.md"
                            if content_file.exists():
                                tool_path = f"{model_dir.name}/{category_dir.name}/{subcategory_dir.name}/{tool_dir.name}"
                                all_tools.append({
                                    "name": tool_path,
                                    "display_name": f"[{model_dir.name}] {tool_dir.name}",
                                    "model": model_dir.name,
                                    "category": category_dir.name,
                                    "subcategory": subcategory_dir.name,
                                    "tool": tool_dir.name
                                })
        
        logger.info(f"Found {len(all_tools)} tools for user {current_user['account']}")
        return {"tools": all_tools, "count": len(all_tools)}
    except Exception as e:
        logger.error(f"Error listing tools: {e}")
        return {"tools": [], "message": "Error listing tools", "error": str(e)}

@app.get("/hello")
async def get_hello():
    return {"message": "Hello from MFP_Tool 2025/07/11!"}

@app.post("/upload")
async def upload_file(file: UploadFile):
    try:
        files_path = Path(__file__).parent.parent / "files"
        files_path.mkdir(exist_ok=True)
        file_location = files_path / file.filename
        with file_location.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        logger.info(f"File uploaded successfully: {file.filename}")
        return {"filename": file.filename, "message": "File uploaded successfully"}
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return {"message": "File upload failed", "error": str(e)}

@app.get("/gettool/{tool_path:path}")
async def get_tool(tool_path: str, current_user = Depends(get_current_user)):
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        # tool_path should be in format: model/category/subcategory/tool
        full_tool_path = tools_path / tool_path
        
        if not full_tool_path.exists():
            raise HTTPException(status_code=404, detail="Tool not found")
        
        # Read content.md
        content_file = full_tool_path / "content.md"
        if not content_file.exists():
            raise HTTPException(status_code=404, detail="Content file not found")
        
        with content_file.open("r", encoding="utf-8") as f:
            content = f.read()
        
        # Get metadata if exists
        metadata_file = full_tool_path / "metadata.json"
        metadata = {}
        if metadata_file.exists():
            with metadata_file.open("r", encoding="utf-8") as f:
                metadata = json.load(f)
        
        # Get list of images
        images_path = full_tool_path / "image"
        images = []
        if images_path.exists():
            for img_file in images_path.iterdir():
                if img_file.is_file() and img_file.suffix.lower() in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                    images.append(img_file.name)
        
        logger.info(f"Retrieved tool: {tool_path} for user {current_user['account']}")
        return {
            "tool_name": tool_path,
            "content": content,
            "metadata": metadata,
            "images": images
        }
    except Exception as e:
        logger.error(f"Error getting tool {tool_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving tool: {str(e)}")

@app.get("/gettoolimage/{tool_path:path}/{image_name}")
async def get_tool_image(tool_path: str, image_name: str, current_user = Depends(get_current_user)):
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        # tool_path should be in format: model/category/subcategory/tool
        image_path = tools_path / tool_path / "image" / image_name
        
        if not image_path.exists():
            raise HTTPException(status_code=404, detail="Image not found")
        
        return FileResponse(image_path)
    except Exception as e:
        logger.error(f"Error getting image {image_name} for tool {tool_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving image: {str(e)}")

@app.post("/login")
async def login(login_request: LoginRequest):
    """User login endpoint"""
    try:
        user = get_user_by_account(login_request.account)
        if not user or not verify_password(login_request.password, user["password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect account or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["account"]}, expires_delta=access_token_expires
        )
        
        logger.info(f"User {user['account']} logged in successfully")
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "uid": user["uid"],
                "account": user["account"],
                "type": user["type"],
                "name": user["name"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/verify-token")
async def verify_token(current_user = Depends(get_current_user)):
    """Verify JWT token and return user info"""
    return {
        "valid": True,
        "user": {
            "uid": current_user["uid"],
            "account": current_user["account"],
            "type": current_user["type"],
            "name": current_user["name"]
        }
    }

@app.get("/models")
async def list_models(current_user = Depends(get_current_user)):
    """List all available models"""
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        if not tools_path.exists():
            return {"models": [], "message": "Tools directory not found"}
        
        models = []
        for item in tools_path.iterdir():
            if item.is_dir():
                models.append({
                    "name": item.name,
                    "display_name": item.name
                })
        
        logger.info(f"Found {len(models)} models for user {current_user['account']}")
        return {"models": models, "count": len(models)}
    except Exception as e:
        logger.error(f"Error listing models: {e}")
        return {"models": [], "message": "Error listing models", "error": str(e)}

@app.get("/models/{model_name}/categories")
async def list_categories(model_name: str, current_user = Depends(get_current_user)):
    """List categories for a specific model"""
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        model_path = tools_path / model_name
        
        if not model_path.exists():
            raise HTTPException(status_code=404, detail="Model not found")
        
        categories = []
        for item in model_path.iterdir():
            if item.is_dir():
                categories.append({
                    "name": item.name,
                    "display_name": item.name
                })
        
        logger.info(f"Found {len(categories)} categories for model {model_name}")
        return {"categories": categories, "count": len(categories)}
    except Exception as e:
        logger.error(f"Error listing categories for model {model_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving categories: {str(e)}")

@app.get("/models/{model_name}/categories/{category_name}/subcategories")
async def list_subcategories(model_name: str, category_name: str, current_user = Depends(get_current_user)):
    """List subcategories for a specific model and category"""
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        category_path = tools_path / model_name / category_name
        
        if not category_path.exists():
            raise HTTPException(status_code=404, detail="Category not found")
        
        subcategories = []
        for item in category_path.iterdir():
            if item.is_dir():
                subcategories.append({
                    "name": item.name,
                    "display_name": item.name
                })
        
        logger.info(f"Found {len(subcategories)} subcategories for {model_name}/{category_name}")
        return {"subcategories": subcategories, "count": len(subcategories)}
    except Exception as e:
        logger.error(f"Error listing subcategories: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving subcategories: {str(e)}")

@app.get("/models/{model_name}/categories/{category_name}/subcategories/{subcategory_name}/tools")
async def list_tools_in_subcategory(model_name: str, category_name: str, subcategory_name: str, current_user = Depends(get_current_user)):
    """List tools in a specific subcategory"""
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        subcategory_path = tools_path / model_name / category_name / subcategory_name
        
        if not subcategory_path.exists():
            raise HTTPException(status_code=404, detail="Subcategory not found")
        
        tools = []
        for item in subcategory_path.iterdir():
            if item.is_dir():
                # Check if this directory contains content.md
                content_file = item / "content.md"
                if content_file.exists():
                    tools.append({
                        "name": item.name,
                        "display_name": item.name,
                        "path": f"{model_name}/{category_name}/{subcategory_name}/{item.name}"
                    })
        
        logger.info(f"Found {len(tools)} tools in {model_name}/{category_name}/{subcategory_name}")
        return {"tools": tools, "count": len(tools)}
    except Exception as e:
        logger.error(f"Error listing tools: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving tools: {str(e)}")
