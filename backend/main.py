from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pathlib import Path
from urllib.parse import unquote as urldecode
import shutil
import logging
import os
import json
import sqlite3
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt
from contextlib import asynccontextmanager
# from passlib.context import CryptContext  # Commented out due to compatibility issues
from pydantic import BaseModel

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting application...")
    # recreate_admin_user()  # Fix admin user password
    debug_database_users()  # Debug database state
    yield
    # Shutdown
    logger.info("Shutting down application...")

app = FastAPI(lifespan=lifespan)

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

# Password hashing using bcrypt directly
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password_bcrypt(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash using bcrypt"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

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

class UserCreateRequest(BaseModel):
    account: str
    password: str
    type: int
    name: str

class UserUpdateRequest(BaseModel):
    account: str = None
    password: str = None
    type: int = None
    name: str = None

class ToolEditRequest(BaseModel):
    content: str

class FileRequest(BaseModel):
    file_path: str

class FileSaveRequest(BaseModel):
    file_path: str
    content: str

class CategoryCreateRequest(BaseModel):
    name: str
    display_name: str
    description: str = ""
    parent_path: str = ""

class ToolCreateRequest(BaseModel):
    name: str
    display_name: str
    description: str
    category: str = ""
    tags: list[str] = []
    content: str
    parent_path: str = ""

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_password_hash(password: str) -> str:
    """Hash password using bcrypt"""
    return hash_password(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using bcrypt"""
    try:
        logger.info(f"Verifying password... Plain length: {len(plain_password)}, Hash: {hashed_password[:20]}...")
        result = bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        logger.info(f"Password verification result: {result}")
        return result
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def debug_database_users():
    """Debug function to check database users"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT account, password, type FROM users")
        users = cursor.fetchall()
        conn.close()
        
        logger.info("=== DATABASE USERS DEBUG ===")
        for account, password_hash, user_type in users:
            logger.info(f"User: {account}, Type: {user_type}, Hash: {password_hash[:20]}...")
            
            # Test password verification
            test_password = "admin123" if account == "admin" else "unknown"
            is_valid = bcrypt.checkpw(test_password.encode('utf-8'), password_hash.encode('utf-8'))
            logger.info(f"  Testing password '{test_password}': {is_valid}")
        
        return users
    except Exception as e:
        logger.error(f"Database debug error: {e}")
        return []

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create JWT access token"""
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
        logger.info(f"Attempting to decode JWT token")
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        account: str = payload.get("sub")
        logger.info(f"JWT decoded successfully, account: {account}")
        
        if account is None:
            logger.error("No account found in JWT payload")
            raise credentials_exception
            
    except JWTError as e:
        logger.error(f"JWT decode error: {e}")
        raise credentials_exception
    except Exception as e:
        logger.error(f"Unexpected error in JWT processing: {e}")
        raise credentials_exception
    
    user = get_user_by_account(account)
    if user is None:
        logger.error(f"User not found in database: {account}")
        raise credentials_exception
        
    logger.info(f"User authenticated successfully: {account}")
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

def get_tools_path():
    """Get tools directory path with fallback logic"""
    # First try external data path
    external_tools_path = Path("/home/user/NISC_MFPTool_Data") / "tools"
    if external_tools_path.exists():
        return external_tools_path
    
    # Fallback to local tools directory
    local_tools_path = Path(__file__).parent.parent / "tools"
    return local_tools_path

@app.get("/listtools")
async def list_tools(current_user = Depends(get_current_user)):
    """List all tools in hierarchical structure"""
    try:
        logger.info(f"User {current_user['account']} requesting tools list")
        tools_path = get_tools_path()
        if not tools_path.exists():
            logger.warning(f"Tools directory not found: {tools_path}")
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
    except HTTPException:
        # Re-raise HTTP exceptions (like 401)
        raise
    except Exception as e:
        logger.error(f"Error listing tools: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing tools: {str(e)}")

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
        tools_path = get_tools_path()
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
async def get_tool_image(tool_path: str, image_name: str):
    """Get tool image by tool path and image name"""
    try:
        # URL decode the parameters
        tool_path = urldecode(tool_path)
        image_name = urldecode(image_name)
        
        logger.info(f"Getting image: {image_name} for tool path: {tool_path}")
        
        tools_path = get_tools_path()
        
        # Construct the full image path: tools/model/category/subcategory/tool/image/image_name
        image_path = tools_path / tool_path / "image" / image_name
        
        logger.info(f"Looking for image at: {image_path}")
        
        if not image_path.exists():
            logger.error(f"Image not found: {image_path}")
            raise HTTPException(status_code=404, detail=f"Image not found: {image_path}")
        
        return FileResponse(image_path)
        
    except Exception as e:
        logger.error(f"Error getting image {image_name} for tool {tool_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving image: {str(e)}")
    
@app.post("/login")
async def login(login_request: LoginRequest):
    """User login endpoint"""
    try:
        logger.info(f"Login attempt for account: {login_request.account}")
        
        user = get_user_by_account(login_request.account)
        if not user:
            logger.warning(f"User not found: {login_request.account}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect account or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        logger.info(f"User found: {user['account']}, checking password...")
        
        password_valid = verify_password(login_request.password, user["password"])
        logger.info(f"Password verification result: {password_valid}")
        
        if not password_valid:
            logger.warning(f"Invalid password for user: {login_request.account}")
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
        tools_path = get_tools_path()
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
        tools_path = get_tools_path()
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
        tools_path = get_tools_path()
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
        tools_path = get_tools_path()
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

@app.get("/browse")
async def browse_dynamic_structure(path: str = "", current_user = Depends(get_current_user)):
    """
    Browse dynamic directory structure - returns both subcategories and tools at any level
    
    Args:
        path: Relative path from tools directory (e.g., 'TaskalfaC3253' or 'TaskalfaC3253/4-10定期保養步驟')
        
    Returns:
        - items: Combined list of subcategories and tools
        - current_path: Current directory path
        - breadcrumbs: Navigation breadcrumbs
        - parent_path: Path to parent directory (null if at root)
    """
    try:
        tools_path = get_tools_path()
        
        # Parse and validate the path
        if path:
            current_path = tools_path / path
            path_parts = Path(path).parts
        else:
            current_path = tools_path
            path_parts = ()
        
        if not current_path.exists() or not current_path.is_dir():
            raise HTTPException(status_code=404, detail="Path not found")
        
        # Build breadcrumbs for navigation
        breadcrumbs = []
        breadcrumb_path = ""
        
        for i, part in enumerate(path_parts):
            if i == 0:
                breadcrumb_path = part
            else:
                breadcrumb_path = f"{breadcrumb_path}/{part}"
            
            breadcrumbs.append({
                "name": part,
                "display_name": part,
                "path": breadcrumb_path
            })
        
        # Get parent path
        parent_path = None
        if path_parts:
            if len(path_parts) == 1:
                parent_path = ""
            else:
                parent_path = "/".join(path_parts[:-1])
        
        # Scan current directory for items
        items = []
        
        for item in current_path.iterdir():
            if not item.is_dir():
                continue
            
            # Check if this directory contains content.md (making it a tool)
            content_file = item / "content.md"
            
            if content_file.exists():
                # This is a tool
                item_path = f"{path}/{item.name}" if path else item.name
                
                # Try to read metadata for display name
                metadata_file = item / "metadata.json"
                display_name = item.name
                
                try:
                    if metadata_file.exists():
                        with open(metadata_file, 'r', encoding='utf-8') as f:
                            metadata = json.load(f)
                            display_name = metadata.get('display_name', item.name)
                except Exception as e:
                    logger.warning(f"Error reading metadata for {item}: {e}")
                
                items.append({
                    "name": item.name,
                    "display_name": display_name,
                    "type": "tool",
                    "path": item_path,
                    "is_tool": True
                })
            else:
                # This is a subcategory - count tools in it recursively
                item_path = f"{path}/{item.name}" if path else item.name
                tool_count = count_tools_recursive(item)
                
                items.append({
                    "name": item.name,
                    "display_name": item.name,
                    "type": "category",
                    "path": item_path,
                    "is_tool": False,
                    "tool_count": tool_count
                })
        
        # Sort items: categories first, then tools, both alphabetically
        items.sort(key=lambda x: (x["is_tool"], x["name"]))
        
        result = {
            "items": items,
            "current_path": path,
            "breadcrumbs": breadcrumbs,
            "parent_path": parent_path,
            "count": len(items)
        }
        
        logger.info(f"Browse path '{path}' returned {len(items)} items")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error browsing path '{path}': {e}")
        raise HTTPException(status_code=500, detail=f"Error browsing path: {str(e)}")

def count_tools_recursive(directory_path: Path) -> int:
    """Recursively count tools (directories with content.md) in a directory"""
    try:
        count = 0
        for item in directory_path.iterdir():
            if not item.is_dir():
                continue
            
            content_file = item / "content.md"
            if content_file.exists():
                count += 1
            else:
                # Recursively count in subdirectories
                count += count_tools_recursive(item)
        
        return count
    except Exception as e:
        logger.warning(f"Error counting tools in {directory_path}: {e}")
        return 0

@app.get("/search")
async def search_tools(q: str, current_user = Depends(get_current_user)):
    """Search tools across all models and categories using dynamic structure"""
    try:
        if not q or len(q.strip()) < 1:
            return {"results": [], "count": 0}
        
        query = q.strip().lower()
        tools_path = get_tools_path()
        results = []
        
        # Recursively search through all directories
        def search_directory(current_dir: Path, relative_path: str = ""):
            """Recursively search for tools in directory structure"""
            try:
                for item in current_dir.iterdir():
                    if not item.is_dir():
                        continue
                    
                    item_relative_path = f"{relative_path}/{item.name}" if relative_path else item.name
                    content_file = item / "content.md"
                    
                    if content_file.exists():
                        # This is a tool
                        tool_name = item.name
                        
                        # Check if query matches tool name (case insensitive)
                        if query in tool_name.lower():
                            # Build breadcrumb path for display
                            path_parts = item_relative_path.split("/")
                            breadcrumb_display = " > ".join(path_parts[:-1]) if len(path_parts) > 1 else "根目錄"
                            
                            # Try to get display name from metadata
                            display_name = tool_name
                            try:
                                metadata_file = item / "metadata.json"
                                if metadata_file.exists():
                                    with open(metadata_file, 'r', encoding='utf-8') as f:
                                        metadata = json.load(f)
                                        display_name = metadata.get('display_name', tool_name)
                            except Exception:
                                pass
                            
                            results.append({
                                "name": tool_name,
                                "display_name": display_name,
                                "path": item_relative_path,
                                "path_display": breadcrumb_display,
                                "type": "tool",
                                "match_type": "name"
                            })
                        
                        # Also search in content.md file for comprehensive search
                        else:
                            try:
                                with open(content_file, 'r', encoding='utf-8') as f:
                                    content = f.read().lower()
                                    if query in content:
                                        path_parts = item_relative_path.split("/")
                                        breadcrumb_display = " > ".join(path_parts[:-1]) if len(path_parts) > 1 else "根目錄"
                                        
                                        # Try to get display name from metadata
                                        display_name = tool_name
                                        try:
                                            metadata_file = item / "metadata.json"
                                            if metadata_file.exists():
                                                with open(metadata_file, 'r', encoding='utf-8') as f:
                                                    metadata = json.load(f)
                                                    display_name = metadata.get('display_name', tool_name)
                                        except Exception:
                                            pass
                                        
                                        results.append({
                                            "name": tool_name,
                                            "display_name": display_name,
                                            "path": item_relative_path,
                                            "path_display": breadcrumb_display,
                                            "type": "tool",
                                            "match_type": "content"
                                        })
                            except Exception as e:
                                logger.warning(f"Error reading content file {content_file}: {e}")
                    else:
                        # This is a category, continue searching recursively
                        search_directory(item, item_relative_path)
                        
            except Exception as e:
                logger.warning(f"Error searching directory {current_dir}: {e}")
        
        # Start searching from tools root
        search_directory(tools_path)
        
        # Remove duplicates based on path
        seen_paths = set()
        unique_results = []
        for result in results:
            if result["path"] not in seen_paths:
                seen_paths.add(result["path"])
                unique_results.append(result)
                
        # Sort results: name matches first, then content matches, both alphabetically
        unique_results.sort(key=lambda x: (x["match_type"] != "name", x["display_name"]))
        
        # Limit to 20 results to avoid overwhelming the UI
        limited_results = unique_results[:20]
        
        logger.info(f"Search for '{q}' found {len(limited_results)} results")
        return {"results": limited_results, "count": len(limited_results), "query": q}
        
    except Exception as e:
        logger.error(f"Error searching tools: {e}")
        raise HTTPException(status_code=500, detail=f"Search error: {str(e)}")

@app.put("/edittool/{tool_path:path}")
async def edit_tool(tool_path: str, edit_request: ToolEditRequest, current_user = Depends(get_current_user)):
    """Edit tool content (Admin only)"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin permission required"
            )
        
        tools_path = get_tools_path()
        full_tool_path = tools_path / tool_path
        
        if not full_tool_path.exists():
            raise HTTPException(status_code=404, detail="Tool not found")
        
        # Write content to content.md
        content_file = full_tool_path / "content.md"
        
        # Create backup before editing
        backup_file = full_tool_path / f"content.md.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if content_file.exists():
            shutil.copy2(content_file, backup_file)
        
        with content_file.open("w", encoding="utf-8") as f:
            f.write(edit_request.content)
        
        logger.info(f"Tool {tool_path} edited by admin {current_user['account']}")
        return {
            "message": "Tool content updated successfully",
            "tool_path": tool_path,
            "backup_created": str(backup_file)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error editing tool {tool_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error editing tool: {str(e)}")

# User Management APIs (Admin only)
def check_admin_permission(current_user):
    """Check if current user has admin permission (type=2)"""
    if current_user["type"] != 2:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required"
        )

@app.get("/admin/users")
async def list_users(current_user = Depends(get_current_user)):
    """List all users (Admin only)"""
    try:
        check_admin_permission(current_user)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT uid, account, type, name FROM users ORDER BY uid")
        users = cursor.fetchall()
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append({
                "uid": user["uid"],
                "account": user["account"],
                "type": user["type"],
                "name": user["name"]
            })
        
        logger.info(f"Admin {current_user['account']} listed {len(users_list)} users")
        return {"users": users_list, "count": len(users_list)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving users: {str(e)}")

@app.post("/admin/users")
async def create_user(user_data: UserCreateRequest, current_user = Depends(get_current_user)):
    """Create new user (Admin only)"""
    try:
        check_admin_permission(current_user)
        
        # Check if user already exists
        existing_user = get_user_by_account(user_data.account)
        if existing_user:
            raise HTTPException(status_code=400, detail="User account already exists")
        
        # Hash password
        hashed_password = hash_password(user_data.password)
        
        # Insert new user
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (account, password, type, name)
            VALUES (?, ?, ?, ?)
        ''', (user_data.account, hashed_password, user_data.type, user_data.name))
        
        new_user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Admin {current_user['account']} created user: {user_data.account}")
        return {
            "message": "User created successfully",
            "user": {
                "uid": new_user_id,
                "account": user_data.account,
                "type": user_data.type,
                "name": user_data.name
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")

@app.put("/admin/users/{user_id}")
async def update_user(user_id: int, user_data: UserUpdateRequest, current_user = Depends(get_current_user)):
    """Update user (Admin only)"""
    try:
        check_admin_permission(current_user)
        
        # Check if user exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE uid = ?", (user_id,))
        existing_user = cursor.fetchone()
        
        if not existing_user:
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")
        
        # Build update query dynamically
        update_fields = []
        update_values = []
        
        if user_data.account is not None:
            # Check if new account already exists (excluding current user)
            cursor.execute("SELECT uid FROM users WHERE account = ? AND uid != ?", (user_data.account, user_id))
            if cursor.fetchone():
                conn.close()
                raise HTTPException(status_code=400, detail="Account already exists")
            update_fields.append("account = ?")
            update_values.append(user_data.account)
        
        if user_data.password is not None:
            update_fields.append("password = ?")
            update_values.append(hash_password(user_data.password))
        
        if user_data.type is not None:
            update_fields.append("type = ?")
            update_values.append(user_data.type)
        
        if user_data.name is not None:
            update_fields.append("name = ?")
            update_values.append(user_data.name)
        
        if not update_fields:
            conn.close()
            raise HTTPException(status_code=400, detail="No fields to update")
        
        # Execute update
        update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE uid = ?"
        update_values.append(user_id)
        cursor.execute(update_query, update_values)
        conn.commit()
        
        # Get updated user
        cursor.execute("SELECT uid, account, type, name FROM users WHERE uid = ?", (user_id,))
        updated_user = cursor.fetchone()
        conn.close()
        
        logger.info(f"Admin {current_user['account']} updated user ID: {user_id}")
        return {
            "message": "User updated successfully",
            "user": {
                "uid": updated_user["uid"],
                "account": updated_user["account"],
                "type": updated_user["type"],
                "name": updated_user["name"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        raise HTTPException(status_code=500, detail=f"Error updating user: {str(e)}")

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: int, current_user = Depends(get_current_user)):
    """Delete user (Admin only)"""
    try:
        check_admin_permission(current_user)
        
        # Check if user exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT account FROM users WHERE uid = ?", (user_id,))
        user_to_delete = cursor.fetchone()
        
        if not user_to_delete:
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")
        
        # Prevent deleting self
        if user_id == current_user["uid"]:
            conn.close()
            raise HTTPException(status_code=400, detail="Cannot delete your own account")
        
        # Delete user
        cursor.execute("DELETE FROM users WHERE uid = ?", (user_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"Admin {current_user['account']} deleted user: {user_to_delete['account']}")
        return {"message": "User deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting user: {str(e)}")

@app.get("/admin/users/{user_id}")
async def get_user(user_id: int, current_user = Depends(get_current_user)):
    """Get user details (Admin only)"""
    try:
        check_admin_permission(current_user)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT uid, account, type, name FROM users WHERE uid = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
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
        logger.error(f"Error getting user: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving user: {str(e)}")

# Tool and Category Management APIs (Admin only)
@app.delete("/admin/tools/{tool_path:path}")
async def delete_tool(tool_path: str, current_user = Depends(get_current_user)):
    """Delete a tool (Admin only)"""
    try:
        check_admin_permission(current_user)
        
        tools_path = get_tools_path()
        full_tool_path = tools_path / tool_path
        
        if not full_tool_path.exists():
            raise HTTPException(status_code=404, detail="Tool not found")
        
        # Check if it's actually a tool (has content.md)
        content_file = full_tool_path / "content.md"
        if not content_file.exists():
            raise HTTPException(status_code=400, detail="Path is not a tool")
        
        # Create backup before deletion
        backup_dir = tools_path / "deleted_backups" / datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        tool_name = full_tool_path.name
        backup_path = backup_dir / tool_name
        
        # Copy tool to backup location
        shutil.copytree(full_tool_path, backup_path)
        
        # Delete the tool directory
        shutil.rmtree(full_tool_path)
        
        logger.info(f"Admin {current_user['account']} deleted tool: {tool_path}")
        return {
            "message": "Tool deleted successfully",
            "tool_path": tool_path,
            "backup_location": str(backup_path)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting tool {tool_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting tool: {str(e)}")

@app.delete("/admin/categories/{category_path:path}")
async def delete_empty_category(category_path: str, current_user = Depends(get_current_user)):
    """Delete an empty category/subcategory (Admin only)"""
    try:
        check_admin_permission(current_user)
        
        tools_path = get_tools_path()
        full_category_path = tools_path / category_path
        
        if not full_category_path.exists():
            raise HTTPException(status_code=404, detail="Category not found")
        
        if not full_category_path.is_dir():
            raise HTTPException(status_code=400, detail="Path is not a directory")
        
        # Check if category is empty (no tools or subcategories)
        has_content = False
        for item in full_category_path.iterdir():
            if item.is_dir():
                # Check if this is a tool (has content.md) or has any content
                content_file = item / "content.md"
                if content_file.exists():
                    has_content = True
                    break
                # Check if subdirectory has any content recursively
                if any(subitem.is_dir() for subitem in item.iterdir()):
                    has_content = True
                    break
                # Check if subdirectory has any tools
                if has_tools_recursive(item):
                    has_content = True
                    break
        
        if has_content:
            raise HTTPException(
                status_code=400, 
                detail="Category is not empty. Please delete all tools and subcategories first."
            )
        
        # Create backup before deletion
        backup_dir = tools_path / "deleted_backups" / datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        category_name = full_category_path.name
        backup_path = backup_dir / f"category_{category_name}"
        
        # Copy category to backup location
        shutil.copytree(full_category_path, backup_path)
        
        # Delete the category directory
        shutil.rmtree(full_category_path)
        
        logger.info(f"Admin {current_user['account']} deleted empty category: {category_path}")
        return {
            "message": "Empty category deleted successfully",
            "category_path": category_path,
            "backup_location": str(backup_path)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting category {category_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting category: {str(e)}")

def has_tools_recursive(directory_path: Path) -> bool:
    """Recursively check if a directory contains any tools"""
    try:
        for item in directory_path.iterdir():
            if not item.is_dir():
                continue
            
            content_file = item / "content.md"
            if content_file.exists():
                return True
            
            # Recursively check subdirectories
            if has_tools_recursive(item):
                return True
        
        return False
    except Exception as e:
        logger.warning(f"Error checking tools in {directory_path}: {e}")
        return True  # Assume has content if error occurs for safety

@app.get("/admin/category-info/{category_path:path}")
async def get_category_info(category_path: str, current_user = Depends(get_current_user)):
    """Get information about a category for deletion purposes (Admin only)"""
    try:
        check_admin_permission(current_user)
        
        tools_path = get_tools_path()
        full_category_path = tools_path / category_path
        
        if not full_category_path.exists():
            raise HTTPException(status_code=404, detail="Category not found")
        
        if not full_category_path.is_dir():
            raise HTTPException(status_code=400, detail="Path is not a directory")
        
        # Count tools and subcategories
        tool_count = 0
        subcategory_count = 0
        items = []
        
        for item in full_category_path.iterdir():
            if not item.is_dir():
                continue
            
            content_file = item / "content.md"
            if content_file.exists():
                # This is a tool
                tool_count += 1
                items.append({
                    "name": item.name,
                    "type": "tool",
                    "path": f"{category_path}/{item.name}"
                })
            else:
                # This is a subcategory
                subcategory_count += 1
                sub_tool_count = count_tools_recursive(item)
                items.append({
                    "name": item.name,
                    "type": "category",
                    "path": f"{category_path}/{item.name}",
                    "tool_count": sub_tool_count
                })
        
        is_empty = tool_count == 0 and subcategory_count == 0
        can_delete = is_empty
        
        return {
            "category_path": category_path,
            "is_empty": is_empty,
            "can_delete": can_delete,
            "tool_count": tool_count,
            "subcategory_count": subcategory_count,
            "items": items,
            "total_items": len(items)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting category info {category_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting category info: {str(e)}")

def recreate_admin_user():
    """Recreate admin user with correct password hash"""
    try:
        logger.info("Recreating admin user...")
        
        # Generate new hash for admin123
        new_hash = hash_password("admin123")
        logger.info(f"Generated new hash for admin123: {new_hash[:20]}...")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete existing admin user
        cursor.execute("DELETE FROM users WHERE account = ?", ("admin",))
        
        # Insert new admin user
        cursor.execute(
            "INSERT INTO users (account, password, type, name) VALUES (?, ?, ?, ?)",
            ("admin", new_hash, 2, "Administrator")
        )
        
        conn.commit()
        conn.close()
        
        logger.info("Admin user recreated successfully")
        
        # Test the new hash
        test_result = bcrypt.checkpw("admin123".encode('utf-8'), new_hash.encode('utf-8'))
        logger.info(f"Testing new hash: {test_result}")
        
    except Exception as e:
        logger.error(f"Error recreating admin user: {e}")

# File operations endpoints
@app.post("/api/get-file")
async def get_file(request: FileRequest, current_user = Depends(get_current_user)):
    """Get file content"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:  # Only admin can access
            raise HTTPException(status_code=403, detail="Admin access required")
        
        file_path = request.file_path
        logger.info(f"Requested file path: {file_path}")
        
        # Parse the path - expect format like "tool_path/filename.ext"
        if '/' in file_path:
            tool_path, filename = file_path.rsplit('/', 1)
        else:
            raise HTTPException(status_code=400, detail="Invalid file path format")
        
        # Use the same path resolution as gettool endpoint
        tools_path = get_tools_path()
        full_tool_path = tools_path / tool_path
        
        logger.info(f"Tool path: {tool_path}")
        logger.info(f"Full tool path: {full_tool_path}")
        logger.info(f"Filename: {filename}")
        
        if not full_tool_path.exists():
            raise HTTPException(status_code=404, detail="Tool directory not found")
        
        full_file_path = full_tool_path / filename
        logger.info(f"Full file path: {full_file_path}")
        logger.info(f"File exists check: {full_file_path.exists()}")
        
        if not full_file_path.exists():
            # For metadata.json, create a default template if it doesn't exist
            if filename == 'metadata.json':
                default_metadata = {
                    "display_name": "",
                    "description": "",
                    "category": "",
                    "tags": [],
                    "version": "1.0",
                    "last_modified": datetime.now().isoformat()
                }
                content = json.dumps(default_metadata, ensure_ascii=False, indent=2)
                return {"success": True, "content": content, "created_default": True}
            else:
                return {"success": False, "error": "File not found"}
        
        with open(full_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return {"success": True, "content": content}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error reading file {request.file_path}: {e}")
        return {"success": False, "error": str(e)}

@app.post("/api/save-file")  
async def save_file(request: FileSaveRequest, current_user = Depends(get_current_user)):
    """Save file content"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:  # Only admin can access
            raise HTTPException(status_code=403, detail="Admin access required")
        
        file_path = request.file_path
        
        # Parse the path - expect format like "tool_path/filename.ext"
        if '/' in file_path:
            tool_path, filename = file_path.rsplit('/', 1)
        else:
            raise HTTPException(status_code=400, detail="Invalid file path format")
        
        # Use the same path resolution as gettool endpoint
        tools_path = get_tools_path()
        full_tool_path = tools_path / tool_path
        
        if not full_tool_path.exists():
            raise HTTPException(status_code=404, detail="Tool directory not found")
        
        full_file_path = full_tool_path / filename
        
        # Create backup before saving if file exists
        if full_file_path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = full_tool_path / f"{filename}.backup_{timestamp}"
            shutil.copy2(full_file_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
        
        # Save the file
        with open(full_file_path, 'w', encoding='utf-8') as f:
            f.write(request.content)
        
        logger.info(f"File saved by admin user {current_user['uid']}: {full_file_path}")
        return {"success": True, "message": "File saved successfully"}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error saving file {request.file_path}: {e}")
        return {"success": False, "error": str(e)}

@app.post("/admin/categories")
async def create_category(request: CategoryCreateRequest, current_user = Depends(get_current_user)):
    """Create a new category"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        tools_path = get_tools_path()
        
        # Build the full path
        if request.parent_path:
            parent_path = tools_path / request.parent_path
        else:
            parent_path = tools_path
        
        if not parent_path.exists():
            raise HTTPException(status_code=404, detail="Parent path not found")
        
        # Create the new category directory
        new_category_path = parent_path / request.name
        
        if new_category_path.exists():
            raise HTTPException(status_code=400, detail="Category already exists")
        
        new_category_path.mkdir(parents=True, exist_ok=False)
        
        # Create a metadata.json file for the category
        metadata = {
            "type": "category",
            "name": request.name,
            "display_name": request.display_name,
            "description": request.description,
            "created_at": datetime.now().isoformat(),
            "created_by": current_user["uid"]
        }
        
        metadata_path = new_category_path / "metadata.json"
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Category created by admin user {current_user['uid']}: {new_category_path}")
        return {"success": True, "message": "Category created successfully", "path": str(new_category_path.relative_to(tools_path))}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error creating category: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create category: {str(e)}")

@app.post("/admin/tools")
async def create_tool(request: ToolCreateRequest, current_user = Depends(get_current_user)):
    """Create a new tool"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        tools_path = get_tools_path()
        
        # Build the full path
        if request.parent_path:
            parent_path = tools_path / request.parent_path
        else:
            parent_path = tools_path
        
        if not parent_path.exists():
            raise HTTPException(status_code=404, detail="Parent path not found")
        
        # Create the new tool directory
        new_tool_path = parent_path / request.name
        
        if new_tool_path.exists():
            raise HTTPException(status_code=400, detail="Tool already exists")
        
        new_tool_path.mkdir(parents=True, exist_ok=False)
        
        # Create the image directory
        image_path = new_tool_path / "image"
        image_path.mkdir(exist_ok=True)
        
        # Create content.md file
        content_path = new_tool_path / "content.md"
        with open(content_path, 'w', encoding='utf-8') as f:
            f.write(request.content)
        
        # Create metadata.json file
        metadata = {
            "type": "tool",
            "name": request.name,
            "display_name": request.display_name,
            "description": request.description,
            "category": request.category,
            "tags": request.tags,
            "version": "1.0.0",
            "created_at": datetime.now().isoformat(),
            "created_by": current_user["uid"],
            "last_modified": datetime.now().isoformat(),
            "last_modified_by": current_user["uid"]
        }
        
        metadata_path = new_tool_path / "metadata.json"
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Tool created by admin user {current_user['uid']}: {new_tool_path}")
        return {"success": True, "message": "Tool created successfully", "path": str(new_tool_path.relative_to(tools_path))}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error creating tool: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create tool: {str(e)}")

@app.get("/admin/tool-images/{tool_path:path}")
async def get_tool_images(tool_path: str, current_user = Depends(get_current_user)):
    """Get list of images in a tool's image directory"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        tools_path = get_tools_path()
        tool_dir = tools_path / tool_path
        image_dir = tool_dir / "image"
        
        if not tool_dir.exists():
            raise HTTPException(status_code=404, detail="Tool not found")
        
        if not image_dir.exists():
            return {"images": []}
        
        images = []
        for file_path in image_dir.iterdir():
            if file_path.is_file() and file_path.suffix.lower() in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
                images.append({
                    "name": file_path.name,
                    "size": file_path.stat().st_size,
                    "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                })
        
        # Sort by name
        images.sort(key=lambda x: x["name"])
        
        return {"images": images}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error getting tool images: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get tool images: {str(e)}")

@app.post("/admin/upload-tool-image")
async def upload_tool_image(file: UploadFile = File(...), current_user = Depends(get_current_user)):
    """Upload an image to a tool's image directory"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Validate file type
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")
        
        # Validate file extension
        file_ext = Path(file.filename).suffix.lower()
        if file_ext not in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            raise HTTPException(status_code=400, detail="Unsupported image format")
        
        return {"success": True, "message": "Image uploaded successfully", "filename": file.filename}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error uploading image: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to upload image: {str(e)}")

@app.post("/admin/upload-tool-image/{tool_path:path}")
async def upload_tool_image_to_path(tool_path: str, file: UploadFile = File(...), current_user = Depends(get_current_user)):
    """Upload an image to a specific tool's image directory"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Validate file type
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")
        
        # Validate file extension
        file_ext = Path(file.filename).suffix.lower()
        if file_ext not in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            raise HTTPException(status_code=400, detail="Unsupported image format")
        
        tools_path = get_tools_path()
        tool_dir = tools_path / tool_path
        image_dir = tool_dir / "image"
        
        if not tool_dir.exists():
            raise HTTPException(status_code=404, detail="Tool not found")
        
        # Create image directory if it doesn't exist
        image_dir.mkdir(exist_ok=True)
        
        # Save the file
        file_path = image_dir / file.filename
        
        # Check if file already exists
        if file_path.exists():
            # Create backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = image_dir / f"{file.filename}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
        
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        logger.info(f"Image uploaded by admin user {current_user['uid']}: {file_path}")
        return {"success": True, "message": "Image uploaded successfully", "filename": file.filename}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error uploading image: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to upload image: {str(e)}")

@app.delete("/admin/tool-images/{tool_path:path}/{image_name}")
async def delete_tool_image(tool_path: str, image_name: str, current_user = Depends(get_current_user)):
    """Delete an image from a tool's image directory"""
    try:
        # Check if user is admin
        if current_user["type"] != 2:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        tools_path = get_tools_path()
        tool_dir = tools_path / tool_path
        image_dir = tool_dir / "image"
        image_path = image_dir / image_name
        
        if not tool_dir.exists():
            raise HTTPException(status_code=404, detail="Tool not found")
        
        if not image_path.exists():
            raise HTTPException(status_code=404, detail="Image not found")
        
        # Create backup before deletion
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = tools_path.parent / "backups" / "deleted_images"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        backup_filename = f"{tool_path.replace('/', '_')}_{image_name}.backup_{timestamp}"
        backup_path = backup_dir / backup_filename
        
        shutil.copy2(image_path, backup_path)
        
        # Delete the original file
        image_path.unlink()
        
        logger.info(f"Image deleted by admin user {current_user['uid']}: {image_path}")
        return {"success": True, "message": "Image deleted successfully", "backup_location": str(backup_path)}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error deleting image: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete image: {str(e)}")
