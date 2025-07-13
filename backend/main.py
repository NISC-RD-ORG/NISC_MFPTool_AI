from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import logging
import os
import json
import sqlite3
import hashlib

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

# Database configuration
DB_PATH = Path(__file__).parent / "mfptool.db"

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

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
async def list_tools():
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        if not tools_path.exists():
            return {"tools": [], "message": "Tools directory not found"}
        
        tools = []
        for item in tools_path.iterdir():
            if item.is_dir():
                tools.append({
                    "name": item.name,
                    "display_name": item.name  # You can modify this for better display names
                })
        
        logger.info(f"Found {len(tools)} tools")
        return {"tools": tools, "count": len(tools)}
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

@app.get("/gettool/{tool_name}")
async def get_tool(tool_name: str):
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        tool_path = tools_path / tool_name
        
        if not tool_path.exists():
            raise HTTPException(status_code=404, detail="Tool not found")
        
        # Read content.md
        content_file = tool_path / "content.md"
        if not content_file.exists():
            raise HTTPException(status_code=404, detail="Content file not found")
        
        with content_file.open("r", encoding="utf-8") as f:
            content = f.read()
        
        # Get metadata if exists
        metadata_file = tool_path / "metadata.json"
        metadata = {}
        if metadata_file.exists():
            with metadata_file.open("r", encoding="utf-8") as f:
                metadata = json.load(f)
        
        # Get list of images
        images_path = tool_path / "image"
        images = []
        if images_path.exists():
            for img_file in images_path.iterdir():
                if img_file.is_file() and img_file.suffix.lower() in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                    images.append(img_file.name)
        
        logger.info(f"Retrieved tool: {tool_name}")
        return {
            "tool_name": tool_name,
            "content": content,
            "metadata": metadata,
            "images": images
        }
    except Exception as e:
        logger.error(f"Error getting tool {tool_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving tool: {str(e)}")

@app.get("/gettoolimage/{tool_name}/{image_name}")
async def get_tool_image(tool_name: str, image_name: str):
    try:
        tools_path = Path(__file__).parent.parent / "tools"
        image_path = tools_path / tool_name / "image" / image_name
        
        if not image_path.exists():
            raise HTTPException(status_code=404, detail="Image not found")
        
        return FileResponse(image_path)
    except Exception as e:
        logger.error(f"Error getting image {image_name} for tool {tool_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving image: {str(e)}")
