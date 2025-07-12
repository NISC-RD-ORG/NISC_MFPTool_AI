from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import logging
import os

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
