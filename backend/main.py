from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import logging
import os
import json

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
