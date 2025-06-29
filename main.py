from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Request
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from typing import Optional
import os
import shutil
import random
import string
import logging
import traceback
import json
import qrcode
from io import BytesIO
import base64
import asyncio

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="LinkShare Pro", description="URL Shortener & File Sharing API")

# CORS middleware untuk frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Folder penyimpanan file
STORAGE_DIR = "storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

# Penyimpanan sementara dan persistent
short_urls = {}
uploaded_files = {}
upload_progress = {}  # Track upload progress
URL_STORAGE_FILE = "short_urls.json"

def save_short_urls():
    with open(URL_STORAGE_FILE, "w") as f:
        json.dump(short_urls, f, default=str)

def load_short_urls():
    if os.path.exists(URL_STORAGE_FILE):
        with open(URL_STORAGE_FILE, "r") as f:
            data = json.load(f)
            for code, val in data.items():
                val["created_at"] = datetime.fromisoformat(val["created_at"])
                val["expires_at"] = datetime.fromisoformat(val["expires_at"]) if val["expires_at"] else None
                short_urls[code] = val

load_short_urls()

# Fungsi utilitas
def generate_code(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def calculate_expiry(value: Optional[int], unit: Optional[str]) -> Optional[datetime]:
    if not value or not unit:
        return None
    now = datetime.utcnow()
    if unit == "minutes":
        return now + timedelta(minutes=value)
    elif unit == "hours":
        return now + timedelta(hours=value)
    elif unit == "days":
        return now + timedelta(days=value)
    return None

def generate_qr_base64(url: str) -> str:
    """Generate QR code and return as base64 string"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    # Convert to base64
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"

@app.get("/", response_class=HTMLResponse)
def index():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        logger.error("index.html file not found")
        return HTMLResponse(content="<h1>Welcome to LinkShare Pro</h1><p>index.html not found.</p>")
    except Exception as e:
        logger.error(f"Error reading index.html: {str(e)}")
        return HTMLResponse(content="<h1>Error</h1><p>Could not load the page.</p>")

@app.post("/shorten")
def shorten_url(
    original_url: str = Form(...),
    custom_alias: Optional[str] = Form(None),
    expires_in_minutes: Optional[int] = Form(None)
):
    try:
        logger.info(f"Shortening URL: {original_url}")

        if not original_url.startswith(('http://', 'https://')):
            raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

        code = custom_alias.strip() if custom_alias else generate_code()

        if custom_alias and not custom_alias.replace('-', '').replace('_', '').isalnum():
            raise HTTPException(status_code=400, detail="Custom alias can only contain letters, numbers, hyphens, and underscores")

        if code in short_urls:
            raise HTTPException(status_code=400, detail="Alias already in use")

        expiry = datetime.utcnow() + timedelta(minutes=expires_in_minutes) if expires_in_minutes and expires_in_minutes > 0 else None

        short_urls[code] = {
            "url": original_url,
            "expires_at": expiry,
            "created_at": datetime.utcnow()
        }
        save_short_urls()

        # Generate QR code
        short_url = f"https://nauval.cloud/s/{code}"
        qr_base64 = generate_qr_base64(short_url)

        return {
            "short_url": short_url,
            "expires_at": expiry.isoformat() if expiry else None,
            "code": code,
            "qr_code_url": f"https://nauval.cloud/qr/{code}",
            "qr_code_base64": qr_base64
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error shortening URL: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/s/{code}")
def redirect_short_url(code: str):
    try:
        logger.info(f"Accessing short URL: {code}")
        data = short_urls.get(code)
        if not data:
            logger.warning(f"Short URL not found: {code}")
            raise HTTPException(status_code=404, detail="Short URL not found")

        if data["expires_at"] and datetime.utcnow() > data["expires_at"]:
            logger.info(f"Short URL expired: {code}")
            del short_urls[code]
            save_short_urls()
            raise HTTPException(status_code=410, detail="Short URL expired")

        return RedirectResponse(data["url"])

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error redirecting URL {code}: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/qr/{code}")
def generate_qr(code: str):
    url_target = None
    if code in short_urls:
        url_target = f"https://nauval.cloud/s/{code}"
    elif code in uploaded_files:
        url_target = f"https://nauval.cloud/download/{code}"
    else:
        raise HTTPException(status_code=404, detail="Short URL or file not found")

    img = qrcode.make(url_target)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    return StreamingResponse(buffer, media_type="image/png")

@app.get("/upload-progress/{upload_id}")
def get_upload_progress(upload_id: str):
    """Get upload progress for a specific upload ID"""
    progress = upload_progress.get(upload_id, {"progress": 0, "speed": 0, "status": "not_found"})
    return progress

@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    filename: Optional[str] = Form(None),
    expire_value: Optional[int] = Form(None),
    expire_unit: Optional[str] = Form(None),
    upload_id: Optional[str] = Form(None)
):
    try:
        logger.info(f"Uploading file: {file.filename}")

        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected")

        # Initialize progress tracking
        if not upload_id:
            upload_id = generate_code(12)
        
        upload_progress[upload_id] = {
            "progress": 0,
            "speed": 0,
            "status": "starting",
            "uploaded": 0,
            "total": 0
        }

        # Get file size
        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)

        if file_size > 100 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File size too large (max 100MB)")

        upload_progress[upload_id]["total"] = file_size
        upload_progress[upload_id]["status"] = "uploading"

        ext = os.path.splitext(file.filename)[1]
        name = filename.strip() if filename else generate_code()
        name = "".join(c for c in name if c.isalnum() or c in ('-', '_')).rstrip()
        if not name:
            name = generate_code()

        final_name = f"{name}{ext}"
        file_path = os.path.join(STORAGE_DIR, final_name)

        counter = 1
        original_final_name = final_name
        while os.path.exists(file_path):
            name_part = os.path.splitext(original_final_name)[0]
            final_name = f"{name_part}_{counter}{ext}"
            file_path = os.path.join(STORAGE_DIR, final_name)
            counter += 1

        # Upload with progress tracking
        start_time = datetime.utcnow()
        uploaded_bytes = 0
        chunk_size = 8192  # 8KB chunks

        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                
                buffer.write(chunk)
                uploaded_bytes += len(chunk)
                
                # Calculate progress and speed
                elapsed_time = (datetime.utcnow() - start_time).total_seconds()
                if elapsed_time > 0:
                    speed = uploaded_bytes / elapsed_time  # bytes per second
                    progress_percent = (uploaded_bytes / file_size) * 100
                    
                    upload_progress[upload_id].update({
                        "progress": min(progress_percent, 100),
                        "speed": speed,
                        "uploaded": uploaded_bytes,
                        "status": "uploading"
                    })
                
                # Small delay to allow progress tracking
                await asyncio.sleep(0.01)

        upload_progress[upload_id]["status"] = "completed"
        upload_progress[upload_id]["progress"] = 100

        expires_at = calculate_expiry(expire_value, expire_unit)

        uploaded_files[final_name] = {
            "path": file_path,
            "expires_at": expires_at,
            "original_name": file.filename,
            "size": file_size,
            "created_at": datetime.utcnow()
        }

        # Generate QR code
        file_url = f"https://nauval.cloud/download/{final_name}"
        qr_base64 = generate_qr_base64(file_url)

        logger.info(f"File uploaded successfully: {final_name}")

        # Clean up progress tracking after a delay
        asyncio.create_task(cleanup_progress(upload_id))

        return {
            "file_url": file_url,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "filename": final_name,
            "original_name": file.filename,
            "size": file_size,
            "qr_code_url": f"https://nauval.cloud/qr/{final_name}",
            "qr_code_base64": qr_base64,
            "upload_id": upload_id
        }

    except HTTPException:
        if upload_id:
            upload_progress[upload_id]["status"] = "error"
        raise
    except Exception as e:
        if upload_id:
            upload_progress[upload_id]["status"] = "error"
        logger.error(f"Error uploading file: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

async def cleanup_progress(upload_id: str):
    """Clean up progress tracking after 5 minutes"""
    await asyncio.sleep(300)  # 5 minutes
    if upload_id in upload_progress:
        del upload_progress[upload_id]

@app.get("/download/{filename}")
def download_file(filename: str):
    try:
        logger.info(f"Downloading file: {filename}")
        data = uploaded_files.get(filename)
        if not data or not os.path.exists(data["path"]):
            logger.warning(f"File not found: {filename}")
            raise HTTPException(status_code=404, detail="File not found")

        if data["expires_at"] and datetime.utcnow() > data["expires_at"]:
            logger.info(f"File expired: {filename}")
            try:
                os.remove(data["path"])
            except:
                pass
            del uploaded_files[filename]
            raise HTTPException(status_code=410, detail="File expired")

        return FileResponse(
            data["path"],
            filename=data.get("original_name", filename),
            media_type='application/octet-stream'
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading file {filename}: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/stats")
def get_stats():
    try:
        return {
            "total_urls": len(short_urls),
            "total_files": len(uploaded_files),
            "storage_dir": STORAGE_DIR
        }
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
