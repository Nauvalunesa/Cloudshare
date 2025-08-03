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
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse
from collections import defaultdict
from datetime import datetime
import subprocess
import socket

ip_request_log = defaultdict(list)
banned_ips = set()

def get_real_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    try:
        return request.client.host or socket.gethostbyname(socket.gethostname())
    except:
        return "unknown"

class AntiDDOSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = get_real_ip(request)
        now = datetime.utcnow()

        if ip in banned_ips:
            logger.warning(f"[BLOCKED] {ip} tried to access but is banned.")
            return HTMLResponse("<h1>403 Forbidden</h1><p>You are banned.</p>", status_code=403)

        ip_request_log[ip] = [t for t in ip_request_log[ip] if (now - t).total_seconds() <= 10]
        ip_request_log[ip].append(now)

        
        recent_3s = [t for t in ip_request_log[ip] if (now - t).total_seconds() <= 3]
        recent_10s = ip_request_log[ip]

        if len(recent_10s) > 20:
            try:
                subprocess.run(["ufw", "deny", "from", ip], check=False)
                logger.warning(f"[BANNED] IP {ip} permanently banned via UFW.")
                banned_ips.add(ip)
            except Exception as e:
                logger.error(f"[ERROR] Failed to ban IP {ip}: {e}")
            return HTMLResponse("<h1>429 Too Many Requests</h1><p>You are permanently banned.</p>", status_code=429)

        if len(recent_3s) > 5:
            logger.info(f"[RATE LIMITED] IP {ip} hit 429.")
            return HTMLResponse("<h1>429 Too Many Requests</h1><p>Slow down.</p>", status_code=429)

        return await call_next(request)
        
        
# 
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="LinkShare Pro", description="URL Shortener & File Sharing API")
app.add_middleware(AntiDDOSMiddleware)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORAGE_DIR = "storage"
URL_STORAGE_FILE = "short_urls.json"
UPLOADED_FILES_FILE = "uploaded_files.json"
HTML_STORAGE_DIR = "webpages"
HTML_META_FILE = "html_pages.json"

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(HTML_STORAGE_DIR, exist_ok=True)

short_urls = {}
uploaded_files = {}
upload_progress = {}
html_pages = {}


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

def save_uploaded_files():
    serializable = {
        k: {
            **v,
            "created_at": v["created_at"].isoformat(),
            "expires_at": v["expires_at"].isoformat() if v["expires_at"] else None
        } for k, v in uploaded_files.items()
    }
    with open(UPLOADED_FILES_FILE, "w") as f:
        json.dump(serializable, f, indent=2)

def load_uploaded_files():
    if os.path.exists(UPLOADED_FILES_FILE):
        with open(UPLOADED_FILES_FILE, "r") as f:
            data = json.load(f)
            for fname, meta in data.items():
                meta["created_at"] = datetime.fromisoformat(meta["created_at"])
                meta["expires_at"] = datetime.fromisoformat(meta["expires_at"]) if meta["expires_at"] else None
                uploaded_files[fname] = meta

def save_html_metadata():
    serializable = {
        k: {
            "expires_at": v["expires_at"].isoformat(),
            "filename": v["filename"]
        } for k, v in html_pages.items()
    }
    with open(HTML_META_FILE, "w") as f:
        json.dump(serializable, f, indent=2)

def load_html_metadata():
    if os.path.exists(HTML_META_FILE):
        with open(HTML_META_FILE, "r") as f:
            data = json.load(f)
            for code, val in data.items():
                html_pages[code] = {
                    "expires_at": datetime.fromisoformat(val["expires_at"]),
                    "filename": val["filename"]
                }


load_short_urls()
load_uploaded_files()
load_html_metadata()


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
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"



@app.get("/", response_class=HTMLResponse)
def index():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("<h1>Welcome to LinkShare Pro</h1><p>index.html not found.</p>")
    except Exception as e:
        logger.error(f"Error reading index.html: {str(e)}")
        return HTMLResponse("<h1>Error</h1><p>Could not load the page.</p>")

@app.post("/shorten")
def shorten_url(original_url: str = Form(...), custom_alias: Optional[str] = Form(None), expires_in_minutes: Optional[int] = Form(None)):
    try:
        if not original_url.startswith(('http://', 'https://')):
            raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

        code = custom_alias.strip() if custom_alias else generate_code()
        if custom_alias and not custom_alias.replace('-', '').replace('_', '').isalnum():
            raise HTTPException(status_code=400, detail="Alias can only contain letters, numbers, hyphens, and underscores")
        if code in short_urls:
            raise HTTPException(status_code=400, detail="Alias already in use")

        expiry = datetime.utcnow() + timedelta(minutes=expires_in_minutes) if expires_in_minutes else None
        short_urls[code] = {
            "url": original_url,
            "expires_at": expiry,
            "created_at": datetime.utcnow()
        }
        save_short_urls()

        short_url = f"https://nauval.cloud/s/{code}"
        return {
            "short_url": short_url,
            "expires_at": expiry.isoformat() if expiry else None,
            "code": code,
            "qr_code_url": f"https://nauval.cloud/qr/{code}",
            "qr_code_base64": generate_qr_base64(short_url)
        }
    except Exception as e:
        logger.error(f"Error shortening URL: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/s/{code}")
def redirect_short_url(code: str):
    try:
        data = short_urls.get(code)
        if not data:
            raise HTTPException(status_code=404, detail="Short URL not found")
        if data["expires_at"] and datetime.utcnow() > data["expires_at"]:
            del short_urls[code]
            save_short_urls()
            raise HTTPException(status_code=410, detail="Short URL expired")
        return RedirectResponse(data["url"])
    except Exception as e:
        logger.error(f"Redirect error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/qr/{code}")
def generate_qr(code: str):
    if code in short_urls:
        target = f"https://nauval.cloud/s/{code}"
    elif code in uploaded_files:
        target = f"https://nauval.cloud/download/{code}"
    else:
        raise HTTPException(status_code=404, detail="Code not found")
    img = qrcode.make(target)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="image/png")

@app.get("/upload-progress/{upload_id}")
def get_upload_progress(upload_id: str):
    return upload_progress.get(upload_id, {"progress": 0, "speed": 0, "status": "not_found"})

@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...), filename: Optional[str] = Form(None), expire_value: Optional[int] = Form(None), expire_unit: Optional[str] = Form(None), upload_id: Optional[str] = Form(None)):
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected")

        upload_id = upload_id or generate_code(12)
        upload_progress[upload_id] = {"progress": 0, "speed": 0, "status": "starting", "uploaded": 0, "total": 0}

        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)
        if file_size > 100 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Max file size is 100MB")

        upload_progress[upload_id]["total"] = file_size
        upload_progress[upload_id]["status"] = "uploading"

        ext = os.path.splitext(file.filename)[1]
        name = filename.strip() if filename else generate_code()
        name = "".join(c for c in name if c.isalnum() or c in ('-', '_')).rstrip()
        final_name = f"{name}{ext}"
        path = os.path.join(STORAGE_DIR, final_name)

        counter = 1
        while os.path.exists(path):
            final_name = f"{name}_{counter}{ext}"
            path = os.path.join(STORAGE_DIR, final_name)
            counter += 1

        start_time = datetime.utcnow()
        uploaded = 0

        with open(path, "wb") as buffer:
            while True:
                chunk = await file.read(8192)
                if not chunk:
                    break
                buffer.write(chunk)
                uploaded += len(chunk)
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                if elapsed > 0:
                    speed = uploaded / elapsed
                    progress = uploaded / file_size * 100
                    upload_progress[upload_id].update({"progress": progress, "speed": speed, "uploaded": uploaded})

                await asyncio.sleep(0.01)

        upload_progress[upload_id]["status"] = "completed"
        upload_progress[upload_id]["progress"] = 100

        expires_at = calculate_expiry(expire_value, expire_unit)

        uploaded_files[final_name] = {
            "path": path,
            "expires_at": expires_at,
            "original_name": file.filename,
            "size": file_size,
            "created_at": datetime.utcnow()
        }
        save_uploaded_files()

        asyncio.create_task(cleanup_progress(upload_id))

        url = f"https://nauval.cloud/download/{final_name}"
        return {
            "file_url": url,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "filename": final_name,
            "original_name": file.filename,
            "size": file_size,
            "qr_code_url": f"https://nauval.cloud/qr/{final_name}",
            "qr_code_base64": generate_qr_base64(url),
            "upload_id": upload_id
        }
    except Exception as e:
        upload_progress[upload_id]["status"] = "error"
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

async def cleanup_progress(upload_id: str):
    await asyncio.sleep(300)
    upload_progress.pop(upload_id, None)

@app.get("/download/{filename}")
def download_file(filename: str):
    try:
        data = uploaded_files.get(filename)
        if not data or not os.path.exists(data["path"]):
            raise HTTPException(status_code=404, detail="File not found")

        if data["expires_at"] and datetime.utcnow() > data["expires_at"]:
            try:
                os.remove(data["path"])
            except:
                pass
            del uploaded_files[filename]
            save_uploaded_files()
            raise HTTPException(status_code=410, detail="File expired")

        return FileResponse(data["path"], filename=data.get("original_name", filename), media_type='application/octet-stream')
    except Exception as e:
        logger.error(f"Download error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/upload/html")
async def upload_html_page(
    file: UploadFile = File(...),
    code: str = Form(...),
    expire_days: int = Form(...)
):
    if not file.filename.endswith(".html"):
        raise HTTPException(status_code=400, detail="Only .html files allowed")

    if not code.isalnum():
        raise HTTPException(status_code=400, detail="Code must be alphanumeric")

    if code in html_pages:
        raise HTTPException(status_code=400, detail="Code already used")

    if expire_days > 7 or expire_days < 1:
        raise HTTPException(status_code=400, detail="Expire must be between 1 and 7 days")

    filename = f"{code}.html"
    filepath = os.path.join(HTML_STORAGE_DIR, filename)

    with open(filepath, "wb") as f:
        content = await file.read()
        f.write(content)

    expires_at = datetime.utcnow() + timedelta(days=expire_days)
    html_pages[code] = {
        "filename": filename,
        "expires_at": expires_at
    }
    save_html_metadata()

    return {
        "status": True,
        "message": f"Uploaded as /view/{code}",
        "expires_at": expires_at.isoformat()
    }

@app.get("/view/{code}", response_class=HTMLResponse)
def view_uploaded_html_page(code: str):
    page = html_pages.get(code)
    if not page:
        raise HTTPException(status_code=404, detail="Page not found")

    if datetime.utcnow() > page["expires_at"]:
        filepath = os.path.join(HTML_STORAGE_DIR, page["filename"])
        try:
            os.remove(filepath)
        except:
            pass
        del html_pages[code]
        save_html_metadata()
        raise HTTPException(status_code=410, detail="Page expired")

    filepath = os.path.join(HTML_STORAGE_DIR, page["filename"])
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File missing")

    return FileResponse(filepath, media_type="text/html")

@app.get("/stats")
def get_stats():
    try:
        return {
            "total_urls": len(short_urls),
            "total_files": len(uploaded_files),
            "total_html_pages": len(html_pages),
            "storage_dir": STORAGE_DIR,
            "html_dir": HTML_STORAGE_DIR
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
