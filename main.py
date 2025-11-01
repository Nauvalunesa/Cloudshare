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
import time
from functools import lru_cache
from PIL import Image
import hashlib

# DDoS Protection Configuration
MAX_TRACKED_IPS = 10000  # Maximum IPs to track in memory
CLEANUP_INTERVAL = 300  # Clean old IPs every 5 minutes
MAX_CONCURRENT_UPLOADS_PER_IP = 3  # Max concurrent uploads per IP
RATE_LIMIT_STRICT = 3  # requests per second
RATE_LIMIT_BURST = 10  # requests per 10 seconds
RATE_LIMIT_BAN = 30  # requests per 10 seconds before permanent ban
BANNED_IPS_FILE = "banned_ips.json"

ip_request_log = defaultdict(list)
banned_ips = set()
active_uploads = defaultdict(int)
qr_cache = {}  # QR code cache
last_cleanup_time = time.time()

def load_banned_ips():
    """Load banned IPs from persistent storage"""
    global banned_ips
    if os.path.exists(BANNED_IPS_FILE):
        try:
            with open(BANNED_IPS_FILE, "r") as f:
                banned_ips = set(json.load(f))
            logger.info(f"Loaded {len(banned_ips)} banned IPs from storage")
        except Exception as e:
            logger.error(f"Error loading banned IPs: {e}")

def save_banned_ips():
    """Save banned IPs to persistent storage"""
    try:
        with open(BANNED_IPS_FILE, "w") as f:
            json.dump(list(banned_ips), f)
    except Exception as e:
        logger.error(f"Error saving banned IPs: {e}")

def cleanup_old_ips():
    """Clean up old IPs from tracking to prevent memory leak"""
    global last_cleanup_time
    now = time.time()

    if now - last_cleanup_time < CLEANUP_INTERVAL:
        return

    current_time = datetime.utcnow()
    cleaned = 0

    # Remove IPs that haven't made requests in the last 10 seconds
    ips_to_remove = []
    for ip, timestamps in list(ip_request_log.items()):
        if not timestamps or (current_time - timestamps[-1]).total_seconds() > 10:
            ips_to_remove.append(ip)

    for ip in ips_to_remove:
        del ip_request_log[ip]
        cleaned += 1

    # If still too many IPs, remove oldest ones
    if len(ip_request_log) > MAX_TRACKED_IPS:
        sorted_ips = sorted(ip_request_log.items(), key=lambda x: x[1][-1] if x[1] else datetime.min)
        excess = len(ip_request_log) - MAX_TRACKED_IPS
        for ip, _ in sorted_ips[:excess]:
            del ip_request_log[ip]
            cleaned += 1

    last_cleanup_time = now
    if cleaned > 0:
        logger.info(f"Cleaned up {cleaned} IPs from tracking")

def get_real_ip(request: Request) -> str:
    """Extract real IP from request, handling proxies"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
    else:
        try:
            ip = request.client.host or socket.gethostbyname(socket.gethostname())
        except:
            ip = "unknown"

    # Basic validation to prevent injection
    if ip != "unknown" and not all(c.isdigit() or c in '.:-' for c in ip):
        return "unknown"

    return ip

def ban_ip_via_firewall(ip: str) -> bool:
    """Ban IP using UFW firewall with proper timeout and validation"""
    if ip == "unknown" or ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10."):
        return False

    try:
        # Use timeout to prevent hanging
        result = subprocess.run(
            ["ufw", "deny", "from", ip],
            capture_output=True,
            timeout=5,
            check=False
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout banning IP {ip} via UFW")
        return False
    except Exception as e:
        logger.error(f"Error banning IP {ip}: {e}")
        return False

class AntiDDOSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Run periodic cleanup
        cleanup_old_ips()

        ip = get_real_ip(request)
        now = datetime.utcnow()

        # Check if IP is banned
        if ip in banned_ips:
            logger.warning(f"[BLOCKED] {ip} tried to access but is banned.")
            return HTMLResponse("<h1>403 Forbidden</h1><p>You are banned.</p>", status_code=403)

        # Clean old timestamps and add current request
        ip_request_log[ip] = [t for t in ip_request_log[ip] if (now - t).total_seconds() <= 10]
        ip_request_log[ip].append(now)

        # Calculate request rates
        recent_1s = [t for t in ip_request_log[ip] if (now - t).total_seconds() <= 1]
        recent_10s = ip_request_log[ip]

        # Permanent ban if excessive requests (30+ in 10 seconds)
        if len(recent_10s) > RATE_LIMIT_BAN:
            if ban_ip_via_firewall(ip):
                logger.warning(f"[BANNED] IP {ip} permanently banned via UFW ({len(recent_10s)} requests in 10s).")
            banned_ips.add(ip)
            save_banned_ips()
            return HTMLResponse(
                "<h1>429 Too Many Requests</h1><p>You are permanently banned for excessive requests.</p>",
                status_code=429
            )

        # Temporary rate limit (10+ requests in 10 seconds)
        if len(recent_10s) > RATE_LIMIT_BURST:
            logger.info(f"[RATE LIMITED] IP {ip} exceeded burst limit ({len(recent_10s)} requests in 10s).")
            return HTMLResponse(
                "<h1>429 Too Many Requests</h1><p>Too many requests. Please slow down.</p>",
                status_code=429
            )

        # Strict rate limit (3+ requests per second)
        if len(recent_1s) > RATE_LIMIT_STRICT:
            logger.info(f"[RATE LIMITED] IP {ip} exceeded strict limit ({len(recent_1s)} requests/sec).")
            return HTMLResponse(
                "<h1>429 Too Many Requests</h1><p>Request rate too high. Slow down.</p>",
                status_code=429
            )

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
IMAGES_DIR = "images"
BIOLINK_DATA_FILE = "biolinks.json"

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(HTML_STORAGE_DIR, exist_ok=True)
os.makedirs(IMAGES_DIR, exist_ok=True)

short_urls = {}
uploaded_files = {}
upload_progress = {}
html_pages = {}
biolinks = {}


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

def save_biolinks():
    serializable = {
        k: {
            **v,
            "created_at": v["created_at"].isoformat() if isinstance(v.get("created_at"), datetime) else v.get("created_at"),
        } for k, v in biolinks.items()
    }
    with open(BIOLINK_DATA_FILE, "w") as f:
        json.dump(serializable, f, indent=2)

def load_biolinks():
    if os.path.exists(BIOLINK_DATA_FILE):
        with open(BIOLINK_DATA_FILE, "r") as f:
            data = json.load(f)
            for code, val in data.items():
                if "created_at" in val and isinstance(val["created_at"], str):
                    val["created_at"] = datetime.fromisoformat(val["created_at"])
                biolinks[code] = val

load_short_urls()
load_uploaded_files()
load_html_metadata()
load_banned_ips()  # Load banned IPs on startup
load_biolinks()  # Load bio links on startup


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

@app.get("/advanced.html", response_class=HTMLResponse)
def advanced():
    try:
        with open("advanced.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="advanced.html not found")
    except Exception as e:
        logger.error(f"Error reading advanced.html: {str(e)}")
        raise HTTPException(status_code=500, detail="Could not load the page")

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
    # Check cache first to prevent CPU exhaustion
    if code in qr_cache:
        buffer = BytesIO(qr_cache[code])
        return StreamingResponse(buffer, media_type="image/png")

    if code in short_urls:
        target = f"https://nauval.cloud/s/{code}"
    elif code in uploaded_files:
        target = f"https://nauval.cloud/download/{code}"
    else:
        raise HTTPException(status_code=404, detail="Code not found")

    # Generate QR code
    img = qrcode.make(target)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    qr_data = buffer.getvalue()

    # Cache the QR code (limit cache size to prevent memory issues)
    if len(qr_cache) < 1000:
        qr_cache[code] = qr_data

    buffer = BytesIO(qr_data)
    return StreamingResponse(buffer, media_type="image/png")

@app.get("/upload-progress/{upload_id}")
def get_upload_progress(upload_id: str):
    return upload_progress.get(upload_id, {"progress": 0, "speed": 0, "status": "not_found"})

@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...), filename: Optional[str] = Form(None), expire_value: Optional[int] = Form(None), expire_unit: Optional[str] = Form(None), upload_id: Optional[str] = Form(None)):
    try:
        # Get client IP for rate limiting
        client_ip = get_real_ip(request)

        # Check concurrent upload limit per IP
        if active_uploads[client_ip] >= MAX_CONCURRENT_UPLOADS_PER_IP:
            raise HTTPException(
                status_code=429,
                detail=f"Too many concurrent uploads. Maximum {MAX_CONCURRENT_UPLOADS_PER_IP} uploads allowed per IP."
            )

        # Increment active upload counter
        active_uploads[client_ip] += 1

        if not file.filename:
            active_uploads[client_ip] -= 1
            raise HTTPException(status_code=400, detail="No file selected")

        upload_id = upload_id or generate_code(12)
        upload_progress[upload_id] = {"progress": 0, "speed": 0, "status": "starting", "uploaded": 0, "total": 0}

        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)

        # Reduced max file size to mitigate storage exhaustion attacks
        if file_size > 50 * 1024 * 1024:  # 50MB instead of 100MB
            active_uploads[client_ip] -= 1
            raise HTTPException(status_code=400, detail="Max file size is 50MB")

        # Reject empty files
        if file_size == 0:
            active_uploads[client_ip] -= 1
            raise HTTPException(status_code=400, detail="Empty files are not allowed")

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

        # Decrement active upload counter
        active_uploads[client_ip] = max(0, active_uploads[client_ip] - 1)
        if active_uploads[client_ip] == 0:
            active_uploads.pop(client_ip, None)

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
        # Decrement active upload counter on error
        active_uploads[client_ip] = max(0, active_uploads[client_ip] - 1)
        if active_uploads[client_ip] == 0:
            active_uploads.pop(client_ip, None)

        if 'upload_id' in locals():
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
    request: Request,
    file: UploadFile = File(...),
    code: str = Form(...),
    expire_days: int = Form(...)
):
    if not file.filename.endswith(".html"):
        raise HTTPException(status_code=400, detail="Only .html files allowed")

    # Stricter code validation to prevent path traversal
    if not code.isalnum() or len(code) < 3 or len(code) > 20:
        raise HTTPException(status_code=400, detail="Code must be alphanumeric and 3-20 characters")

    if code in html_pages:
        raise HTTPException(status_code=400, detail="Code already used")

    if expire_days > 7 or expire_days < 1:
        raise HTTPException(status_code=400, detail="Expire must be between 1 and 7 days")

    # Check file size to prevent abuse
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:  # 5MB max for HTML
        raise HTTPException(status_code=400, detail="HTML file too large (max 5MB)")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file not allowed")

    filename = f"{code}.html"
    filepath = os.path.join(HTML_STORAGE_DIR, filename)

    # Write the content we already read
    with open(filepath, "wb") as f:
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

# Text Snippets Storage
SNIPPETS_FILE = "snippets.json"
text_snippets = {}

def save_snippets():
    serializable = {
        k: {
            **v,
            "created_at": v["created_at"].isoformat(),
            "expires_at": v["expires_at"].isoformat() if v["expires_at"] else None
        } for k, v in text_snippets.items()
    }
    with open(SNIPPETS_FILE, "w") as f:
        json.dump(serializable, f, indent=2)

def load_snippets():
    if os.path.exists(SNIPPETS_FILE):
        with open(SNIPPETS_FILE, "r") as f:
            data = json.load(f)
            for code, meta in data.items():
                meta["created_at"] = datetime.fromisoformat(meta["created_at"])
                meta["expires_at"] = datetime.fromisoformat(meta["expires_at"]) if meta["expires_at"] else None
                text_snippets[code] = meta

# Load snippets on startup
load_snippets()

@app.post("/snippet")
async def create_snippet(
    code: str = Form(...),
    content: str = Form(...),
    language: str = Form("text"),
    expire_value: Optional[int] = Form(None),
    expire_unit: Optional[str] = Form(None),
    password: Optional[str] = Form(None)
):
    """Create a text/code snippet"""
    try:
        # Validate code
        if not code.replace('-', '').replace('_', '').isalnum() or len(code) < 3 or len(code) > 30:
            raise HTTPException(status_code=400, detail="Code must be alphanumeric (3-30 chars)")

        if code in text_snippets:
            raise HTTPException(status_code=400, detail="Code already exists")

        # Validate content size
        if len(content) > 1 * 1024 * 1024:  # 1MB max
            raise HTTPException(status_code=400, detail="Content too large (max 1MB)")

        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Content cannot be empty")

        # Calculate expiry
        expires_at = calculate_expiry(expire_value, expire_unit)

        # Store snippet
        text_snippets[code] = {
            "content": content,
            "language": language,
            "password": password,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at
        }
        save_snippets()

        snippet_url = f"/snippet/{code}"
        return {
            "success": True,
            "url": snippet_url,
            "code": code,
            "expires_at": expires_at.isoformat() if expires_at else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating snippet: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/snippet/{code}", response_class=HTMLResponse)
async def view_snippet_page(code: str, request: Request):
    """Serve snippet viewer HTML page"""
    return FileResponse("snippet_viewer.html")

@app.get("/api/snippet/{code}")
async def view_snippet(code: str, password: Optional[str] = None):
    """View a text snippet (API endpoint)"""
    snippet = text_snippets.get(code)
    if not snippet:
        raise HTTPException(status_code=404, detail="Snippet not found")

    # Check expiry
    if snippet["expires_at"] and datetime.utcnow() > snippet["expires_at"]:
        del text_snippets[code]
        save_snippets()
        raise HTTPException(status_code=410, detail="Snippet expired")

    # Check password
    if snippet.get("password"):
        if not password or password != snippet["password"]:
            raise HTTPException(status_code=401, detail="Password required")

    return {
        "content": snippet["content"],
        "language": snippet["language"],
        "created_at": snippet["created_at"].isoformat(),
        "expires_at": snippet["expires_at"].isoformat() if snippet["expires_at"] else None
    }

@app.get("/snippet/{code}/raw")
async def view_snippet_raw(code: str, password: Optional[str] = None):
    """View raw snippet content"""
    snippet = text_snippets.get(code)
    if not snippet:
        raise HTTPException(status_code=404, detail="Snippet not found")

    if snippet["expires_at"] and datetime.utcnow() > snippet["expires_at"]:
        del text_snippets[code]
        save_snippets()
        raise HTTPException(status_code=410, detail="Snippet expired")

    if snippet.get("password"):
        if not password or password != snippet["password"]:
            raise HTTPException(status_code=401, detail="Password required")

    return HTMLResponse(content=snippet["content"], media_type="text/plain")

@app.get("/stats")
def get_stats():
    try:
        return {
            "total_urls": len(short_urls),
            "total_files": len(uploaded_files),
            "total_html_pages": len(html_pages),
            "total_snippets": len(text_snippets),
            "total_biolinks": len(biolinks),
            "storage_dir": STORAGE_DIR,
            "html_dir": HTML_STORAGE_DIR
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Image Upload for Bio Links
@app.post("/upload/image")
async def upload_image(
    request: Request,
    file: UploadFile = File(...)
):
    """Upload and optimize images for bio links (profile, cover, etc.)"""
    try:
        client_ip = get_real_ip(request)

        # Validate file type
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="Only image files allowed")

        allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
        if file.content_type not in allowed_types:
            raise HTTPException(status_code=400, detail=f"Supported formats: JPEG, PNG, GIF, WEBP")

        # Read image data
        image_data = await file.read()

        # Size limit: 10MB for images
        if len(image_data) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Image too large (max 10MB)")

        # Open with PIL for validation and optimization
        try:
            img = Image.open(BytesIO(image_data))

            # Validate image
            img.verify()

            # Reopen for processing (verify closes the file)
            img = Image.open(BytesIO(image_data))

            # Convert RGBA to RGB if needed
            if img.mode == 'RGBA':
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3])
                img = background
            elif img.mode not in ('RGB', 'L'):
                img = img.convert('RGB')

            # Optimize: resize if too large (max 1200px width/height)
            max_size = 1200
            if img.width > max_size or img.height > max_size:
                img.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)

            # Generate unique filename using hash
            image_hash = hashlib.md5(image_data).hexdigest()[:12]
            ext = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
            filename = f"{image_hash}.{ext}"
            filepath = os.path.join(IMAGES_DIR, filename)

            # Save optimized image
            img.save(filepath, optimize=True, quality=85)

            # Get file size
            file_size = os.path.getsize(filepath)

            image_url = f"/images/{filename}"

            return {
                "success": True,
                "url": image_url,
                "filename": filename,
                "size": file_size,
                "dimensions": {"width": img.width, "height": img.height}
            }

        except Exception as e:
            logger.error(f"Image processing error: {e}")
            raise HTTPException(status_code=400, detail="Invalid image file")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image upload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/images/{filename}")
async def get_image(filename: str):
    """Serve uploaded images"""
    filepath = os.path.join(IMAGES_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Image not found")
    return FileResponse(filepath)

# Premium Bio Link Builder
@app.post("/biolink/create")
async def create_biolink(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(...),
    bio: str = Form(""),
    profile_image: Optional[str] = Form(None),
    cover_image: Optional[str] = Form(None),
    theme: str = Form("cosmic"),
    links: str = Form("[]"),
    social_links: str = Form("{}"),
    custom_css: Optional[str] = Form(None),
    analytics_enabled: bool = Form(True)
):
    """Create a premium bio link page"""
    try:
        # Validate username
        if not username.replace('-', '').replace('_', '').isalnum() or len(username) < 3 or len(username) > 30:
            raise HTTPException(status_code=400, detail="Username must be alphanumeric (3-30 chars)")

        # Parse JSON fields
        try:
            links_data = json.loads(links)
            social_data = json.loads(social_links)
        except:
            raise HTTPException(status_code=400, detail="Invalid JSON data for links")

        # Validate theme
        valid_themes = ['cosmic', 'minimal', 'gradient', 'dark', 'neon', 'ocean', 'sunset', 'forest']
        if theme not in valid_themes:
            theme = 'cosmic'

        # Create bio link data
        biolink_data = {
            "username": username,
            "display_name": display_name,
            "bio": bio,
            "profile_image": profile_image,
            "cover_image": cover_image,
            "theme": theme,
            "links": links_data,
            "social_links": social_data,
            "custom_css": custom_css,
            "analytics_enabled": analytics_enabled,
            "views": 0,
            "clicks": {},
            "created_at": datetime.utcnow()
        }

        biolinks[username] = biolink_data
        save_biolinks()

        bio_url = f"/bio/{username}"

        return {
            "success": True,
            "url": bio_url,
            "username": username,
            "preview_url": f"https://nauval.cloud{bio_url}"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bio link creation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/bio/{username}", response_class=HTMLResponse)
async def view_biolink(username: str):
    """View bio link page"""
    biolink = biolinks.get(username)
    if not biolink:
        raise HTTPException(status_code=404, detail="Bio link not found")

    # Increment view counter
    biolink["views"] = biolink.get("views", 0) + 1
    save_biolinks()

    return FileResponse("biolink_viewer.html")

@app.get("/api/biolink/{username}")
async def get_biolink_data(username: str):
    """Get bio link data (API)"""
    biolink = biolinks.get(username)
    if not biolink:
        raise HTTPException(status_code=404, detail="Bio link not found")

    return {
        "username": biolink["username"],
        "display_name": biolink["display_name"],
        "bio": biolink["bio"],
        "profile_image": biolink.get("profile_image"),
        "cover_image": biolink.get("cover_image"),
        "theme": biolink["theme"],
        "links": biolink["links"],
        "social_links": biolink.get("social_links", {}),
        "custom_css": biolink.get("custom_css"),
        "views": biolink.get("views", 0)
    }

@app.post("/api/biolink/{username}/click")
async def track_click(username: str, link_id: str = Form(...)):
    """Track link clicks for analytics"""
    biolink = biolinks.get(username)
    if not biolink:
        raise HTTPException(status_code=404, detail="Bio link not found")

    if "clicks" not in biolink:
        biolink["clicks"] = {}

    biolink["clicks"][link_id] = biolink["clicks"].get(link_id, 0) + 1
    save_biolinks()

    return {"success": True}
