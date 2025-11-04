from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Request, Header
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from typing import Optional, List
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
import hmac
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import zipfile


MAX_TRACKED_IPS = 10000
CLEANUP_INTERVAL = 300
MAX_CONCURRENT_UPLOADS_PER_IP = 3
RATE_LIMIT_STRICT = 3
RATE_LIMIT_BURST = 10
RATE_LIMIT_BAN = 30
BANNED_IPS_FILE = "banned_ips.json"


MAX_QR_REQUESTS_PER_MINUTE = 30
MAX_IMAGE_UPLOADS_PER_HOUR = 50
MAX_BIOLINKS_PER_IP = 5
MAX_SNIPPETS_PER_IP = 20
MAX_HTML_PAGES_PER_IP = 10
QR_CACHE_MAX_SIZE = 500
QR_CACHE_CLEANUP_INTERVAL = 3600

ip_request_log = defaultdict(list)
banned_ips = set()
active_uploads = defaultdict(int)
qr_cache = {}
qr_request_log = defaultdict(list)
image_upload_log = defaultdict(list)
creation_counts = defaultdict(lambda: {"biolinks": 0, "snippets": 0, "html": 0})
last_cleanup_time = time.time()
last_qr_cache_cleanup = time.time()

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", hashlib.sha256(b"cloudshare-secret-key-2025").digest())
HMAC_KEY = os.getenv("HMAC_KEY", b"cloudshare-hmac-key-2025")

def encrypt_file_content(data: bytes, password: Optional[str] = None) -> tuple:
    key = hashlib.sha256(password.encode()).digest() if password else ENCRYPTION_KEY
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext

def decrypt_file_content(encrypted_data: bytes, password: Optional[str] = None) -> bytes:
    key = hashlib.sha256(password.encode()).digest() if password else ENCRYPTION_KEY
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def compute_hmac(data: bytes) -> str:
    return hmac.new(HMAC_KEY, data, hashlib.sha256).hexdigest()

def verify_hmac(data: bytes, expected_hmac: str) -> bool:
    return hmac.compare_digest(compute_hmac(data), expected_hmac)

def load_banned_ips():

    global banned_ips
    if os.path.exists(BANNED_IPS_FILE):
        try:
            with open(BANNED_IPS_FILE, "r") as f:
                banned_ips = set(json.load(f))
            logger.info(f"Loaded {len(banned_ips)} banned IPs from storage")
        except Exception as e:
            logger.error(f"Error loading banned IPs: {e}")

def save_banned_ips():

    try:
        with open(BANNED_IPS_FILE, "w") as f:
            json.dump(list(banned_ips), f)
    except Exception as e:
        logger.error(f"Error saving banned IPs: {e}")

def cleanup_old_ips():

    global last_cleanup_time, last_qr_cache_cleanup
    now = time.time()

    if now - last_cleanup_time < CLEANUP_INTERVAL:
        return

    current_time = datetime.utcnow()
    cleaned = 0


    ips_to_remove = []
    for ip, timestamps in list(ip_request_log.items()):
        if not timestamps or (current_time - timestamps[-1]).total_seconds() > 10:
            ips_to_remove.append(ip)

    for ip in ips_to_remove:
        del ip_request_log[ip]
        cleaned += 1


    if len(ip_request_log) > MAX_TRACKED_IPS:
        sorted_ips = sorted(ip_request_log.items(), key=lambda x: x[1][-1] if x[1] else datetime.min)
        excess = len(ip_request_log) - MAX_TRACKED_IPS
        for ip, _ in sorted_ips[:excess]:
            del ip_request_log[ip]
            cleaned += 1


    for ip in list(qr_request_log.keys()):
        qr_request_log[ip] = [t for t in qr_request_log[ip] if (current_time - t).total_seconds() <= 60]
        if not qr_request_log[ip]:
            del qr_request_log[ip]


    for ip in list(image_upload_log.keys()):
        image_upload_log[ip] = [t for t in image_upload_log[ip] if (current_time - t).total_seconds() <= 3600]
        if not image_upload_log[ip]:
            del image_upload_log[ip]


    if now - last_qr_cache_cleanup > QR_CACHE_CLEANUP_INTERVAL:
        if len(qr_cache) > QR_CACHE_MAX_SIZE:

            excess = len(qr_cache) - QR_CACHE_MAX_SIZE
            for key in list(qr_cache.keys())[:excess]:
                del qr_cache[key]
        last_qr_cache_cleanup = now

    last_cleanup_time = now
    if cleaned > 0:
        logger.info(f"Cleaned up {cleaned} IPs from tracking")

def check_qr_rate_limit(ip: str) -> bool:

    current_time = datetime.utcnow()
    qr_request_log[ip] = [t for t in qr_request_log[ip] if (current_time - t).total_seconds() <= 60]

    if len(qr_request_log[ip]) >= MAX_QR_REQUESTS_PER_MINUTE:
        return False

    qr_request_log[ip].append(current_time)
    return True

def check_image_upload_limit(ip: str) -> bool:

    current_time = datetime.utcnow()
    image_upload_log[ip] = [t for t in image_upload_log[ip] if (current_time - t).total_seconds() <= 3600]

    if len(image_upload_log[ip]) >= MAX_IMAGE_UPLOADS_PER_HOUR:
        return False

    image_upload_log[ip].append(current_time)
    return True

def check_creation_limit(ip: str, resource_type: str, max_limit: int) -> bool:

    if creation_counts[ip][resource_type] >= max_limit:
        return False
    creation_counts[ip][resource_type] += 1
    return True

def get_real_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
    else:
        try:
            ip = request.client.host or socket.gethostbyname(socket.gethostname())
        except:
            ip = "unknown"

    if ip != "unknown" and not all(c.isdigit() or c in '.:-' for c in ip):
        return "unknown"

    return ip

def is_browser_request(request: Request) -> bool:
    user_agent = request.headers.get("User-Agent", "").lower()
    accept = request.headers.get("Accept", "").lower()
    sec_fetch_site = request.headers.get("Sec-Fetch-Site", "")
    sec_fetch_mode = request.headers.get("Sec-Fetch-Mode", "")
    sec_fetch_dest = request.headers.get("Sec-Fetch-Dest", "")
    accept_language = request.headers.get("Accept-Language", "")
    accept_encoding = request.headers.get("Accept-Encoding", "")
    upgrade_insecure = request.headers.get("Upgrade-Insecure-Requests", "")

    score = 0

    if not user_agent:
        return False

    bot_patterns = [
        'curl', 'wget', 'python', 'java', 'go-http', 'okhttp',
        'axios', 'node-fetch', 'scrapy', 'bot', 'spider', 'crawl',
        'postman', 'insomnia', 'httpie', 'perl', 'ruby', 'php',
        'scanner', 'nikto', 'nmap', 'masscan', 'metasploit'
    ]

    for pattern in bot_patterns:
        if pattern in user_agent:
            return False

    browser_patterns = [
        'mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera',
        'msie', 'trident', 'webkit', 'gecko', 'applewebkit'
    ]

    has_browser_ua = False
    for pattern in browser_patterns:
        if pattern in user_agent:
            has_browser_ua = True
            score += 1
            break

    if not has_browser_ua:
        return False

    if 'text/html' in accept:
        score += 2

    if accept_language:
        score += 1

    if 'gzip' in accept_encoding or 'deflate' in accept_encoding:
        score += 1

    if sec_fetch_site or sec_fetch_mode or sec_fetch_dest:
        score += 2

    if upgrade_insecure == "1":
        score += 1

    if len(user_agent) > 50:
        score += 1

    return score >= 4

def ban_ip_via_firewall(ip: str) -> bool:

    if ip == "unknown" or ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10."):
        return False

    try:

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

        cleanup_old_ips()

        ip = get_real_ip(request)
        now = datetime.utcnow()


        if ip in banned_ips:
            logger.warning(f"[BLOCKED] {ip} tried to access but is banned.")
            return HTMLResponse("<h1>403 Forbidden</h1><p>You are banned.</p>", status_code=403)


        ip_request_log[ip] = [t for t in ip_request_log[ip] if (now - t).total_seconds() <= 10]
        ip_request_log[ip].append(now)


        recent_1s = [t for t in ip_request_log[ip] if (now - t).total_seconds() <= 1]
        recent_10s = ip_request_log[ip]


        if len(recent_10s) > RATE_LIMIT_BAN:
            if ban_ip_via_firewall(ip):
                logger.warning(f"[BANNED] IP {ip} permanently banned via UFW ({len(recent_10s)} requests in 10s).")
            banned_ips.add(ip)
            save_banned_ips()
            return HTMLResponse(
                "<h1>429 Too Many Requests</h1><p>You are permanently banned for excessive requests.</p>",
                status_code=429
            )


        if len(recent_10s) > RATE_LIMIT_BURST:
            logger.info(f"[RATE LIMITED] IP {ip} exceeded burst limit ({len(recent_10s)} requests in 10s).")
            return HTMLResponse(
                "<h1>429 Too Many Requests</h1><p>Too many requests. Please slow down.</p>",
                status_code=429
            )


        if len(recent_1s) > RATE_LIMIT_STRICT:
            logger.info(f"[RATE LIMITED] IP {ip} exceeded strict limit ({len(recent_1s)} requests/sec).")
            return HTMLResponse(
                "<h1>429 Too Many Requests</h1><p>Request rate too high. Slow down.</p>",
                status_code=429
            )

        return await call_next(request)
        
        
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="LinkShare Pro",
    description="URL Shortener & File Sharing API",
    max_upload_size=52428800
)
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
    try:
        serializable = {
            k: {
                **v,
                "created_at": v["created_at"].isoformat() if isinstance(v.get("created_at"), datetime) else v.get("created_at"),
                "expires_at": v["expires_at"].isoformat() if isinstance(v.get("expires_at"), datetime) else v.get("expires_at"),
                "last_accessed": v["last_accessed"].isoformat() if isinstance(v.get("last_accessed"), datetime) else v.get("last_accessed")
            } for k, v in uploaded_files.items()
        }


        if os.path.exists(UPLOADED_FILES_FILE):
            backup_file = f"{UPLOADED_FILES_FILE}.backup"
            shutil.copy2(UPLOADED_FILES_FILE, backup_file)


        temp_file = f"{UPLOADED_FILES_FILE}.tmp"
        with open(temp_file, "w") as f:
            json.dump(serializable, f, indent=2)


        os.replace(temp_file, UPLOADED_FILES_FILE)

    except Exception as e:
        logger.error(f"Error saving uploaded files: {e}")


def load_uploaded_files():

    files_to_try = [UPLOADED_FILES_FILE, f"{UPLOADED_FILES_FILE}.backup"]

    for file_path in files_to_try:
        if not os.path.exists(file_path):
            continue

        try:
            with open(file_path, "r") as f:
                data = json.load(f)


            for fname, meta in data.items():
                try:

                    if meta.get("created_at"):
                        meta["created_at"] = datetime.fromisoformat(meta["created_at"]) if isinstance(meta["created_at"], str) else meta["created_at"]

                    if meta.get("expires_at"):
                        meta["expires_at"] = datetime.fromisoformat(meta["expires_at"]) if isinstance(meta["expires_at"], str) else meta["expires_at"]

                    if meta.get("last_accessed"):
                        meta["last_accessed"] = datetime.fromisoformat(meta["last_accessed"]) if isinstance(meta["last_accessed"], str) else None

                    uploaded_files[fname] = meta
                except Exception as e:
                    logger.error(f"Error parsing file metadata for {fname}: {e}")

                    continue

            logger.info(f"Successfully loaded {len(uploaded_files)} uploaded files from {file_path}")
            return

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {file_path}: {e}")
            if file_path == UPLOADED_FILES_FILE:
                logger.info("Attempting to load from backup...")
                continue
            else:
                logger.error("Backup file also corrupt, starting fresh")
                break

        except Exception as e:
            logger.error(f"Error loading uploaded files from {file_path}: {e}")
            continue


    logger.warning("Could not load uploaded files, starting with empty database")
    uploaded_files.clear()

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
load_banned_ips()
load_biolinks()


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
def index(request: Request):
    if not is_browser_request(request):
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("<h1>403</h1>")
    except Exception as e:
        logger.error(f"Error reading index.html: {str(e)}")
        return HTMLResponse("<h1>403</h1>")

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
def generate_qr(code: str, request: Request):
    client_ip = get_real_ip(request)


    if code in qr_cache:
        buffer = BytesIO(qr_cache[code])
        return StreamingResponse(buffer, media_type="image/png")


    if not check_qr_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail=f"Too many QR code requests. Limit: {MAX_QR_REQUESTS_PER_MINUTE}/minute")

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
    qr_data = buffer.getvalue()


    if len(qr_cache) < QR_CACHE_MAX_SIZE:
        qr_cache[code] = qr_data

    buffer = BytesIO(qr_data)
    return StreamingResponse(buffer, media_type="image/png")

@app.get("/upload-progress/{upload_id}")
def get_upload_progress(upload_id: str):
    return upload_progress.get(upload_id, {"progress": 0, "speed": 0, "status": "not_found"})

@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...), filename: Optional[str] = Form(None), password: Optional[str] = Form(None), expire_value: Optional[int] = Form(None), expire_unit: Optional[str] = Form(None), upload_id: Optional[str] = Form(None)):
    try:
        client_ip = get_real_ip(request)
        if active_uploads[client_ip] >= MAX_CONCURRENT_UPLOADS_PER_IP:
            raise HTTPException(status_code=429, detail=f"Too many concurrent uploads")
        active_uploads[client_ip] += 1
        if not file.filename:
            active_uploads[client_ip] -= 1
            raise HTTPException(status_code=400, detail="No file selected")
        upload_id = upload_id or generate_code(12)
        upload_progress[upload_id] = {"progress": 0, "speed": 0, "status": "reading", "uploaded": 0, "total": 0}
        file_content = await file.read()
        file_size = len(file_content)
        if file_size > 50 * 1024 * 1024:
            active_uploads[client_ip] -= 1
            raise HTTPException(status_code=400, detail="Max file size is 50MB")
        if file_size == 0:
            active_uploads[client_ip] -= 1
            raise HTTPException(status_code=400, detail="Empty files not allowed")
        upload_progress[upload_id]["total"] = file_size
        upload_progress[upload_id]["status"] = "encrypting"
        file_key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(file_content)
        encrypted_content = nonce + tag + ciphertext
        encrypted_key = file_key
        if password:
            password_hash = hashlib.sha256(password.encode()).digest()
            key_cipher = AES.new(password_hash, AES.MODE_GCM)
            key_ciphertext, key_tag = key_cipher.encrypt_and_digest(file_key)
            encrypted_key = key_cipher.nonce + key_tag + key_ciphertext
        file_hmac = compute_hmac(encrypted_content)
        ext = os.path.splitext(file.filename)[1]
        name = filename.strip() if filename else generate_code()
        name = "".join(c for c in name if c.isalnum() or c in ('-', '_')).rstrip()
        final_name = f"{name}{ext}"
        internal_name = f"{final_name}.enc"
        path = os.path.join(STORAGE_DIR, internal_name)
        counter = 1
        while os.path.exists(path):
            final_name = f"{name}_{counter}{ext}"
            internal_name = f"{final_name}.enc"
            path = os.path.join(STORAGE_DIR, internal_name)
            counter += 1
        with open(path, "wb") as buffer:
            buffer.write(encrypted_content)
        upload_progress[upload_id]["status"] = "completed"
        upload_progress[upload_id]["progress"] = 100
        expires_at = calculate_expiry(expire_value, expire_unit)
        uploaded_files[final_name] = {
            "path": path,
            "expires_at": expires_at,
            "original_name": file.filename,
            "size": file_size,
            "encrypted_size": len(encrypted_content),
            "created_at": datetime.utcnow(),
            "encryption_key": base64.b64encode(encrypted_key).decode(),
            "has_password": password is not None,
            "hmac": file_hmac,
            "downloads": 0
        }
        save_uploaded_files()

        asyncio.create_task(cleanup_progress(upload_id))

        url = f"https://nauval.cloud/download/{final_name}"


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
async def download_file(filename: str, password: Optional[str] = None):
    try:
        data = uploaded_files.get(filename)
        if not data:
            data = uploaded_files.get(f"{filename}.enc")
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
        
        if not data.get("encryption_key"):
            data["downloads"] = data.get("downloads", 0) + 1
            data["last_accessed"] = datetime.utcnow()
            save_uploaded_files()
            return FileResponse(data["path"], filename=data.get("original_name", filename), media_type='application/octet-stream')
        
        if data.get("has_password") and not password:
            raise HTTPException(status_code=401, detail="Password required")
        with open(data["path"], "rb") as f:
            encrypted_content = f.read()
        if data.get("hmac") and not verify_hmac(encrypted_content, data.get("hmac", "")):
            raise HTTPException(status_code=500, detail="File integrity check failed")
        try:
            encrypted_key = base64.b64decode(data["encryption_key"])
            if data.get("has_password"):
                if not password:
                    raise HTTPException(status_code=401, detail="Password required")
                password_hash = hashlib.sha256(password.encode()).digest()
                key_nonce = encrypted_key[:12]
                key_tag = encrypted_key[12:28]
                key_ciphertext = encrypted_key[28:]
                key_cipher = AES.new(password_hash, AES.MODE_GCM, nonce=key_nonce)
                file_key = key_cipher.decrypt_and_verify(key_ciphertext, key_tag)
            else:
                file_key = encrypted_key
            nonce = encrypted_content[:12]
            tag = encrypted_content[12:28]
            ciphertext = encrypted_content[28:]
            cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
            file_content = cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise HTTPException(status_code=401, detail="Invalid password or corrupted file")
        data["downloads"] = data.get("downloads", 0) + 1
        data["last_accessed"] = datetime.utcnow()
        save_uploaded_files()
        return StreamingResponse(
            BytesIO(file_content),
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename={data.get('original_name', filename)}"}
        )
    except HTTPException:
        raise
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
    client_ip = get_real_ip(request)


    if not check_creation_limit(client_ip, "html", MAX_HTML_PAGES_PER_IP):
        raise HTTPException(status_code=429, detail=f"Too many HTML pages created. Limit: {MAX_HTML_PAGES_PER_IP} per IP")

    if not file.filename.endswith(".html"):
        raise HTTPException(status_code=400, detail="Only .html files allowed")


    if not code.isalnum() or len(code) < 3 or len(code) > 20:
        raise HTTPException(status_code=400, detail="Code must be alphanumeric and 3-20 characters")

    if code in html_pages:
        raise HTTPException(status_code=400, detail="Code already used")

    if expire_days > 7 or expire_days < 1:
        raise HTTPException(status_code=400, detail="Expire must be between 1 and 7 days")


    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="HTML file too large (max 5MB)")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file not allowed")

    filename = f"{code}.html"
    filepath = os.path.join(HTML_STORAGE_DIR, filename)


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
def view_uploaded_html_page(code: str, request: Request):
    if not is_browser_request(request):
        raise HTTPException(status_code=403, detail="Forbidden")

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


load_snippets()

@app.post("/snippet")
async def create_snippet(
    request: Request,
    code: str = Form(...),
    content: str = Form(...),
    language: str = Form("text"),
    expire_value: Optional[int] = Form(None),
    expire_unit: Optional[str] = Form(None),
    password: Optional[str] = Form(None)
):

    try:
        client_ip = get_real_ip(request)


        if not check_creation_limit(client_ip, "snippets", MAX_SNIPPETS_PER_IP):
            raise HTTPException(status_code=429, detail=f"Too many snippets created. Limit: {MAX_SNIPPETS_PER_IP} per IP")


        if not code.replace('-', '').replace('_', '').isalnum() or len(code) < 3 or len(code) > 30:
            raise HTTPException(status_code=400, detail="Code must be alphanumeric (3-30 chars)")

        if code in text_snippets:
            raise HTTPException(status_code=400, detail="Code already exists")


        if len(content) > 1 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Content too large (max 1MB)")

        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Content cannot be empty")


        expires_at = calculate_expiry(expire_value, expire_unit)


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
    if not is_browser_request(request):
        raise HTTPException(status_code=403, detail="Forbidden")
    return FileResponse("snippet_viewer.html")

@app.get("/api/snippet/{code}")
async def view_snippet(code: str, password: Optional[str] = None):

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

    return {
        "content": snippet["content"],
        "language": snippet["language"],
        "created_at": snippet["created_at"].isoformat(),
        "expires_at": snippet["expires_at"].isoformat() if snippet["expires_at"] else None
    }

@app.get("/snippet/{code}/raw")
async def view_snippet_raw(code: str, password: Optional[str] = None):

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
def get_stats(request: Request, admin_token: Optional[str] = None):
    try:
        client_ip = get_real_ip(request)


        basic_stats = {
            "total_urls": len(short_urls),
            "total_files": len(uploaded_files),
            "total_snippets": len(text_snippets),
            "total_biolinks": len(biolinks)
        }


        if admin_token == os.getenv("ADMIN_TOKEN"):
            basic_stats.update({
                "total_html_pages": len(html_pages),
                "storage_dir": STORAGE_DIR,
                "html_dir": HTML_STORAGE_DIR,
                "banned_ips_count": len(banned_ips),
                "tracked_ips": len(ip_request_log),
                "qr_cache_size": len(qr_cache)
            })

        return basic_stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload/image")
async def upload_image(
    request: Request,
    file: UploadFile = File(...)
):

    try:
        client_ip = get_real_ip(request)


        if not check_image_upload_limit(client_ip):
            raise HTTPException(status_code=429, detail=f"Too many image uploads. Limit: {MAX_IMAGE_UPLOADS_PER_HOUR}/hour")


        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="Only image files allowed")

        allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
        if file.content_type not in allowed_types:
            raise HTTPException(status_code=400, detail=f"Supported formats: JPEG, PNG, GIF, WEBP")


        image_data = await file.read()


        if len(image_data) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Image too large (max 10MB)")


        try:
            img = Image.open(BytesIO(image_data))


            img.verify()


            img = Image.open(BytesIO(image_data))


            if img.mode == 'RGBA':
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3])
                img = background
            elif img.mode not in ('RGB', 'L'):
                img = img.convert('RGB')


            max_size = 1200
            if img.width > max_size or img.height > max_size:
                img.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)


            image_hash = hashlib.md5(image_data).hexdigest()[:12]
            ext = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
            filename = f"{image_hash}.{ext}"
            filepath = os.path.join(IMAGES_DIR, filename)


            img.save(filepath, optimize=True, quality=85)


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

    filepath = os.path.join(IMAGES_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Image not found")
    return FileResponse(filepath)


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

    try:
        client_ip = get_real_ip(request)


        if not check_creation_limit(client_ip, "biolinks", MAX_BIOLINKS_PER_IP):
            raise HTTPException(status_code=429, detail=f"Too many bio links created. Limit: {MAX_BIOLINKS_PER_IP} per IP")


        if not username.replace('-', '').replace('_', '').isalnum() or len(username) < 3 or len(username) > 30:
            raise HTTPException(status_code=400, detail="Username must be alphanumeric (3-30 chars)")


        try:
            links_data = json.loads(links)
            social_data = json.loads(social_links)
        except:
            raise HTTPException(status_code=400, detail="Invalid JSON data for links")


        valid_themes = ['cosmic', 'minimal', 'gradient', 'dark', 'neon', 'ocean', 'sunset', 'forest']
        if theme not in valid_themes:
            theme = 'cosmic'


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
async def view_biolink(username: str, request: Request):
    if not is_browser_request(request):
        raise HTTPException(status_code=403, detail="Forbidden")

    biolink = biolinks.get(username)
    if not biolink:
        raise HTTPException(status_code=404, detail="Bio link not found")

    biolink["views"] = biolink.get("views", 0) + 1

    if biolink["views"] % 10 == 0:
        save_biolinks()

    return FileResponse("biolink_viewer.html")

@app.get("/api/biolink/{username}")
async def get_biolink_data(username: str):

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

    biolink = biolinks.get(username)
    if not biolink:
        raise HTTPException(status_code=404, detail="Bio link not found")

    if "clicks" not in biolink:
        biolink["clicks"] = {}

    biolink["clicks"][link_id] = biolink["clicks"].get(link_id, 0) + 1
    save_biolinks()

    return {"success": True}

@app.post("/upload/bulk")
async def bulk_upload(request: Request, files: List[UploadFile] = File(...), password: Optional[str] = Form(None), expire_value: Optional[int] = Form(None), expire_unit: Optional[str] = Form(None)):
    try:
        if len(files) > 20:
            raise HTTPException(status_code=400, detail="Maximum 20 files per bulk upload")
        results = []
        for file in files:
            try:
                file_content = await file.read()
                if len(file_content) > 50 * 1024 * 1024:
                    results.append({"filename": file.filename, "success": False, "error": "File too large"})
                    continue
                file_key = get_random_bytes(32)
                nonce = get_random_bytes(12)
                cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(file_content)
                encrypted_content = nonce + tag + ciphertext
                encrypted_key = file_key
                if password:
                    password_hash = hashlib.sha256(password.encode()).digest()
                    key_cipher = AES.new(password_hash, AES.MODE_GCM)
                    key_ciphertext, key_tag = key_cipher.encrypt_and_digest(file_key)
                    encrypted_key = key_cipher.nonce + key_tag + key_ciphertext
                file_hmac = compute_hmac(encrypted_content)
                ext = os.path.splitext(file.filename)[1]
                final_name = f"{generate_code()}{ext}"
                internal_name = f"{final_name}.enc"
                path = os.path.join(STORAGE_DIR, internal_name)
                with open(path, "wb") as buffer:
                    buffer.write(encrypted_content)
                expires_at = calculate_expiry(expire_value, expire_unit)
                uploaded_files[final_name] = {
                    "path": path,
                    "expires_at": expires_at,
                    "original_name": file.filename,
                    "size": len(file_content),
                    "created_at": datetime.utcnow(),
                    "encryption_key": base64.b64encode(encrypted_key).decode(),
                    "has_password": password is not None,
                    "hmac": file_hmac,
                    "downloads": 0
                }
                url = f"https://nauval.cloud/download/{final_name}"
                results.append({"filename": file.filename, "success": True, "url": url, "code": final_name})
            except Exception as e:
                results.append({"filename": file.filename, "success": False, "error": str(e)})
        save_uploaded_files()
        return {"total": len(files), "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download/bulk")
async def bulk_download(codes: str, password: Optional[str] = None):
    try:
        file_codes = [c.strip() for c in codes.split(',') if c.strip()]
        if len(file_codes) > 20:
            raise HTTPException(status_code=400, detail="Maximum 20 files")


        total_size = 0
        max_bulk_size = 200 * 1024 * 1024
        for code in file_codes:
            data = uploaded_files.get(code)
            if data and os.path.exists(data["path"]):
                total_size += data.get("size", 0)
                if total_size > max_bulk_size:
                    raise HTTPException(status_code=400, detail=f"Total file size exceeds {max_bulk_size // (1024*1024)}MB limit")

        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for code in file_codes:
                data = uploaded_files.get(code)
                if data and os.path.exists(data["path"]):
                    try:
                        with open(data["path"], "rb") as f:
                            encrypted_content = f.read()


                        if not data.get("encryption_key"):
                            with open(data["path"], "rb") as f:
                                file_content = f.read()
                            zip_file.writestr(data.get("original_name", code), file_content)
                            continue

                        encrypted_key = base64.b64decode(data["encryption_key"])
                        if data.get("has_password"):
                            if not password:
                                continue
                            password_hash = hashlib.sha256(password.encode()).digest()
                            key_nonce = encrypted_key[:12]
                            key_tag = encrypted_key[12:28]
                            key_ciphertext = encrypted_key[28:]
                            key_cipher = AES.new(password_hash, AES.MODE_GCM, nonce=key_nonce)
                            file_key = key_cipher.decrypt_and_verify(key_ciphertext, key_tag)
                        else:
                            file_key = encrypted_key
                        nonce = encrypted_content[:12]
                        tag = encrypted_content[12:28]
                        ciphertext = encrypted_content[28:]
                        cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
                        file_content = cipher.decrypt_and_verify(ciphertext, tag)
                        zip_file.writestr(data.get("original_name", code), file_content)
                    except:
                        continue
        zip_buffer.seek(0)
        return StreamingResponse(zip_buffer, media_type='application/zip', headers={"Content-Disposition": "attachment; filename=cloudshare-files.zip"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats/file/{filename}")
async def get_file_stats(filename: str):
    try:
        data = uploaded_files.get(filename)
        if not data:
            raise HTTPException(status_code=404, detail="File not found")
        return {
            "filename": filename,
            "original_name": data.get("original_name"),
            "size": data.get("size"),
            "created_at": data.get("created_at").isoformat() if data.get("created_at") else None,
            "expires_at": data.get("expires_at").isoformat() if data.get("expires_at") else None,
            "downloads": data.get("downloads", 0),
            "last_accessed": data.get("last_accessed").isoformat() if data.get("last_accessed") else None,
            "encrypted": True,
            "has_password": data.get("has_password", False)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
