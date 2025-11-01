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
ANALYTICS_FILE = "analytics.json"

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(HTML_STORAGE_DIR, exist_ok=True)

short_urls = {}
uploaded_files = {}
upload_progress = {}
html_pages = {}
analytics = {}


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

def save_analytics():
    serializable = {}
    for key, val in analytics.items():
        serializable[key] = {
            "total_clicks": val["total_clicks"],
            "last_clicked": val["last_clicked"].isoformat() if val["last_clicked"] else None,
            "click_history": [c.isoformat() for c in val["click_history"]],
            "referrers": val["referrers"],
            "user_agents": val["user_agents"],
            "countries": val.get("countries", {})
        }
    with open(ANALYTICS_FILE, "w") as f:
        json.dump(serializable, f, indent=2)

def load_analytics():
    if os.path.exists(ANALYTICS_FILE):
        with open(ANALYTICS_FILE, "r") as f:
            data = json.load(f)
            for key, val in data.items():
                analytics[key] = {
                    "total_clicks": val["total_clicks"],
                    "last_clicked": datetime.fromisoformat(val["last_clicked"]) if val["last_clicked"] else None,
                    "click_history": [datetime.fromisoformat(c) for c in val["click_history"]],
                    "referrers": val["referrers"],
                    "user_agents": val["user_agents"],
                    "countries": val.get("countries", {})
                }

def track_click(code: str, request: Request):
    if code not in analytics:
        analytics[code] = {
            "total_clicks": 0,
            "last_clicked": None,
            "click_history": [],
            "referrers": {},
            "user_agents": {},
            "countries": {}
        }

    analytics[code]["total_clicks"] += 1
    analytics[code]["last_clicked"] = datetime.utcnow()
    analytics[code]["click_history"].append(datetime.utcnow())

    # Keep only last 100 clicks
    if len(analytics[code]["click_history"]) > 100:
        analytics[code]["click_history"] = analytics[code]["click_history"][-100:]

    # Track referrer
    referrer = request.headers.get("referer", "direct")
    analytics[code]["referrers"][referrer] = analytics[code]["referrers"].get(referrer, 0) + 1

    # Track user agent
    user_agent = request.headers.get("user-agent", "unknown")[:50]
    analytics[code]["user_agents"][user_agent] = analytics[code]["user_agents"].get(user_agent, 0) + 1

    save_analytics()

load_short_urls()
load_uploaded_files()
load_html_metadata()
load_analytics()


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

def generate_qr_base64(url: str, fill_color: str = "black", back_color: str = "white") -> str:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color=fill_color, back_color=back_color)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"

def generate_qr_image(url: str, fill_color: str = "black", back_color: str = "white") -> BytesIO:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color=fill_color, back_color=back_color)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer



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
def shorten_url(
    original_url: str = Form(...),
    custom_alias: Optional[str] = Form(None),
    expires_in_minutes: Optional[int] = Form(None),
    password: Optional[str] = Form(None)
):
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
            "created_at": datetime.utcnow(),
            "password": password.strip() if password else None
        }
        save_short_urls()

        short_url = f"https://nauval.cloud/s/{code}"
        return {
            "short_url": short_url,
            "expires_at": expiry.isoformat() if expiry else None,
            "code": code,
            "qr_code_url": f"https://nauval.cloud/qr/{code}",
            "qr_code_base64": generate_qr_base64(short_url),
            "password_protected": bool(password)
        }
    except Exception as e:
        logger.error(f"Error shortening URL: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/s/{code}")
def redirect_short_url(code: str, request: Request):
    try:
        data = short_urls.get(code)
        if not data:
            raise HTTPException(status_code=404, detail="Short URL not found")
        if data["expires_at"] and datetime.utcnow() > data["expires_at"]:
            del short_urls[code]
            save_short_urls()
            raise HTTPException(status_code=410, detail="Short URL expired")

        # Check password protection
        if data.get("password"):
            # Return password prompt page instead of direct redirect
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"><title>Password Required</title>
            <style>body{{font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;background:#f5f5f5}}
            .box{{background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center}}
            input{{padding:10px;margin:10px 0;width:250px;border:1px solid #ddd;border-radius:5px}}
            button{{padding:10px 30px;background:#007bff;color:white;border:none;border-radius:5px;cursor:pointer}}
            button:hover{{background:#0056b3}}</style></head>
            <body><div class="box"><h2>🔒 Password Required</h2><p>This link is password protected</p>
            <form method="post" action="/s/{code}/unlock">
            <input type="password" name="password" placeholder="Enter password" required>
            <br><button type="submit">Unlock</button></form></div></body></html>
            """)

        # Track click
        track_click(f"url_{code}", request)

        return RedirectResponse(data["url"])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Redirect error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/s/{code}/unlock")
def unlock_short_url(code: str, password: str = Form(...), request: Request = None):
    try:
        data = short_urls.get(code)
        if not data:
            raise HTTPException(status_code=404, detail="Short URL not found")

        if data.get("password") != password:
            return HTMLResponse("""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"><title>Wrong Password</title>
            <style>body{font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;background:#f5f5f5}
            .box{background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center}
            .error{color:red;margin-bottom:15px}</style></head>
            <body><div class="box"><div class="error">❌ Wrong Password</div>
            <a href="javascript:history.back()">← Go Back</a></div></body></html>
            """, status_code=401)

        # Track click
        track_click(f"url_{code}", request)

        return RedirectResponse(data["url"])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unlock error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/qr/{code}")
def generate_qr(code: str, fg: Optional[str] = None, bg: Optional[str] = None):
    if code in short_urls:
        target = f"https://nauval.cloud/s/{code}"
    elif code in uploaded_files:
        target = f"https://nauval.cloud/download/{code}"
    else:
        raise HTTPException(status_code=404, detail="Code not found")

    fill_color = fg if fg else "black"
    back_color = bg if bg else "white"

    buffer = generate_qr_image(target, fill_color, back_color)
    return StreamingResponse(buffer, media_type="image/png")

@app.get("/upload-progress/{upload_id}")
def get_upload_progress(upload_id: str):
    return upload_progress.get(upload_id, {"progress": 0, "speed": 0, "status": "not_found"})

@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    filename: Optional[str] = Form(None),
    expire_value: Optional[int] = Form(None),
    expire_unit: Optional[str] = Form(None),
    upload_id: Optional[str] = Form(None),
    password: Optional[str] = Form(None)
):
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
            "created_at": datetime.utcnow(),
            "password": password.strip() if password else None
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
            "upload_id": upload_id,
            "password_protected": bool(password)
        }
    except Exception as e:
        upload_progress[upload_id]["status"] = "error"
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

async def cleanup_progress(upload_id: str):
    await asyncio.sleep(300)
    upload_progress.pop(upload_id, None)

@app.get("/download/{filename}")
def download_file(filename: str, request: Request):
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

        # Check password protection
        if data.get("password"):
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"><title>Password Required</title>
            <style>body{{font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;background:#f5f5f5}}
            .box{{background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center}}
            input{{padding:10px;margin:10px 0;width:250px;border:1px solid #ddd;border-radius:5px}}
            button{{padding:10px 30px;background:#28a745;color:white;border:none;border-radius:5px;cursor:pointer}}
            button:hover{{background:#218838}}</style></head>
            <body><div class="box"><h2>🔒 Password Required</h2><p>File: {data.get('original_name', filename)}</p>
            <form method="post" action="/download/{filename}/unlock">
            <input type="password" name="password" placeholder="Enter password" required>
            <br><button type="submit">Download</button></form></div></body></html>
            """)

        # Track download
        track_click(f"file_{filename}", request)

        return FileResponse(data["path"], filename=data.get("original_name", filename), media_type='application/octet-stream')
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/download/{filename}/unlock")
def unlock_file(filename: str, password: str = Form(...), request: Request = None):
    try:
        data = uploaded_files.get(filename)
        if not data:
            raise HTTPException(status_code=404, detail="File not found")

        if data.get("password") != password:
            return HTMLResponse("""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"><title>Wrong Password</title>
            <style>body{font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;background:#f5f5f5}
            .box{background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center}
            .error{color:red;margin-bottom:15px}</style></head>
            <body><div class="box"><div class="error">❌ Wrong Password</div>
            <a href="javascript:history.back()">← Go Back</a></div></body></html>
            """, status_code=401)

        # Track download
        track_click(f"file_{filename}", request)

        return FileResponse(data["path"], filename=data.get("original_name", filename), media_type='application/octet-stream')
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unlock file error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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

@app.post("/batch-shorten")
def batch_shorten_urls(urls: list = Form(...)):
    """Shorten multiple URLs at once"""
    try:
        import json as json_lib
        urls_list = json_lib.loads(urls) if isinstance(urls, str) else urls
        results = []

        for url in urls_list:
            try:
                if not url.startswith(('http://', 'https://')):
                    results.append({"url": url, "error": "Invalid URL format"})
                    continue

                code = generate_code()
                short_urls[code] = {
                    "url": url,
                    "expires_at": None,
                    "created_at": datetime.utcnow(),
                    "password": None
                }

                short_url = f"https://nauval.cloud/s/{code}"
                results.append({
                    "original_url": url,
                    "short_url": short_url,
                    "code": code,
                    "qr_code_url": f"https://nauval.cloud/qr/{code}"
                })
            except Exception as e:
                results.append({"url": url, "error": str(e)})

        save_short_urls()
        return {"results": results, "total": len(results)}
    except Exception as e:
        logger.error(f"Batch shorten error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics/{code}")
def get_analytics(code: str):
    """Get detailed analytics for a specific URL or file"""
    # Check if it's a URL or file
    key = f"url_{code}" if code in short_urls else f"file_{code}"

    if key not in analytics:
        return {
            "code": code,
            "total_clicks": 0,
            "last_clicked": None,
            "click_history": [],
            "referrers": {},
            "user_agents": {},
            "message": "No analytics data yet"
        }

    data = analytics[key]
    return {
        "code": code,
        "total_clicks": data["total_clicks"],
        "last_clicked": data["last_clicked"].isoformat() if data["last_clicked"] else None,
        "recent_clicks": [c.isoformat() for c in data["click_history"][-20:]],
        "top_referrers": dict(sorted(data["referrers"].items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_user_agents": dict(sorted(data["user_agents"].items(), key=lambda x: x[1], reverse=True)[:5])
    }

@app.get("/manage/urls")
def list_urls(limit: int = 50, offset: int = 0):
    """List all shortened URLs with pagination"""
    try:
        urls_list = []
        for code, data in list(short_urls.items())[offset:offset+limit]:
            analytics_key = f"url_{code}"
            clicks = analytics.get(analytics_key, {}).get("total_clicks", 0)

            urls_list.append({
                "code": code,
                "url": data["url"],
                "created_at": data["created_at"].isoformat(),
                "expires_at": data["expires_at"].isoformat() if data["expires_at"] else None,
                "password_protected": bool(data.get("password")),
                "clicks": clicks,
                "short_url": f"https://nauval.cloud/s/{code}"
            })

        return {
            "urls": urls_list,
            "total": len(short_urls),
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"List URLs error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/manage/files")
def list_files(limit: int = 50, offset: int = 0):
    """List all uploaded files with pagination"""
    try:
        files_list = []
        for filename, data in list(uploaded_files.items())[offset:offset+limit]:
            analytics_key = f"file_{filename}"
            downloads = analytics.get(analytics_key, {}).get("total_clicks", 0)

            files_list.append({
                "filename": filename,
                "original_name": data.get("original_name", filename),
                "size": data.get("size", 0),
                "created_at": data["created_at"].isoformat(),
                "expires_at": data["expires_at"].isoformat() if data["expires_at"] else None,
                "password_protected": bool(data.get("password")),
                "downloads": downloads,
                "file_url": f"https://nauval.cloud/download/{filename}"
            })

        return {
            "files": files_list,
            "total": len(uploaded_files),
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"List files error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/manage/url/{code}")
def delete_url(code: str):
    """Delete a shortened URL"""
    try:
        if code not in short_urls:
            raise HTTPException(status_code=404, detail="URL not found")

        del short_urls[code]
        save_short_urls()

        # Clean up analytics
        analytics_key = f"url_{code}"
        if analytics_key in analytics:
            del analytics[analytics_key]
            save_analytics()

        return {"message": "URL deleted successfully", "code": code}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete URL error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/manage/file/{filename}")
def delete_file(filename: str):
    """Delete an uploaded file"""
    try:
        if filename not in uploaded_files:
            raise HTTPException(status_code=404, detail="File not found")

        data = uploaded_files[filename]

        # Delete physical file
        try:
            if os.path.exists(data["path"]):
                os.remove(data["path"])
        except Exception as e:
            logger.warning(f"Could not delete physical file: {e}")

        del uploaded_files[filename]
        save_uploaded_files()

        # Clean up analytics
        analytics_key = f"file_{filename}"
        if analytics_key in analytics:
            del analytics[analytics_key]
            save_analytics()

        return {"message": "File deleted successfully", "filename": filename}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete file error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/preview/{filename}")
def preview_file(filename: str, request: Request):
    """Preview image or PDF files in browser"""
    try:
        data = uploaded_files.get(filename)
        if not data or not os.path.exists(data["path"]):
            raise HTTPException(status_code=404, detail="File not found")

        if data["expires_at"] and datetime.utcnow() > data["expires_at"]:
            raise HTTPException(status_code=410, detail="File expired")

        # Check password
        if data.get("password"):
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"><title>Password Required</title>
            <style>body{{font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;background:#f5f5f5}}
            .box{{background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center}}</style></head>
            <body><div class="box"><h2>🔒 Password Required</h2>
            <p>This file is password protected</p>
            <a href="/download/{filename}">Go to download page</a></div></body></html>
            """)

        # Check file type
        ext = os.path.splitext(filename)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            media_type = f"image/{ext[1:]}"
            return FileResponse(data["path"], media_type=media_type)
        elif ext == '.pdf':
            return FileResponse(data["path"], media_type="application/pdf")
        else:
            raise HTTPException(status_code=400, detail="Preview not available for this file type")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Preview error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/redirect/{code}")
def custom_redirect(code: str, countdown: int = 5):
    """Custom redirect page with countdown timer"""
    try:
        data = short_urls.get(code)
        if not data:
            raise HTTPException(status_code=404, detail="Short URL not found")

        if data["expires_at"] and datetime.utcnow() > data["expires_at"]:
            raise HTTPException(status_code=410, detail="Short URL expired")

        target_url = data["url"]
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Redirecting...</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }}
                .box {{
                    background: white;
                    padding: 50px;
                    border-radius: 20px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                    text-align: center;
                    max-width: 500px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 20px;
                }}
                #countdown {{
                    font-size: 72px;
                    color: #667eea;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .url {{
                    color: #666;
                    word-break: break-all;
                    margin: 20px 0;
                    padding: 15px;
                    background: #f5f5f5;
                    border-radius: 10px;
                }}
                .skip {{
                    display: inline-block;
                    margin-top: 20px;
                    padding: 12px 30px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    transition: background 0.3s;
                }}
                .skip:hover {{
                    background: #764ba2;
                }}
            </style>
        </head>
        <body>
            <div class="box">
                <h1>🚀 Redirecting...</h1>
                <div id="countdown">{countdown}</div>
                <div class="url">You will be redirected to:<br><strong>{target_url}</strong></div>
                <a href="{target_url}" class="skip">Skip & Go Now</a>
            </div>
            <script>
                let seconds = {countdown};
                const countdownEl = document.getElementById('countdown');
                const interval = setInterval(() => {{
                    seconds--;
                    countdownEl.textContent = seconds;
                    if (seconds <= 0) {{
                        clearInterval(interval);
                        window.location.href = '{target_url}';
                    }}
                }}, 1000);
            </script>
        </body>
        </html>
        """)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Custom redirect error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
def get_stats():
    try:
        total_clicks = sum(data.get("total_clicks", 0) for data in analytics.values())

        return {
            "total_urls": len(short_urls),
            "total_files": len(uploaded_files),
            "total_html_pages": len(html_pages),
            "total_clicks": total_clicks,
            "storage_dir": STORAGE_DIR,
            "html_dir": HTML_STORAGE_DIR
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
