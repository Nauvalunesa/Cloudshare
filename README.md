# 🚀 CloudShare - End-to-End Encrypted File Sharing Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-Latest-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Security](https://img.shields.io/badge/Security-AES--256--GCM-red.svg)
![Status](https://img.shields.io/badge/Status-Production-success.svg)

**Zero-Knowledge File Sharing Platform with Military-Grade Encryption**

*Owner can't see your files. Period.*

[🌐 Live Demo](https://nauval.cloud) • [🔒 Security](#-security) • [🚀 Quick Start](#-installation)

</div>

---

## 🔐 Why CloudShare?

### **True End-to-End Encryption**
- ✅ Files encrypted with unique AES-256-GCM key per file
- ✅ Server owner **CANNOT** decrypt your files
- ✅ Only you (and password holders) can access content
- ✅ HMAC-SHA256 integrity verification
- ✅ Zero-knowledge architecture

### **How It Works**
```
┌──────────────────────────────────────────────┐
│  UPLOAD (Client-Side Encryption Prep)        │
├──────────────────────────────────────────────┤
│  1. Generate random 32-byte encryption key   │
│  2. Encrypt file with AES-256-GCM            │
│  3. Optional: Encrypt key with password      │
│  4. Upload encrypted file + encrypted key    │
│  5. Server stores ONLY encrypted data        │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│  DOWNLOAD (Automatic Decryption)             │
├──────────────────────────────────────────────┤
│  1. Retrieve encrypted file                  │
│  2. Verify HMAC integrity                    │
│  3. Decrypt encryption key (with password)   │
│  4. Decrypt file content                     │
│  5. Serve original file to user              │
└──────────────────────────────────────────────┘
```

**Server owner can only see:**
- ❌ NOT your file content (encrypted)
- ❌ NOT your encryption key (encrypted)
- ✅ File size, upload date, download count

---

## ✨ Features

### 🔒 **Encrypted File Sharing**
- **AES-256-GCM Encryption** - Unique key per file
- **Password Protection** - Additional encryption layer
- **HMAC Integrity** - Tamper detection
- **Automatic Encryption** - Transparent to users
- **Bulk Upload** - Up to 20 files at once
- **Bulk Download** - ZIP multiple files
- **Download Stats** - Track access count

### 📁 **Google Drive-like Dashboard** ✨ NEW
- **Multi-file Upload** - Single, multiple, or entire folder upload
- **Per-file Progress** - Individual progress bars for each file
- **Session-based Isolation** - Users see only their own files (public mode)
- **Admin System** - Full access to all files with authentication
- **File Management** - Share, delete, rename files with one click
- **File Preview** - Secure preview with share IDs (no filename exposure)
- **Grid & List Views** - Switch between viewing modes
- **Search & Filter** - Find files quickly
- **Storage Statistics** - Track usage with visual charts

### 🔐 **Two-Tier Permission System** ✨ NEW
- **Public Mode**: No login required
  - Upload files anonymously
  - See only your own files (session-based)
  - Share files with unique links
  - Delete and rename your files
- **Admin Mode**: Full control
  - Username: `nauval` / Password: `nauvaldrive`
  - Access to ALL files from all users
  - Advanced file management
  - Server filesystem browser
  - SFTP Manager access

### 🗂️ **File Manager** (Admin Only) ✨ NEW
- **Dual-panel Interface**: Server filesystem ↔ CloudShare Drive
- **Browse Server Files** - Navigate entire server directory structure
- **Copy to Drive** - Import files from server to Drive
- **Create Directories** - Organize files on server
- **Delete Files** - Remove files from server
- **File Permissions** - View file permissions and ownership

### 🔄 **SFTP Manager** ✨ NEW
- **Dual-panel Interface**: Local Device ↔ SFTP Server
- **Local Device Access** - Browse files on your computer (Chrome/Edge)
- **SFTP Client** - Full-featured remote file management
- **File Transfer** - Upload/download between local and remote
- **File Editing** - Built-in code editor with syntax highlighting
- **Advanced Editor Features**:
  - Syntax highlighting for 30+ languages
  - Line numbers
  - Auto-completion
  - Monokai theme
  - Multiple encoding support
- **SFTP Operations**:
  - Create/delete directories
  - File permissions management
  - Single-click folder navigation
  - "Up" button for easy navigation

### 🔗 **URL Shortener**
- Custom branded short links
- QR code generation
- Click analytics
- Expiration management

### 🌟 **Premium Bio Link Builder**
- **8 Stunning Themes** - Cosmic, Minimal, Gradient, Dark, Neon, Ocean, Sunset, Forest
- **Image Uploads** - Profile & cover with optimization
- **Analytics** - Views & click tracking
- **Unlimited Links** - Social media integration
- **Fully Responsive** - Mobile-perfect design

### 💻 **Code Snippet Sharing**
- Syntax highlighting for 18+ languages
- Password protection
- Expiration dates
- Raw text export

### 🛡️ **Enhanced DDoS Protection**
- **Multi-tier Rate Limiting** - 3 req/sec, 10 req/10sec, ban at 30 req/10sec
- **Endpoint-Specific Limits** - QR codes (30/min), Images (50/hour)
- **Resource Creation Limits** - Bio links (5/IP), Snippets (20/IP), HTML (10/IP)
- **Automatic IP Banning** - UFW firewall integration
- **Memory Protection** - QR cache limits, bulk download size checks
- **Disk I/O Optimization** - Batched saves, reduced write operations
- **Request Body Limits** - 50MB max upload size

---

## 🚀 Installation

### Prerequisites
```bash
Python 3.11+
FastAPI
Uvicorn
Pillow
PyCryptodome
QRCode
Python-Multipart
Paramiko (for SFTP Manager)
```

### Quick Start
```bash
# Clone the repository
git clone https://github.com/Nauvalunesa/Cloudshare.git
cd Cloudshare

# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn main:app --host 0.0.0.0 --port 8000
```

Visit `http://localhost:8000`

### Access Features
- **Main Upload**: `http://localhost:8000`
- **Drive Dashboard**: `http://localhost:8000/drive`
- **File Manager** (Admin): `http://localhost:8000/filemanager`
- **SFTP Manager**: `http://localhost:8000/sftpmanager`
- **Bio Link**: `http://localhost:8000/bio`
- **URL Shortener**: `http://localhost:8000/short`

### Admin Access
- **Username**: `nauval`
- **Password**: `nauvaldrive`

---

## 🔐 Security

### **Encryption Specifications**

| Component | Algorithm | Key Size |
|-----------|-----------|----------|
| File Encryption | AES-GCM | 256-bit |
| Key Derivation | SHA-256 | 256-bit |
| Integrity | HMAC-SHA256 | 256-bit |
| Nonce | Random | 96-bit |
| Tag | GCM Auth | 128-bit |

### **Zero-Knowledge Architecture**
```
User File → [Client] → Encrypted → [Server] → Encrypted Storage
                ↓                      ↓
         Unique Key              Encrypted Key
         (per file)             (with password)
```

**Server NEVER sees:**
- Plaintext file content
- Unencrypted encryption keys
- User passwords

### **Password Protection Flow**
```
User Password → SHA-256 → AES-256-GCM → Encrypted Key
                                       ↓
                                  Stored Safely
```

---

## 📡 API Documentation

### **Encrypted File Upload**
```http
POST /upload
Content-Type: multipart/form-data

Parameters:
  file: File (required)
  filename: string (optional)
  password: string (optional) - adds extra encryption layer
  expire_value: integer (optional)
  expire_unit: string (minutes|hours|days)

Response:
{
  "file_url": "https://nauval.cloud/download/abc123.pdf.enc",
  "filename": "abc123.pdf.enc",
  "size": 1048576,
  "encrypted_size": 1048604,
  "has_password": true,
  "qr_code_base64": "data:image/png;base64,..."
}
```

### **Encrypted File Download**
```http
GET /download/{filename}?password=secret

Headers:
  Authorization: Bearer {token} (if password protected)

Response: Decrypted file stream
```

### **Bulk Upload (Multiple Files)**
```http
POST /upload/bulk
Content-Type: multipart/form-data

Parameters:
  files: List[File] (max 20)
  password: string (optional)
  expire_value: integer
  expire_unit: string

Response:
{
  "total": 5,
  "results": [
    {
      "filename": "document.pdf",
      "success": true,
      "url": "https://nauval.cloud/download/xyz789.pdf.enc"
    }
  ]
}
```

### **Bulk Download (ZIP Archive)**
```http
GET /download/bulk?codes=file1,file2,file3&password=secret

Response: ZIP archive with decrypted files
```

### **File Statistics**
```http
GET /stats/file/{filename}

Response:
{
  "filename": "abc123.pdf.enc",
  "original_name": "document.pdf",
  "size": 1048576,
  "downloads": 42,
  "last_accessed": "2025-11-02T10:30:00",
  "encrypted": true,
  "has_password": true
}
```

### **Drive Dashboard API** ✨ NEW

#### Admin Authentication
```http
POST /api/admin/login
Content-Type: multipart/form-data

Parameters:
  username: string (required) - "nauval"
  password: string (required) - "nauvaldrive"

Response:
{
  "success": true,
  "username": "nauval",
  "token": "admin_session_token"
}
```

#### Drive File Upload
```http
POST /api/drive/upload
Content-Type: multipart/form-data

Parameters:
  files: List[File] (required) - Multiple files
  password: string (optional)

Response:
{
  "success": true,
  "files": [
    {
      "filename": "xyz789.pdf.enc",
      "original_name": "document.pdf",
      "share_id": "Abc12XyZ",
      "share_url": "https://nauval.cloud/f/Abc12XyZ",
      "size": 1048576
    }
  ]
}
```

#### List User Files
```http
GET /api/files/list

Headers:
  Cookie: session_id=xxx (auto-sent by browser)

Response:
{
  "files": [
    {
      "filename": "abc123.pdf.enc",
      "original_name": "document.pdf",
      "size": 1048576,
      "uploaded_at": "2025-11-16T10:30:00",
      "is_shared": true,
      "share_id": "Abc12XyZ",
      "downloads": 5
    }
  ]
}
```

#### Share/Unshare File
```http
POST /api/files/share/{filename}

Response:
{
  "success": true,
  "is_shared": true,
  "share_id": "Abc12XyZ",
  "share_url": "https://nauval.cloud/f/Abc12XyZ"
}
```

#### Delete File
```http
DELETE /api/files/delete/{filename}

Response:
{
  "success": true,
  "message": "File deleted successfully"
}
```

#### Rename File
```http
POST /api/files/rename/{filename}
Content-Type: multipart/form-data

Parameters:
  new_name: string (required)

Response:
{
  "success": true,
  "new_filename": "new_name.pdf.enc"
}
```

#### File Preview by Share ID
```http
GET /f/{share_id}

Response: HTML preview page with file info and download link
```

### **File Manager API** (Admin Only) ✨ NEW

#### Browse Server Filesystem
```http
GET /api/filesystem/browse?path=/home/user

Response:
{
  "current_path": "/home/user",
  "items": [
    {
      "name": "documents",
      "path": "/home/user/documents",
      "is_dir": true,
      "size": 4096,
      "permissions": "drwxr-xr-x",
      "modified": "2025-11-16T10:30:00"
    }
  ]
}
```

#### Copy File to Drive
```http
POST /api/filesystem/copy-to-drive
Content-Type: multipart/form-data

Parameters:
  file_path: string (required) - Absolute path on server

Response:
{
  "success": true,
  "filename": "copied_file.pdf.enc"
}
```

#### Create Directory
```http
POST /api/filesystem/mkdir
Content-Type: multipart/form-data

Parameters:
  path: string (required) - Directory path to create

Response:
{
  "success": true,
  "message": "Directory created"
}
```

### **SFTP Manager API** ✨ NEW

#### Connect to SFTP Server
```http
POST /api/sftp/connect
Content-Type: multipart/form-data

Parameters:
  host: string (required)
  port: int (default: 22)
  username: string (required)
  password: string (required)

Response:
{
  "success": true,
  "message": "Connected to host"
}
```

#### List SFTP Directory
```http
GET /api/sftp/list?path=/home/user

Response:
{
  "files": [
    {
      "name": "document.pdf",
      "path": "/home/user/document.pdf",
      "is_dir": false,
      "size": 1048576,
      "permissions": "-rw-r--r--",
      "modified": "2025-11-16T10:30:00"
    }
  ]
}
```

#### Upload to SFTP
```http
POST /api/sftp/upload
Content-Type: multipart/form-data

Parameters:
  file: File (required)
  remote_path: string (required)

Response:
{
  "success": true,
  "message": "File uploaded"
}
```

#### Download from SFTP
```http
GET /api/sftp/download?path=/home/user/file.pdf

Response: File stream
```

#### Read File for Editing
```http
GET /api/sftp/read?path=/home/user/script.py

Response:
{
  "content": "#!/usr/bin/env python\nprint('Hello')",
  "encoding": "utf-8"
}
```

#### Save Edited File
```http
POST /api/sftp/write
Content-Type: multipart/form-data

Parameters:
  path: string (required)
  content: string (required)

Response:
{
  "success": true,
  "message": "File saved"
}
```

---

## 🎨 Bio Link Themes

| Theme | Description | Best For |
|-------|-------------|----------|
| 🌌 **Cosmic** | Purple gradient | Creators, artists |
| ⚪ **Minimal** | Clean gray | Professionals |
| 🌸 **Gradient** | Pink to red | Influencers |
| 🌑 **Dark** | Deep purple | Developers |
| 💡 **Neon** | Cyberpunk | Gamers |
| 🌊 **Ocean** | Blue calm | Wellness |
| 🌅 **Sunset** | Orange warm | Lifestyle |
| 🌲 **Forest** | Green fresh | Eco-brands |

---

## 🛠️ Technology Stack

### Backend
- **Framework**: FastAPI (Python 3.11+)
- **Server**: Uvicorn (ASGI)
- **Encryption**: PyCryptodome (AES-256-GCM)
- **Hashing**: HMAC-SHA256
- **Image Processing**: Pillow
- **QR Codes**: qrcode library
- **SFTP Client**: Paramiko ✨ NEW
- **File Upload**: Python-Multipart

### Frontend
- **Pure JavaScript** (No frameworks)
- **CSS3** with animations
- **Font Awesome 6** icons
- **Prism.js** syntax highlighting (code snippets)
- **Ace Editor** syntax highlighting (SFTP file editing) ✨ NEW
- **Google Fonts** (Poppins)
- **File System Access API** (local device browsing) ✨ NEW
- **Chart.js** (storage statistics) ✨ NEW

### Security
- AES-256-GCM encryption
- HMAC-SHA256 integrity
- Secure random nonce generation
- Zero-knowledge architecture
- Session-based authentication ✨ NEW
- Cookie-based admin tokens ✨ NEW
- DDoS protection

---

## 📖 Usage Guide

### Getting Started with Drive Dashboard

1. **Public Mode** (No Login Required)
   - Visit `/drive` to access the dashboard
   - Upload files using drag & drop or click upload button
   - Choose upload mode: Single file, Multiple files, or Folder
   - View only YOUR files (session-based isolation)
   - Share files to get public preview links
   - Delete or rename your files anytime

2. **Admin Mode** (Full Access)
   - Click the login icon in Drive dashboard
   - Username: `nauval` | Password: `nauvaldrive`
   - See ALL files from all users
   - Access File Manager and SFTP Manager
   - Full control over all files and server

### Using SFTP Manager

1. **Access Local Files**
   - Click "Select Folder" in left panel
   - Grant browser permission (Chrome/Edge required)
   - Browse your local device files

2. **Connect to SFTP Server**
   - Fill in SFTP credentials (host, port, username, password)
   - Click "Connect"
   - Browse remote server in right panel

3. **Transfer Files**
   - **Upload**: Select local file → Click "Upload to SFTP"
   - **Download**: Select SFTP file → Click "Download to Device"

4. **Edit Files**
   - Click "Edit" on any text/code file
   - Use built-in Ace Editor with syntax highlighting
   - Supports 30+ programming languages
   - Auto-detects language from file extension
   - Click "Save" to update file on server

### Using File Manager (Admin Only)

1. Navigate server filesystem
2. Click folders to browse
3. Copy files to Drive with one click
4. Create directories or delete files
5. View file permissions and metadata

### File Preview System

- **Share Link Format**: `https://nauval.cloud/f/{share_id}`
- Share IDs hide actual filenames for privacy
- Anyone with the link can view (if file is shared)
- Supports images, videos, PDFs, audio files
- Download button included in preview

---

## 📊 Performance

- ⚡ **Encryption Speed**: < 100ms for 10MB files
- 🚀 **Upload Throughput**: 50MB max per file
- 📦 **Bulk Operations**: 20 files simultaneously
- 🔄 **Zero Overhead**: Encryption is transparent
- 📱 **Mobile Optimized**: Works on 3G/4G
- 🗂️ **Drive Dashboard**: Real-time progress tracking per file ✨ NEW
- 🔌 **SFTP Performance**: Persistent connections per session ✨ NEW
- 💾 **File Editing**: Syntax highlighting for files up to 10MB ✨ NEW
- 🌐 **Session Management**: Cookie-based, no database overhead ✨ NEW

---

## 🌐 Browser Compatibility

### Recommended Browsers

| Feature | Chrome | Edge | Firefox | Safari |
|---------|--------|------|---------|--------|
| File Upload | ✅ | ✅ | ✅ | ✅ |
| Drive Dashboard | ✅ | ✅ | ✅ | ✅ |
| SFTP Manager | ✅ | ✅ | ⚠️ Limited | ⚠️ Limited |
| File Manager | ✅ | ✅ | ✅ | ✅ |
| Local Device Access | ✅ | ✅ | ❌ | ❌ |

**Note**: SFTP Manager's local device browsing requires **File System Access API**, which is only available in Chrome 86+ and Edge 86+. Firefox and Safari users can still use SFTP features but without local device integration.

---

## 🔧 Configuration

### Environment Variables
```bash
export ENCRYPTION_KEY="your-32-byte-key"
export HMAC_KEY="your-hmac-key"
```

### DDoS Settings (main.py)
```python
# General Rate Limiting
MAX_TRACKED_IPS = 10000
RATE_LIMIT_STRICT = 3  # requests per second
RATE_LIMIT_BURST = 10  # requests per 10 seconds
RATE_LIMIT_BAN = 30  # requests before permanent ban
MAX_CONCURRENT_UPLOADS_PER_IP = 3

# Endpoint-Specific Limits
MAX_QR_REQUESTS_PER_MINUTE = 30
MAX_IMAGE_UPLOADS_PER_HOUR = 50
MAX_BIOLINKS_PER_IP = 5
MAX_SNIPPETS_PER_IP = 20
MAX_HTML_PAGES_PER_IP = 10
QR_CACHE_MAX_SIZE = 500
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

---

## 📝 License

MIT License - See [LICENSE](LICENSE)

---

## 🙏 Acknowledgments

- FastAPI team for the amazing framework
- PyCryptodome for encryption libraries
- Open-source community

---

## 📧 Contact

**Developer**: Nauval Unesa  
**Website**: [nauval.cloud](https://nauval.cloud)  
**GitHub**: [@Nauvalunesa](https://github.com/Nauvalunesa)

---

<div align="center">

**🔒 Your files. Your privacy. Always encrypted.**

⭐ Star this repo if you value privacy!

Made with 🔐 by [Nauval Unesa](https://github.com/Nauvalunesa)

</div>
