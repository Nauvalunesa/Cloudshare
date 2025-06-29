#  LinkShare Pro - CloudShare by Nauval

[![Deploy](https://img.shields.io/badge/deploy-pm2-blue?style=flat-square)](https://pm2.keymetrics.io/)
[![License](https://img.shields.io/github/license/Nauvalunesa/cloudshare?style=flat-square)](https://github.com/Nauvalunesa/cloudshare/blob/main/LICENSE)
[![FastAPI](https://img.shields.io/badge/built%20with-FastAPI-00b300?style=flat-square)](https://fastapi.tiangolo.com/)

**All-in-One File Sharing & URL Shortening API built with FastAPI**  
 Upload & Share files instantly  
 Shorten links with optional expiry  
Scan-ready QR codes for easy access  
 Real-time upload progress tracking  

>  Fast.  Secure. Instant.  
> Welcome to the most modern backend for sharing!

---

##  Features

- ✅ **Shorten URLs** with custom aliases & **optional** expiry
- 📂 **Upload Files** (max 100MB) with **optional** expiry timer
- 🕗 Real-time upload progress tracker
- 🖼️ Auto QR code generation (as base64 and PNG)
- 🔗 Redirect handler with expiry logic
- 📊 Stats endpoint for quick health check
- 🌐CORS-ready â€” easy frontend integration
- 🔒 Secure and expirable link handling

---

## — Example in Action

 Live: **[https://nauval.cloud](https://nauval.cloud)**  
Upload a file or shorten a URL â€” get a clean short link and an instant QR code 

---

##  Installation Guide

### 1. Clone the Repository

```bash
git clone https://github.com/Nauvalunesa/cloudshare.git
cd cloudshare
```

### ¦ 2. Install Dependencies

```bash
pip install -r requirements.txt
```

###  3. Run with PM2

```bash
pm2 start "python3 run.py" --name cloudshare
```

> File `run.py` akan menjalankan backend di `0.0.0.0:8800`

---

##  NGINX + SSL Setup (Production)

###  nginx.conf (`/etc/nginx/nginx.conf`)

```nginx
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    client_max_body_size 200M;
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

###  Virtual Host: `/etc/nginx/sites-available/cloudshare.conf`

```nginx
server {
    server_name nauval.cloud;

    location / {
        proxy_pass http://127.0.0.1:8800;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    error_page 404 /404.html;
    location = /404.html {
        root /var/www/html;
    }

    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /var/www/html;
    }

    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/nauval.cloud/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nauval.cloud/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    if ($host = nauval.cloud) {
        return 301 https://$host$request_uri;
    }

    listen 80;
    server_name nauval.cloud;
    return 404;
}
```

###  Enable SSL with Certbot

```bash
apt install certbot python3-certbot-nginx -y
certbot --nginx -d nauval.cloud
certbot renew --dry-run
```

---


##  License

MIT Â© [@Nauvalunesa](https://github.com/Nauvalunesa) 
