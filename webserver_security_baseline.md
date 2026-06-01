# Linux Web Server Security Baseline

## Ubuntu & Oracle Linux + Nginx Reverse Proxy

Version: 1.0
Last Updated: 2026-06-01

---

# 1. Mục tiêu

Tài liệu này mô tả cấu hình chuẩn nhằm bảo vệ các máy chủ web public internet:

* Ubuntu Server
* Oracle Linux
* Nginx Reverse Proxy
* Gunicorn
* NodeJS
* Docker
* MySQL
* PostgreSQL

Mục tiêu:

* Giảm thiểu tấn công từ Internet
* Chặn scanner và bot
* Chặn brute force
* Chặn truy cập trái phép
* Giảm nguy cơ khai thác lỗ hổng
* Chuẩn hóa cấu hình nhiều website

---

# 2. Kiến trúc bảo mật

```text
Internet
    │
    ▼
Firewall (UFW / Firewalld)
    │
    ▼
Nginx Reverse Proxy
    │
    ├── Rate Limit
    ├── Security Headers
    ├── URL Block
    ├── User-Agent Filter
    ├── Host Validation
    └── WAF (ModSecurity)
    │
    ▼
Application
(Gunicorn / NodeJS / Docker)
    │
    ▼
Database
(MySQL / PostgreSQL)
```

---

# 3. Hệ điều hành

## Cập nhật hệ thống

Ubuntu

```bash
apt update
apt upgrade -y
```

Oracle Linux

```bash
dnf update -y
```

---

## Cài đặt công cụ bảo mật

Ubuntu

```bash
apt install -y \
fail2ban \
curl \
wget \
vim \
net-tools \
htop \
rsyslog
```

Oracle Linux

```bash
dnf install -y \
fail2ban \
curl \
wget \
vim \
net-tools \
htop \
rsyslog
```

---

# 4. Hardening SSH

## Chỉ cho phép SSH bằng Key

File:

```text
/etc/ssh/sshd_config
```

Thiết lập:

```ini
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
```

Khởi động lại:

```bash
systemctl restart sshd
```

---

# 5. Firewall

## Ubuntu UFW

Mặc định:

```bash
ufw default deny incoming
ufw default allow outgoing
```

Public:

```bash
ufw allow 80/tcp
ufw allow 443/tcp
```

Internal Only:

```bash
ufw allow from 10.10.0.0/16 to any port 22 hoặc ufw allow from 10.10.26.174 to any port 22
ufw allow from 10.10.0.0/16 to any port 3000
ufw allow from 10.10.0.0/16 to any port 3100
ufw allow from 10.10.0.0/16 to any port 4333
ufw allow from 10.10.0.0/16 to any port 5000
ufw allow from 10.10.0.0/16 to any port 8080
ufw allow from 10.10.0.0/16 to any port 9090
...
```

Enable:

```bash
ufw enable
```

Kiểm tra:

```bash
ufw status verbose
```

---

## Oracle Linux Firewalld

Public:

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
```

Internal:

```bash
firewall-cmd --permanent \
--add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" service name="ssh" accept'

firewall-cmd --permanent \
--add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" port port="3000" protocol="tcp" accept'

firewall-cmd --permanent \
--add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" port port="3100" protocol="tcp" accept'

firewall-cmd --permanent \
--add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" port port="4333" protocol="tcp" accept'

firewall-cmd --permanent \
--add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" port port="5000" protocol="tcp" accept'

firewall-cmd --permanent \
--add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" port port="8080" protocol="tcp" accept'

firewall-cmd --permanent \
--add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" port port="9090" protocol="tcp" accept'
```

Reload:

```bash
firewall-cmd --reload
```

---

# 6. Nginx Global Configuration

File:

```text
/etc/nginx/nginx.conf
```

## Rate Limit

```nginx
limit_req_zone $binary_remote_addr zone=bot:20m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:20m;
```

---

## Block Bad User Agent

```nginx
map $http_user_agent $bad_ua {
    default 0;

    ~*(masscan) 1;
    ~*(zgrab) 1;
    ~*(sqlmap) 1;
    ~*(nikto) 1;
    ~*(wpscan) 1;
    ~*(nmap) 1;
    ~*(acunetix) 1;
    ~*(netsparker) 1;
    ~*(nessus) 1;
    ~*(openvas) 1;

    ~*(python-requests) 1;
    ~*(go-http-client) 1;
}
```

---

## Block Sensitive Files

```nginx
map $request_uri $bad_ext {

    default 0;

    ~*\.env$ 1;
    ~*\.git$ 1;
    ~*\.svn$ 1;
    ~*\.bak$ 1;
    ~*\.old$ 1;
    ~*\.sql$ 1;
    ~*\.ini$ 1;
    ~*\.log$ 1;
}
```

---

# 7. Nginx Common Security Rules

File:

```text
/etc/nginx/security/common-security.conf
```

```nginx
if ($bad_ext) {
    return 444;
}

if ($bad_ua) {
    return 444;
}

if ($host ~ "^[0-9.]+$") {
    return 444;
}
```

---

# 8. Chặn URL Scan

File:

```text
/etc/nginx/security/common-block.conf
```

```nginx
location ~* ^/(wp-admin|wp-login|wp-json|xmlrpc\.php) {
    return 444;
}

location ~* ^/(phpmyadmin|pma|adminer) {
    return 444;
}

location ~* ^/(jenkins|manager/html|actuator) {
    return 444;
}

location ~* ^/(vendor|storage|phpunit|cgi-bin) {
    return 444;
}
```

---

# 9. Site Template

```nginx
server {

    listen 80;
    server_name app.example.com;

    return 301 https://$host$request_uri;
}

server {

    listen 443 ssl http2;

    server_name app.example.com;

    ssl_protocols TLSv1.2 TLSv1.3;

    include /etc/nginx/security/common-security.conf;
    include /etc/nginx/security/common-block.conf;

    limit_req zone=bot burst=30 nodelay;
    limit_conn addr 20;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {

        proxy_pass http://127.0.0.1:7080;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

# 10. Docker Security

Không nên:

```yaml
ports:
  - "3000:3000"
```

Nên:

```yaml
ports:
  - "127.0.0.1:3000:3000"
```

Hoặc:

```yaml
ports:
  - "10.10.15.60:3000:3000"
```

---

# 11. Database Security

## MySQL

```ini
bind-address=127.0.0.1
mysqlx-bind-address=127.0.0.1
```

Khởi động lại:

```bash
systemctl restart mysqld
```

---

## PostgreSQL

```ini
listen_addresses='127.0.0.1'
```

Khởi động lại:

```bash
systemctl restart postgresql
```

---

# 12. Fail2Ban

Tạo:

```text
/etc/fail2ban/jail.local
```

```ini
[DEFAULT]
bantime = 24h
findtime = 10m
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-badbots]
enabled = true
```

Restart:

```bash
systemctl restart fail2ban
```

Kiểm tra:

```bash
fail2ban-client status
```

---

# 13. ModSecurity WAF

Ubuntu

```bash
apt install libnginx-mod-http-modsecurity
```

Oracle Linux

```bash
dnf install nginx-mod-modsecurity
```

Triển khai OWASP CRS.

Chặn:

* SQL Injection
* XSS
* Path Traversal
* RCE
* Command Injection

---

# 14. Tắt Dịch Vụ Không Sử Dụng

```bash
systemctl disable --now rpcbind
systemctl disable --now avahi-daemon
systemctl disable --now snmpd
```

Kiểm tra:

```bash
ss -tulnp
```

---

# 15. Checklist Kiểm Tra Cuối

Kiểm tra firewall:

```bash
ufw status verbose
```

hoặc

```bash
firewall-cmd --list-all
```

Kiểm tra nginx:

```bash
nginx -t
```

Kiểm tra port:

```bash
ss -tulnp
```

Kiểm tra từ bên ngoài:

```bash
nmap SERVER_IP
```

Kết quả mong muốn:

Public:

* 80
* 443

Internal:

* 22
* 3000
* 3100
* 4333
* 5000
* 8080
* 9090

Database:

* localhost only

Docker:

* localhost/private IP only

SSH:

* Key Authentication Only

Fail2Ban:

* Enabled

WAF:

* Enabled
