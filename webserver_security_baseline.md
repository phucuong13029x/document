# Linux Web Server Security Baseline

## Ubuntu / Oracle Linux + Nginx Reverse Proxy

**Version:** 2.0
**Last Updated:** 2026-06-02

---

# 1. Overview

Tài liệu này mô tả bộ tiêu chuẩn bảo mật (Security Baseline) dành cho các máy chủ Web Public Internet.

Áp dụng cho:

* Ubuntu Server
* Oracle Linux
* Nginx Reverse Proxy
* Gunicorn
* NodeJS
* Docker
* MySQL
* PostgreSQL

Mục tiêu:

* Giảm thiểu bề mặt tấn công
* Chặn scanner và bot tự động
* Chặn brute force
* Chặn truy cập trái phép
* Chuẩn hóa cấu hình hệ thống
* Đáp ứng yêu cầu vận hành môi trường Production/UAT

---

# 2. Security Architecture

```text
Internet
    │
    ▼
Firewall
(UFW / Firewalld)
    │
    ▼
Nginx Reverse Proxy
    │
    ├── TLS Hardening
    ├── Security Headers
    ├── Host Validation
    ├── Rate Limit
    ├── Connection Limit
    ├── Scanner Blocking
    ├── ModSecurity WAF
    └── Fail2Ban
    │
    ▼
Application Layer
(Gunicorn / NodeJS / Docker)
    │
    ▼
Database Layer
(MySQL / PostgreSQL)
```

---

# 3. Operating System Hardening

## Update System

### Ubuntu

```bash
apt update
apt upgrade -y
```

### Oracle Linux

```bash
dnf update -y
```

---

## Install Security Packages

### Ubuntu

```bash
apt install -y \
fail2ban \
curl \
wget \
vim \
htop \
net-tools \
rsyslog \
unzip
```

### Oracle Linux

```bash
dnf install -y \
fail2ban \
curl \
wget \
vim \
htop \
net-tools \
rsyslog \
unzip
```

---

# 4. SSH Hardening

File:

```text
/etc/ssh/sshd_config
```

Cấu hình:

```ini
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes

MaxAuthTries 3
LoginGraceTime 30

AllowTcpForwarding no
X11Forwarding no
```

Restart:

```bash
systemctl restart sshd
```

Kiểm tra:

```bash
sshd -t
```

---

# 5. Linux Kernel Hardening

File:

```text
/etc/sysctl.d/99-security.conf
```

```ini
net.ipv4.tcp_syncookies = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

net.ipv4.icmp_echo_ignore_broadcasts = 1

kernel.randomize_va_space = 2
```

Apply:

```bash
sysctl --system
```

---

# 6. Firewall

## Ubuntu UFW

Default Policy

```bash
ufw default deny incoming
ufw default allow outgoing
```

Public Services

```bash
ufw allow 80/tcp
ufw allow 443/tcp
```

Internal Services

```bash
ufw allow from 10.10.0.0/16 to any port 22
ufw allow from 10.10.0.0/16 to any port 3000
ufw allow from 10.10.0.0/16 to any port 3100
ufw allow from 10.10.0.0/16 to any port 4333
ufw allow from 10.10.0.0/16 to any port 5000
ufw allow from 10.10.0.0/16 to any port 8080
ufw allow from 10.10.0.0/16 to any port 9090
```

Enable

```bash
ufw enable
```

Verify

```bash
ufw status verbose
```

---

## Oracle Linux Firewalld

Public

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
```

SSH Internal

```bash
firewall-cmd --permanent \
--add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" service name="ssh" accept'
```

Application Ports

```bash
for p in 3000 3100 4333 5000 8080 9090
do
firewall-cmd --permanent \
--add-rich-rule="rule family='ipv4' source address='10.10.0.0/16' port port='$p' protocol='tcp' accept"
done
```

Reload

```bash
firewall-cmd --reload
```

Verify

```bash
firewall-cmd --list-all
```

---

# 7. Nginx Global Configuration

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

## Block Bad User-Agent

```nginx
map $http_user_agent $bad_ua {
    default 0;

    ~*(sqlmap) 1;
    ~*(nikto) 1;
    ~*(wpscan) 1;
    ~*(masscan) 1;
    ~*(zgrab) 1;
    ~*(nmap) 1;
    ~*(acunetix) 1;
    ~*(netsparker) 1;
    ~*(nessus) 1;
    ~*(openvas) 1;

    ~*(python-requests) 1;
    ~*(go-http-client) 1;
    ~*(curl/) 1;
    ~*(wget/) 1;
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

# 8. Common Security Rules

File

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

if ($request_method !~ ^(GET|POST|PUT|DELETE|OPTIONS|HEAD)$) {
    return 405;
}
```

---

# 9. Common URL Blocking

File

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

location ~* ^/(vendor|storage|phpunit) {
    return 444;
}

location ~* ^/(jenkins|manager/html|actuator) {
    return 444;
}

location ~* ^/(HNAP1|nmap|sdk|evox|cgi-bin|boaform) {
    return 444;
}

location = /onvif/device_service {
    return 444;
}
```

---

# 10. Default Server Protection

```nginx
server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate /etc/nginx/ssl/default.crt;
    ssl_certificate_key /etc/nginx/ssl/default.key;

    return 444;
}
```

---

# 11. Site Template

```nginx
server {
    listen 80;
    server_name app.example.com;

    return 301 https://$host$request_uri;
}

server {

    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate /etc/nginx/ssl/star.crt;
    ssl_certificate_key /etc/nginx/ssl/star.key;

    ssl_protocols TLSv1.2 TLSv1.3;

    include /etc/nginx/security/common-security.conf;
    include /etc/nginx/security/common-block.conf;

    limit_req zone=bot burst=30 nodelay;
    limit_conn addr 20;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-XSS-Protection "1; mode=block" always;

    add_header Content-Security-Policy "frame-ancestors 'self';" always;

    add_header Strict-Transport-Security \
    "max-age=31536000; includeSubDomains" always;

    location / {

        proxy_pass http://127.0.0.1:7080;

        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

# 12. Docker Security

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

Kiểm tra:

```bash
docker ps
docker inspect CONTAINER_ID
```

---

# 13. Database Security

## MySQL

```ini
bind-address=127.0.0.1
mysqlx-bind-address=127.0.0.1
```

Restart

```bash
systemctl restart mysqld
```

---

## PostgreSQL

```ini
listen_addresses='127.0.0.1'
```

Restart

```bash
systemctl restart postgresql
```

---

# 14. Fail2Ban

File

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

Restart

```bash
systemctl restart fail2ban
```

Verify

```bash
fail2ban-client status
```

---

# 15. ModSecurity WAF

Ubuntu

```bash
apt install libnginx-mod-http-modsecurity
```

Oracle Linux

```bash
dnf install nginx-mod-modsecurity
```

Khuyến nghị triển khai:

OWASP CRS

Chặn:

* SQL Injection
* XSS
* LFI
* RFI
* Path Traversal
* Command Injection
* Web Shell Upload

---

# 16. Disable Unused Services

```bash
systemctl disable --now rpcbind
systemctl disable --now avahi-daemon
systemctl disable --now snmpd
```

Verify

```bash
ss -tulnp
```

---

# 17. Monitoring & Audit

SSH Failures

Ubuntu

```bash
grep "Failed password" /var/log/auth.log
```

Oracle Linux

```bash
grep "Failed password" /var/log/secure
```

Top Connections

```bash
netstat -ntu | awk '{print $5}' \
| cut -d: -f1 \
| sort | uniq -c | sort -nr | head
```

Fail2Ban

```bash
fail2ban-client status
```

---

# 18. Final Validation Checklist

## Firewall

```bash
ufw status verbose
```

or

```bash
firewall-cmd --list-all
```

## Nginx

```bash
nginx -t
systemctl reload nginx
```

## Open Ports

```bash
ss -tulnp
```

Expected Public Ports

```text
80
443
```

Expected Internal Ports

```text
22
3000
3100
4333
5000
8080
9090
```

Expected Database

```text
127.0.0.1:3306
127.0.0.1:5432
```

## External Scan

```bash
nmap -Pn SERVER_IP
```

Expected Result

```text
80/tcp open
443/tcp open

22/tcp filtered
3000/tcp filtered
3100/tcp filtered
4333/tcp filtered
5000/tcp filtered
8080/tcp filtered
9090/tcp filtered
```

---

# 19. Security Compliance Summary

Required:

* OS Updated
* Firewall Enabled
* SSH Key Authentication
* Nginx Rate Limit
* Security Headers
* Host Validation
* Fail2Ban Enabled
* ModSecurity Enabled
* OWASP CRS Enabled
* Database Localhost Only
* Docker Internal Binding Only

Recommended:

* Centralized Logging
* SIEM Integration
* Vulnerability Scanning
* Quarterly Security Review
* Penetration Testing

```
```
