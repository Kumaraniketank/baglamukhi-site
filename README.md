# 🔱 Maa Baglamukhi Peeth Parishad — Full Website

Complete website with blog CMS, admin panel, and contact form database.

---

## 📁 Project Structure

```
baglamukhi-site/
├── server.js          ← Backend API server (Node.js, zero dependencies)
├── package.json
├── db/                ← Auto-created database files (JSON)
│   ├── blogs.json     ← All blog posts
│   ├── contacts.json  ← All contact form submissions
│   └── config.json    ← Admin credentials + secret key
└── public/            ← All website files
    ├── index.html     ← Main website
    ├── blog.html      ← Public blog page
    └── admin.html     ← Admin panel
```

---

## 🚀 How to Run

### Requirements
- Node.js v14 or higher (check: `node --version`)
- **No npm install needed** — zero external dependencies!

### Start the Server

```bash
# Navigate to the project folder
cd baglamukhi-site

# Start the server
node server.js
```

You will see:
```
🌐  http://localhost:3000
📝  Blog:  http://localhost:3000/blog
🔐  Admin: http://localhost:3000/admin
```

Open your browser and go to **http://localhost:3000**

---

## 🔐 Admin Panel

URL: **http://localhost:3000/admin**

**Default Login:**
| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `baglamukhi@123` |

⚠️ **Change your password immediately** after first login via Settings tab.

### Admin Features:
- ✍ **Write Blog Posts** — HTML editor with formatting toolbar
- 📝 **Manage Posts** — Edit, publish/unpublish, delete
- 📩 **View Enquiries** — All contact form submissions with devotee details
- ✓ **Mark as Replied** — Track consultation status
- ⚙ **Change Password** — Secure your admin account

---

## 📝 Blog System

**Public Blog:** http://localhost:3000/blog

- Search articles by keyword
- Filter by tags and categories
- Click any post to read in full
- View counter on each post

---

## 📨 Contact Form

The contact form on the main website automatically saves to `db/contacts.json`.

Each submission stores:
- Name, Phone, Email
- Date/Time/Place of Birth
- Service requested
- Detailed query
- Timestamp

View all submissions in the Admin Panel → Contact Forms tab.

---

## 🌐 Hosting on a Real Server (VPS/Cloud)

To run this on a live server:

```bash
# Install PM2 for background running (needs internet)
npm install -g pm2

# Start with PM2
pm2 start server.js --name "baglamukhi-site"
pm2 save
pm2 startup

# The site will now auto-start on server reboot
```

For a custom domain, use **Nginx** as a reverse proxy:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 🔒 Security Notes

1. Change admin password immediately on first login
2. The `db/` folder contains your data — **back it up regularly**
3. Keep `db/config.json` private (contains password hash + secret key)
4. For production, use HTTPS (SSL certificate via Let's Encrypt)

---

## 📞 Support

Maa Baglamukhi Peeth Parishad · Datia, Madhya Pradesh
