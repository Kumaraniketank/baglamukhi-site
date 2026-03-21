/**
 * ═══════════════════════════════════════════════════════
 *  Maa Baglamukhi Peeth Parishad — Backend Server
 *  Pure Node.js, zero npm dependencies
 *  Database: JSON flat-file (db/blogs.json, db/contacts.json)
 *  Auth: SHA-256 password hash + signed session tokens
 * ═══════════════════════════════════════════════════════
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');
const crypto = require('crypto');

const PORT      = process.env.PORT || 3000;
const DB_DIR    = path.join(__dirname, 'db');
const BLOG_FILE = path.join(DB_DIR, 'blogs.json');
const CONT_FILE = path.join(DB_DIR, 'contacts.json');
const CFG_FILE  = path.join(DB_DIR, 'config.json');
const PUBLIC    = path.join(__dirname, 'public');

// ── Ensure DB directory & files ─────────────────────────
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
if (!fs.existsSync(PUBLIC)) fs.mkdirSync(PUBLIC, { recursive: true });

function initFile(file, def) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(def, null, 2));
}

// Default admin: username=admin, password=baglamukhi@123
// Password stored as SHA-256 hash
const DEFAULT_PASS_HASH = crypto.createHash('sha256')
  .update('baglamukhi@123').digest('hex');

initFile(BLOG_FILE, []);
initFile(CONT_FILE, []);
initFile(CFG_FILE, {
  adminUser: 'admin',
  adminHash: DEFAULT_PASS_HASH,
  siteName:  'Maa Baglamukhi Peeth Parishad',
  SECRET:    crypto.randomBytes(32).toString('hex')
});

// ── Helpers ─────────────────────────────────────────────
function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch(e) { return null; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
function uid() {
  return Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
}
function slug(title) {
  return title.toLowerCase()
    .replace(/[^\w\s-]/g, '').replace(/\s+/g, '-').substring(0, 80);
}

// ── Token auth (simple HMAC-signed token) ───────────────
function getSecret() { return readJSON(CFG_FILE).SECRET; }

function signToken(payload) {
  const data    = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig     = crypto.createHmac('sha256', getSecret()).update(data).digest('hex');
  return `${data}.${sig}`;
}
function verifyToken(token) {
  try {
    const [data, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', getSecret()).update(data).digest('hex');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (payload.exp < Date.now()) return null;  // expired
    return payload;
  } catch { return null; }
}
function authHeader(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  return verifyToken(token);
}
function getCookieToken(req) {
  const cookies = req.headers.cookie || '';
  const match   = cookies.match(/admin_token=([^;]+)/);
  return match ? verifyToken(decodeURIComponent(match[1])) : null;
}
function isAdmin(req) {
  return authHeader(req) || getCookieToken(req);
}

// ── Body parser ─────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 500000) req.destroy(); });
    req.on('end', () => {
      try {
        const ct = req.headers['content-type'] || '';
        if (ct.includes('application/json')) resolve(JSON.parse(body));
        else if (ct.includes('urlencoded')) {
          const obj = {};
          body.split('&').forEach(pair => {
            const [k, v] = pair.split('=').map(decodeURIComponent);
            obj[k] = v;
          });
          resolve(obj);
        } else resolve(body);
      } catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ── Response helpers ─────────────────────────────────────
function json(res, status, data) {
  res.writeHead(status, {
    'Content-Type':  'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
  });
  res.end(JSON.stringify(data));
}
function serveFile(res, filepath) {
  const ext = path.extname(filepath).toLowerCase();
  const mimeMap = {
    '.html': 'text/html; charset=utf-8',
    '.css':  'text/css',
    '.js':   'application/javascript',
    '.json': 'application/json',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.svg':  'image/svg+xml',
    '.ico':  'image/x-icon',
  };
  const mime = mimeMap[ext] || 'application/octet-stream';
  try {
    const data = fs.readFileSync(filepath);
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  } catch {
    res.writeHead(404); res.end('Not found');
  }
}

// ════════════════════════════════════════════════════════
//  ROUTER
// ════════════════════════════════════════════════════════
async function router(req, res) {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname.replace(/\/$/, '') || '/';
  const method   = req.method.toUpperCase();

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
    });
    return res.end();
  }

  // ── Static files ────────────────────────────────────
  if (method === 'GET' && !pathname.startsWith('/api/')) {
    // Serve index.html for /
    if (pathname === '/') return serveFile(res, path.join(PUBLIC, 'index.html'));
    if (pathname === '/blog')  return serveFile(res, path.join(PUBLIC, 'blog.html'));
    if (pathname === '/admin') return serveFile(res, path.join(PUBLIC, 'admin.html'));
    const staticPath = path.join(PUBLIC, pathname);
    if (fs.existsSync(staticPath) && fs.statSync(staticPath).isFile()) {
      return serveFile(res, staticPath);
    }
    return serveFile(res, path.join(PUBLIC, 'index.html')); // SPA fallback
  }

  // ════════════════════════════════════════════════════
  //  API ROUTES
  // ════════════════════════════════════════════════════

  // ── POST /api/auth/login ─────────────────────────────
  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await parseBody(req);
    const cfg  = readJSON(CFG_FILE);
    const hash = crypto.createHash('sha256').update(body.password || '').digest('hex');
    if (body.username === cfg.adminUser && hash === cfg.adminHash) {
      const token = signToken({ user: cfg.adminUser, exp: Date.now() + 86400000 * 7 });
      return json(res, 200, { success: true, token });
    }
    return json(res, 401, { success: false, message: 'Invalid credentials' });
  }

  // ── POST /api/auth/change-password ──────────────────
  if (pathname === '/api/auth/change-password' && method === 'POST') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const body = await parseBody(req);
    const cfg  = readJSON(CFG_FILE);
    const oldHash = crypto.createHash('sha256').update(body.oldPassword || '').digest('hex');
    if (oldHash !== cfg.adminHash) return json(res, 400, { message: 'Old password incorrect' });
    cfg.adminHash = crypto.createHash('sha256').update(body.newPassword || '').digest('hex');
    writeJSON(CFG_FILE, cfg);
    return json(res, 200, { success: true });
  }

  // ════ BLOG ROUTES ════════════════════════════════════

  // ── GET /api/blogs — public list (published only) ───
  if (pathname === '/api/blogs' && method === 'GET') {
    const blogs    = readJSON(BLOG_FILE) || [];
    const page     = parseInt(parsed.query.page) || 1;
    const limit    = parseInt(parsed.query.limit) || 10;
    const tag      = parsed.query.tag || '';
    const search   = (parsed.query.q || '').toLowerCase();
    let   filtered = blogs.filter(b => b.status === 'published');
    if (tag)    filtered = filtered.filter(b => (b.tags||[]).includes(tag));
    if (search) filtered = filtered.filter(b =>
      b.title.toLowerCase().includes(search) ||
      b.excerpt.toLowerCase().includes(search));
    filtered.sort((a, b) => b.createdAt - a.createdAt);
    const total    = filtered.length;
    const items    = filtered.slice((page-1)*limit, page*limit)
      .map(b => ({ ...b, content: undefined })); // strip full content from list
    return json(res, 200, { total, page, limit, items });
  }

  // ── GET /api/blogs/all — admin: all posts ────────────
  if (pathname === '/api/blogs/all' && method === 'GET') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const blogs = (readJSON(BLOG_FILE) || [])
      .sort((a, b) => b.createdAt - a.createdAt);
    return json(res, 200, { blogs });
  }

  // ── GET /api/blogs/tags — all tags ──────────────────
  if (pathname === '/api/blogs/tags' && method === 'GET') {
    const blogs = readJSON(BLOG_FILE) || [];
    const tags  = [...new Set(blogs.flatMap(b => b.tags || []))].sort();
    return json(res, 200, { tags });
  }

  // ── GET /api/blogs/:id — single post ────────────────
  const blogMatch = pathname.match(/^\/api\/blogs\/([^/]+)$/);
  if (blogMatch && method === 'GET') {
    const blogs = readJSON(BLOG_FILE) || [];
    const post  = blogs.find(b => b.id === blogMatch[1] || b.slug === blogMatch[1]);
    if (!post) return json(res, 404, { message: 'Post not found' });
    if (post.status !== 'published' && !isAdmin(req))
      return json(res, 403, { message: 'Forbidden' });
    // Increment view count
    post.views = (post.views || 0) + 1;
    writeJSON(BLOG_FILE, blogs);
    return json(res, 200, post);
  }

  // ── POST /api/blogs — create post (admin) ───────────
  if (pathname === '/api/blogs' && method === 'POST') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const body  = await parseBody(req);
    const blogs = readJSON(BLOG_FILE) || [];
    const now   = Date.now();
    const post  = {
      id:          uid(),
      slug:        body.slug || slug(body.title || 'untitled'),
      title:       body.title       || 'Untitled',
      excerpt:     body.excerpt     || '',
      content:     body.content     || '',
      category:    body.category    || 'General',
      tags:        Array.isArray(body.tags) ? body.tags : (body.tags||'').split(',').map(t=>t.trim()).filter(Boolean),
      author:      body.author      || 'Admin',
      status:      body.status      || 'draft',
      featuredImg: body.featuredImg || '',
      views:       0,
      createdAt:   now,
      updatedAt:   now,
    };
    blogs.unshift(post);
    writeJSON(BLOG_FILE, blogs);
    return json(res, 201, post);
  }

  // ── PUT /api/blogs/:id — update post (admin) ─────────
  const blogPut = pathname.match(/^\/api\/blogs\/([^/]+)$/);
  if (blogPut && method === 'PUT') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const body  = await parseBody(req);
    const blogs = readJSON(BLOG_FILE) || [];
    const idx   = blogs.findIndex(b => b.id === blogPut[1]);
    if (idx === -1) return json(res, 404, { message: 'Not found' });
    const updated = {
      ...blogs[idx],
      ...body,
      id:        blogs[idx].id,
      createdAt: blogs[idx].createdAt,
      updatedAt: Date.now(),
      tags:      Array.isArray(body.tags) ? body.tags : (body.tags||'').split(',').map(t=>t.trim()).filter(Boolean),
    };
    blogs[idx] = updated;
    writeJSON(BLOG_FILE, blogs);
    return json(res, 200, updated);
  }

  // ── DELETE /api/blogs/:id — delete post (admin) ──────
  const blogDel = pathname.match(/^\/api\/blogs\/([^/]+)$/);
  if (blogDel && method === 'DELETE') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const blogs   = readJSON(BLOG_FILE) || [];
    const filtered = blogs.filter(b => b.id !== blogDel[1]);
    writeJSON(BLOG_FILE, filtered);
    return json(res, 200, { success: true });
  }

  // ════ CONTACT ROUTES ══════════════════════════════════

  // ── POST /api/contact — save contact submission ──────
  if (pathname === '/api/contact' && method === 'POST') {
    const body     = await parseBody(req);
    const contacts = readJSON(CONT_FILE) || [];
    const entry    = {
      id:        uid(),
      name:      body.name        || '',
      phone:     body.phone       || '',
      email:     body.email       || '',
      dob:       body.dob         || '',
      tob:       body.tob         || '',
      pob:       body.pob         || '',
      service:   body.service     || '',
      query:     body.query       || '',
      status:    'new',
      createdAt: Date.now(),
    };
    contacts.unshift(entry);
    writeJSON(CONT_FILE, contacts);
    return json(res, 201, { success: true, id: entry.id, message: 'Request received! We will contact you within 24 hours.' });
  }

  // ── GET /api/contacts — list contacts (admin) ────────
  if (pathname === '/api/contacts' && method === 'GET') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const contacts = (readJSON(CONT_FILE) || [])
      .sort((a, b) => b.createdAt - a.createdAt);
    return json(res, 200, { contacts, total: contacts.length });
  }

  // ── PUT /api/contacts/:id — mark status (admin) ──────
  const contPut = pathname.match(/^\/api\/contacts\/([^/]+)$/);
  if (contPut && method === 'PUT') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const body     = await parseBody(req);
    const contacts = readJSON(CONT_FILE) || [];
    const idx      = contacts.findIndex(c => c.id === contPut[1]);
    if (idx === -1) return json(res, 404, { message: 'Not found' });
    contacts[idx].status = body.status || contacts[idx].status;
    contacts[idx].notes  = body.notes  || contacts[idx].notes || '';
    writeJSON(CONT_FILE, contacts);
    return json(res, 200, contacts[idx]);
  }

  // ── DELETE /api/contacts/:id — delete contact (admin)
  const contDel = pathname.match(/^\/api\/contacts\/([^/]+)$/);
  if (contDel && method === 'DELETE') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const contacts = readJSON(CONT_FILE) || [];
    writeJSON(CONT_FILE, contacts.filter(c => c.id !== contDel[1]));
    return json(res, 200, { success: true });
  }

  // ── GET /api/stats — dashboard stats (admin) ─────────
  if (pathname === '/api/stats' && method === 'GET') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const blogs    = readJSON(BLOG_FILE) || [];
    const contacts = readJSON(CONT_FILE) || [];
    return json(res, 200, {
      totalBlogs:      blogs.length,
      publishedBlogs:  blogs.filter(b => b.status === 'published').length,
      draftBlogs:      blogs.filter(b => b.status === 'draft').length,
      totalViews:      blogs.reduce((s, b) => s + (b.views||0), 0),
      totalContacts:   contacts.length,
      newContacts:     contacts.filter(c => c.status === 'new').length,
      repliedContacts: contacts.filter(c => c.status === 'replied').length,
    });
  }

  // 404
  return json(res, 404, { message: 'API route not found' });
}

// ── Start server ─────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    await router(req, res);
  } catch (err) {
    console.error('Server error:', err);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Internal server error' }));
  }
});

server.listen(PORT, () => {
  console.log(`
  ════════════════════════════════════════════
   🔱 Maa Baglamukhi Peeth Parishad Server
  ════════════════════════════════════════════
   🌐  http://localhost:${PORT}
   📝  Blog:  http://localhost:${PORT}/blog
   🔐  Admin: http://localhost:${PORT}/admin
  ────────────────────────────────────────────
   Default Admin Login:
   Username: admin
   Password: baglamukhi@123
   (Change this immediately after first login!)
  ════════════════════════════════════════════
  `);
});
