/**
 * ═══════════════════════════════════════════════════════════
 *  Maa Baglamukhi Peeth Parishad — Backend Server v3
 *  Database : MongoDB Atlas (cloud — data never deletes)
 *  Auth     : SHA-256 + HMAC signed tokens
 * ═══════════════════════════════════════════════════════════
 *
 *  SETUP:
 *  1. npm install mongodb
 *  2. Set env variable MONGODB_URI on Render:
 *     mongodb+srv://user:pass@cluster.mongodb.net/baglamukhi
 *  3. Set ADMIN_SECRET on Render (any random long string)
 *     e.g.  openssl rand -hex 32
 * ═══════════════════════════════════════════════════════════
 */

'use strict';
// Load .env file for local development
require('fs').existsSync('.env') && require('fs').readFileSync('.env','utf8')
  .split('\n').forEach(line => {
    const [k,...v] = line.split('=');
    if(k && v.length) process.env[k.trim()] = v.join('=').trim();
  });

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ── MongoDB ───────────────────────────────────────────────
let MongoClient;
try { MongoClient = require('mongodb').MongoClient; }
catch(e) {
  console.error('❌  mongodb package not found. Run:  npm install mongodb');
  process.exit(1);
}

const MONGO_URI = process.env.MONGODB_URI || '';
const PORT      = process.env.PORT        || 3000;
const PUBLIC    = path.join(__dirname, 'public');
const UPL_DIR   = path.join(PUBLIC, 'uploads');

// Admin credentials from env (fallback to defaults)
const ADMIN_USER    = process.env.ADMIN_USER     || 'admin';
const ADMIN_PASS    = process.env.ADMIN_PASS     || 'baglamukhi@123';
const ADMIN_SECRET  = process.env.ADMIN_SECRET   || crypto.randomBytes(32).toString('hex');

[PUBLIC, UPL_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ── SHA-256 helper ────────────────────────────────────────
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function uid()     { return Date.now().toString(36) + crypto.randomBytes(4).toString('hex'); }
function slugify(t){
  return (t||'untitled').toLowerCase()
    .replace(/[^\w\s-]/g,'').replace(/\s+/g,'-').slice(0,80);
}

// ── MongoDB connection ────────────────────────────────────
let db;
let blogs_col, contacts_col, newsletter_col, config_col;

async function connectDB() {
  if (!MONGO_URI) {
    console.error('❌  MONGODB_URI environment variable is not set!');
    console.error('    Set it on Render → Environment → MONGODB_URI');
    process.exit(1);
  }
  try {
    // const client = new MongoClient(MONGO_URI, {
    //   serverSelectionTimeoutMS: 15000,
    //   connectTimeoutMS:         15000,
    //   socketTimeoutMS:          30000,
    //   tls:                      true,
    //   tlsAllowInvalidCertificates: false,
    //   tlsAllowInvalidHostnames:    false,
    // });
  const client = new MongoClient(MONGO_URI, {
  serverSelectionTimeoutMS: 15000,
  connectTimeoutMS:         15000,
  socketTimeoutMS:          30000,
  tls:                      true,
  tlsAllowInvalidCertificates: false,
  tlsAllowInvalidHostnames:    false,
  family: 4,   // Force IPv4
});
    await client.connect();
    db             = client.db('baglamukhi');
    blogs_col      = db.collection('blogs');
    contacts_col   = db.collection('contacts');
    newsletter_col = db.collection('newsletter');
    config_col     = db.collection('config');

    // Indexes for faster queries
    await blogs_col.createIndex({ status: 1, createdAt: -1 });
    await blogs_col.createIndex({ slug: 1 }, { unique: true, sparse: true });
    await contacts_col.createIndex({ createdAt: -1 });
    await newsletter_col.createIndex({ email: 1 }, { unique: true });

    // Seed admin config if first run
    const cfg = await config_col.findOne({ key: 'admin' });
    if (!cfg) {
      await config_col.insertOne({
        key:       'admin',
        adminUser: ADMIN_USER,
        adminHash: sha256(ADMIN_PASS),
      });
      console.log('  ✓ Admin config seeded');
    }

    console.log('  ✅  MongoDB Atlas connected → baglamukhi database');
  } catch(err) {
    console.error('❌  MongoDB connection failed:', err.message);
    process.exit(1);
  }
}

// ── Get admin config ──────────────────────────────────────
async function getAdminCfg() {
  const cfg = await config_col.findOne({ key: 'admin' });
  return cfg || { adminUser: ADMIN_USER, adminHash: sha256(ADMIN_PASS) };
}

// ── Token auth ────────────────────────────────────────────
function signToken(payload) {
  const d = Buffer.from(JSON.stringify(payload)).toString('base64');
  const s = crypto.createHmac('sha256', ADMIN_SECRET).update(d).digest('hex');
  return `${d}.${s}`;
}
function verifyToken(token) {
  try {
    const [d, s] = (token || '').split('.');
    if (!d || !s) return null;
    const expected = crypto.createHmac('sha256', ADMIN_SECRET).update(d).digest('hex');
    if (s !== expected) return null;
    const payload = JSON.parse(Buffer.from(d, 'base64').toString());
    return payload.exp > Date.now() ? payload : null;
  } catch { return null; }
}
function isAdmin(req) {
  const h = (req.headers['authorization'] || '').replace('Bearer ', '');
  if (verifyToken(h)) return true;
  const m = (req.headers.cookie || '').match(/admin_token=([^;]+)/);
  return m ? !!verifyToken(decodeURIComponent(m[1])) : false;
}

// ── Body parser ───────────────────────────────────────────
function parseBody(req, maxBytes = 10 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let total = 0;
    req.on('data', c => {
      total += c.length;
      if (total > maxBytes) { req.destroy(); reject(new Error('Too large')); }
      else chunks.push(c);
    });
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      const ct  = req.headers['content-type'] || '';
      try {
        if (ct.includes('application/json'))      resolve(JSON.parse(buf.toString()));
        else if (ct.includes('urlencoded')) {
          const obj = {};
          buf.toString().split('&').forEach(p => {
            const [k,v] = p.split('=');
            if (k) obj[decodeURIComponent(k)] = decodeURIComponent(v || '');
          });
          resolve(obj);
        } else resolve(buf);
      } catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ── Response helpers ──────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
};
function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
  res.end(JSON.stringify(data));
}
function serveFile(res, filepath) {
  const MIME = {
    '.html':'text/html; charset=utf-8', '.css':'text/css',
    '.js':'application/javascript',     '.json':'application/json',
    '.xml':'application/xml', 
    '.txt':'text/plain',     
    '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
    '.svg':'image/svg+xml', '.ico':'image/x-icon',
    '.webp':'image/webp', '.gif':'image/gif',
  };
  try {
    const data = fs.readFileSync(filepath);
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filepath).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  } catch { res.writeHead(404); res.end('Not found'); }
}

// ── Clean mongo doc (remove _id for client) ───────────────
function clean(doc) {
  if (!doc) return null;
  const d = { ...doc };
  delete d._id;
  return d;
}
function cleanAll(docs) { return (docs || []).map(clean); }

// ════════════════════════════════════════════════════════
//  ROUTER
// ════════════════════════════════════════════════════════
async function router(req, res) {
  // Robust URL parsing — works on all Node.js versions and hosts
  const rawUrl  = req.url || '/';
  const qMark   = rawUrl.indexOf('?');
  let   pathname = qMark === -1 ? rawUrl : rawUrl.slice(0, qMark);
  try { pathname = decodeURIComponent(pathname); } catch(e) {}
  pathname = pathname.replace(/\/+/g, '/');
  if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);
  if (!pathname) pathname = '/';

  // Query string parsing
  const queryStr = qMark === -1 ? '' : rawUrl.slice(qMark + 1);
  const query = { get: (k) => {
    const pair = queryStr.split('&').find(p => p.split('=')[0] === k);
    return pair ? decodeURIComponent(pair.split('=').slice(1).join('=')) : null;
  }};

  const method = req.method.toUpperCase();

  // CORS preflight
  if (method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }

  // ── API routes — check FIRST before static files ──────
  // ── Static + special routes ──
if (!pathname.startsWith('/api') && method === 'GET') {

  // robots.txt
  if (pathname.startsWith('/robots.txt')) {
    const file = path.join(PUBLIC, 'robots.txt');
    if (fs.existsSync(file)) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(fs.readFileSync(file));
    }
  }

  // sitemap.xml
  if (pathname.startsWith('/sitemap.xml')) {
    const file = path.join(PUBLIC, 'sitemap.xml');
    if (fs.existsSync(file)) {
      res.writeHead(200, { 'Content-Type': 'application/xml' });
      return res.end(fs.readFileSync(file));
    }
  }

  if (pathname === '/')       return serveFile(res, path.join(PUBLIC,'index.html'));
  if (pathname === '/blog')   return serveFile(res, path.join(PUBLIC,'blog.html'));
  if (pathname === '/admin')  return serveFile(res, path.join(PUBLIC,'admin.html'));
  if (pathname.startsWith('/blog/')) return serveFile(res, path.join(PUBLIC,'post.html'));

  const sp = path.join(PUBLIC, pathname);
  if (fs.existsSync(sp) && fs.statSync(sp).isFile()) {
    return serveFile(res, sp);
  }

  return serveFile(res, path.join(PUBLIC,'index.html'));
}

  // ════════════════════════════════════════════════════
  //  API ROUTES
  // ════════════════════════════════════════════════════

  // ── Login ─────────────────────────────────────────────
  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await parseBody(req);
    const cfg  = await getAdminCfg();
    if (body.username === cfg.adminUser && sha256(body.password||'') === cfg.adminHash) {
      const token = signToken({ user: cfg.adminUser, exp: Date.now() + 86400000*7 });
      return json(res, 200, { success: true, token });
    }
    return json(res, 401, { success: false, message: 'Invalid credentials' });
  }

  // ── Change password ───────────────────────────────────
  if (pathname === '/api/auth/change-password' && method === 'POST') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const body = await parseBody(req);
    const cfg  = await getAdminCfg();
    if (sha256(body.oldPassword||'') !== cfg.adminHash)
      return json(res, 400, { message: 'Old password incorrect' });
    if (!body.newPassword || body.newPassword.length < 8)
      return json(res, 400, { message: 'Minimum 8 characters' });
    await config_col.updateOne({ key:'admin' }, { $set:{ adminHash: sha256(body.newPassword) } });
    return json(res, 200, { success: true });
  }

  // ── Stats ─────────────────────────────────────────────
  if (pathname === '/api/stats' && method === 'GET') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const [totalBlogs, publishedBlogs, draftBlogs, totalContacts, newContacts, subscribers] =
      await Promise.all([
        blogs_col.countDocuments(),
        blogs_col.countDocuments({ status:'published' }),
        blogs_col.countDocuments({ status:'draft' }),
        contacts_col.countDocuments(),
        contacts_col.countDocuments({ status:'new' }),
        newsletter_col.countDocuments(),
      ]);
    const viewsAgg = await blogs_col.aggregate([{ $group:{ _id:null, total:{ $sum:'$views' } } }]).toArray();
    const totalViews = viewsAgg[0]?.total || 0;
    return json(res, 200, { totalBlogs, publishedBlogs, draftBlogs, totalViews, totalContacts, newContacts, subscribers });
  }

  // ── Image upload ──────────────────────────────────────
  if (pathname === '/api/upload' && method === 'POST') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const body = await parseBody(req, 10*1024*1024);
    if (body && body.base64) {
      const m = body.base64.match(/^data:([^;]+);base64,(.+)$/);
      if (!m) return json(res, 400, { message: 'Invalid base64' });
      const extMap = {'image/jpeg':'.jpg','image/png':'.png','image/gif':'.gif','image/webp':'.webp'};
      const name = uid() + (extMap[m[1]] || '.jpg');
      fs.writeFileSync(path.join(UPL_DIR, name), Buffer.from(m[2], 'base64'));
      return json(res, 200, { url: '/uploads/' + name });
    }
    return json(res, 400, { message: 'No image data' });
  }

  // ════ BLOG ROUTES ═════════════════════════════════════

  // GET /api/blogs — public list
  if (pathname === '/api/blogs' && method === 'GET') {
    const page   = Math.max(1, parseInt(query.get('page'))  || 1);
    const limit  = Math.min(50, parseInt(query.get('limit')) || 10);
    const tag    = query.get('tag')      || '';
    const q      = (query.get('q')       || '').trim();
    const filter = { status: 'published' };
    if (tag) filter.tags = tag;
    if (q)   filter.$or  = [
      { title:   { $regex: q, $options:'i' } },
      { excerpt: { $regex: q, $options:'i' } },
    ];
    const total = await blogs_col.countDocuments(filter);
    const docs  = await blogs_col
      .find(filter, { projection:{ content:0 } })
      .sort({ createdAt:-1 })
      .skip((page-1)*limit).limit(limit)
      .toArray();
    return json(res, 200, { total, page, limit, items: cleanAll(docs) });
  }

  // GET /api/blogs/all — admin
  if (pathname === '/api/blogs/all' && method === 'GET') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const docs = await blogs_col.find({}).sort({ createdAt:-1 }).toArray();
    return json(res, 200, { blogs: cleanAll(docs) });
  }

  // GET /api/blogs/tags
  if (pathname === '/api/blogs/tags' && method === 'GET') {
    const tags = await blogs_col.distinct('tags', { status:'published' });
    return json(res, 200, { tags: tags.sort() });
  }

  // POST /api/blogs — create
  if (pathname === '/api/blogs' && method === 'POST') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const body = await parseBody(req);
    const now  = Date.now();
    const tags = Array.isArray(body.tags) ? body.tags
      : (body.tags||'').split(',').map(t=>t.trim()).filter(Boolean);
    let sl = body.slug || slugify(body.title);
    // Ensure unique slug
    const existing = await blogs_col.findOne({ slug: sl });
    if (existing) sl = sl + '-' + Date.now().toString(36);
    const post = {
      id: uid(), slug:sl,
      title:      body.title      || 'Untitled',
      excerpt:    body.excerpt    || '',
      content:    body.content    || '',
      category:   body.category   || 'General',
      tags,
      author:     body.author     || 'Admin',
      status:     body.status     || 'draft',
      featuredImg:body.featuredImg|| '',
      views: 0, createdAt: now, updatedAt: now,
    };
    await blogs_col.insertOne(post);
    return json(res, 201, clean(post));
  }

  // GET/PUT/DELETE /api/blogs/:id
  const bMatch = pathname.match(/^\/api\/blogs\/([^/]+)$/);
  if (bMatch) {
    const idOrSlug = bMatch[1];

    if (method === 'GET') {
      const post = await blogs_col.findOne({ $or:[{ id:idOrSlug },{ slug:idOrSlug }] });
      if (!post) return json(res, 404, { message: 'Post not found' });
      if (post.status !== 'published' && !isAdmin(req))
        return json(res, 403, { message: 'Forbidden' });
      await blogs_col.updateOne({ id:post.id }, { $inc:{ views:1 } });
      post.views = (post.views||0) + 1;
      // Related posts
      const related = await blogs_col
        .find({ status:'published', category:post.category, id:{ $ne:post.id } }, { projection:{content:0} })
        .limit(3).toArray();
      return json(res, 200, { ...clean(post), related: cleanAll(related) });
    }

    if (method === 'PUT') {
      if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
      const body = await parseBody(req);
      const tags = Array.isArray(body.tags) ? body.tags
        : (body.tags||'').split(',').map(t=>t.trim()).filter(Boolean);
      const update = { ...body, tags, updatedAt: Date.now() };
      delete update._id; delete update.id; delete update.createdAt;
      const result = await blogs_col.findOneAndUpdate(
        { id: idOrSlug },
        { $set: update },
        { returnDocument: 'after' }
      );
      if (!result) return json(res, 404, { message: 'Not found' });
      return json(res, 200, clean(result));
    }

    if (method === 'DELETE') {
      if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
      await blogs_col.deleteOne({ id: idOrSlug });
      return json(res, 200, { success: true });
    }
  }

  // ════ CONTACT ROUTES ══════════════════════════════════

  // POST /api/contact
  if (pathname === '/api/contact' && method === 'POST') {
    const body  = await parseBody(req);
    if (!(body.name||'').trim()) return json(res, 400, { message: 'Name is required' });
    const entry = {
      id:        uid(),
      name:      (body.name||'').trim(),
      phone:     body.phone   ||'',
      email:     body.email   ||'',
      dob:       body.dob     ||'',
      tob:       body.tob     ||'',
      pob:       body.pob     ||'',
      service:   body.service ||'',
      query:     body.query   ||'',
      status:    'new',
      notes:     '',
      createdAt: Date.now(),
    };
    await contacts_col.insertOne(entry);
    return json(res, 201, { success:true, id:entry.id,
      message:'Request received! We will contact you within 24 hours. Jai Maa Baglamukhi! 🔱' });
  }

  // GET /api/contacts — admin
  if (pathname === '/api/contacts' && method === 'GET') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const contacts = await contacts_col.find({}).sort({ createdAt:-1 }).toArray();
    return json(res, 200, { contacts: cleanAll(contacts), total: contacts.length });
  }

  // PUT/DELETE /api/contacts/:id
  const cMatch = pathname.match(/^\/api\/contacts\/([^/]+)$/);
  if (cMatch) {
    if (method === 'PUT') {
      if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
      const body = await parseBody(req);
      const upd  = {};
      if (body.status !== undefined) upd.status = body.status;
      if (body.notes  !== undefined) upd.notes  = body.notes;
      await contacts_col.updateOne({ id: cMatch[1] }, { $set: upd });
      const doc = await contacts_col.findOne({ id: cMatch[1] });
      return json(res, 200, clean(doc));
    }
    if (method === 'DELETE') {
      if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
      await contacts_col.deleteOne({ id: cMatch[1] });
      return json(res, 200, { success: true });
    }
  }

  // ════ NEWSLETTER ══════════════════════════════════════

  if (pathname === '/api/newsletter/subscribe' && method === 'POST') {
    const body  = await parseBody(req);
    const email = (body.email||'').trim().toLowerCase();
    if (!email || !email.includes('@'))
      return json(res, 400, { message: 'Valid email required' });
    try {
      await newsletter_col.insertOne({
        id: uid(), email, name: body.name||'', subscribedAt: Date.now()
      });
      return json(res, 201, { success:true, message:'Subscribed! Jai Maa Baglamukhi! 🔱' });
    } catch(e) {
      if (e.code === 11000) // duplicate key
        return json(res, 200, { success:true, message:'Already subscribed!' });
      throw e;
    }
  }

  if (pathname === '/api/newsletter' && method === 'GET') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const list = await newsletter_col.find({}).sort({ subscribedAt:-1 }).toArray();
    return json(res, 200, { subscribers: cleanAll(list), total: list.length });
  }

  // ── Export / Backup ───────────────────────────────────
  if (pathname === '/api/export' && method === 'GET') {
    if (!isAdmin(req)) return json(res, 401, { message: 'Unauthorized' });
    const type = query.get('type') || 'all';
    const data = { exportedAt: new Date().toISOString() };
    if (type==='blogs'   ||type==='all') data.blogs      = cleanAll(await blogs_col.find({}).toArray());
    if (type==='contacts'||type==='all') data.contacts   = cleanAll(await contacts_col.find({}).toArray());
    if (type==='newsletter'||type==='all') data.newsletter = cleanAll(await newsletter_col.find({}).toArray());
    const fn = `baglamukhi-backup-${type}-${Date.now()}.json`;
    res.writeHead(200, { 'Content-Type':'application/json',
      'Content-Disposition':`attachment; filename="${fn}"`, ...CORS });
    return res.end(JSON.stringify(data, null, 2));
  }

  return json(res, 404, { message: 'Route not found' });
}

// ── Start ─────────────────────────────────────────────────
connectDB().then(() => {
  http.createServer(async (req, res) => {
    try { await router(req, res); }
    catch(err) {
      console.error('[Error]', err.message);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type':'application/json' });
        res.end(JSON.stringify({ message:'Internal server error' }));
      }
    }
  }).listen(PORT, '0.0.0.0', () => {
    console.log(`
  ════════════════════════════════════════════
   🔱  Maa Baglamukhi Peeth Parishad  v3
  ════════════════════════════════════════════
   🌐  Site:  http://localhost:${PORT}
   📝  Blog:  http://localhost:${PORT}/blog
   🔐  Admin: http://localhost:${PORT}/admin
  ────────────────────────────────────────────
   Database : MongoDB Atlas ☁️  (persistent)
   Login    : admin / baglamukhi@123
  ════════════════════════════════════════════`);
  });
});
