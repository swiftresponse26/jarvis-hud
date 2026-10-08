const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const Stripe = require('stripe');

const {
  DATABASE_URL,
  JWT_SECRET,
  ADMIN_INIT_PASSWORD,
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  OPENAI_API_KEY,
  PORT
} = process.env;

if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const app = express();
app.use(cors());

// Some setup flows ping the webhook URL with a plain GET just to check it
// resolves. Respond harmlessly instead of a 404 so that check never looks
// like a failure.
app.get('/api/stripe-webhook', (req, res) => res.status(200).send('ok - waiting for Stripe POST events'));

// Stripe webhook needs the raw body for signature verification, so it's
// registered BEFORE the json() body parser below.
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    console.error('Stripe webhook hit but STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET not configured');
    return res.status(500).send('webhook not configured');
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const userId = session.client_reference_id;
      const customerId = session.customer;
      if (userId) {
        await pool.query(
          'UPDATE users SET active = true, stripe_customer_id = $1 WHERE id = $2',
          [customerId, userId]
        );
      } else if (customerId && session.customer_email) {
        await pool.query(
          'UPDATE users SET active = true, stripe_customer_id = $1 WHERE email = $2',
          [customerId, session.customer_email.toLowerCase()]
        );
      }
    } else if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const isActive = sub.status === 'active' || sub.status === 'trialing';
      await pool.query(
        'UPDATE users SET active = $1 WHERE stripe_customer_id = $2',
        [isActive, sub.customer]
      );
    }
  } catch (err) {
    console.error('Error handling webhook event:', err);
  }

  res.json({ received: true });
});

app.use(express.json());

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT false,
      stripe_customer_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
  const existing = await pool.query("SELECT 1 FROM settings WHERE key = 'admin_password_hash'");
  if (existing.rowCount === 0) {
    const defaultPw = ADMIN_INIT_PASSWORD || 'Soccer3900$';
    const hash = await bcrypt.hash(defaultPw, 10);
    await pool.query("INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)", [hash]);
  }
}

function signUserToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
}
function signAdminToken() {
  return jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
}

function authUser(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'user') return res.status(401).json({ error: 'invalid token' });
    req.userId = payload.sub;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid or expired token' });
  }
}

function authAdmin(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') return res.status(401).json({ error: 'invalid token' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid or expired token' });
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/signup', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'invalid email' });
    if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rowCount > 0) return res.status(409).json({ error: 'an account with that email already exists' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, active',
      [email, hash]
    );
    const user = result.rows[0];
    res.json({ token: signUserToken(user), user: { email: user.email, active: user.active } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const result = await pool.query('SELECT id, email, password_hash, active FROM users WHERE email = $1', [email]);
    if (result.rowCount === 0) return res.status(401).json({ error: 'invalid email or password' });
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid email or password' });
    res.json({ token: signUserToken(user), user: { email: user.email, active: user.active } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/me', authUser, async (req, res) => {
  const result = await pool.query('SELECT email, active FROM users WHERE id = $1', [req.userId]);
  if (result.rowCount === 0) return res.status(404).json({ error: 'not found' });
  res.json({ user: result.rows[0], userId: req.userId });
});

// ---- Jarvis's real AI brain ----
const JARVIS_SYSTEM_PROMPT = [
  'You are JARVIS, a sharp, warm, dry-witted personal AI assistant speaking to "Boss".',
  'You run inside a futuristic HUD interface, so keep replies tight and conversational — this is read aloud by text-to-speech, so never use markdown, asterisks, bullet points, or headers.',
  'Keep most answers under about 120 words unless Boss clearly wants more detail.',
  'You do NOT have live access to any of Boss\'s real business data (no live Shopify numbers, no real orders, no real inventory) from this chat. If asked for live figures, say plainly that you are not connected to that data source right now rather than inventing numbers.',
  'You can discuss strategy, draft messages, brainstorm, explain things, do math, and have a normal conversation on any topic.'
].join(' ');

// simple in-memory per-user rate limit: 30 requests per 10 minutes
const askRateLimit = new Map();
function checkRateLimit(userId) {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const max = 30;
  const entry = askRateLimit.get(userId) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + windowMs; }
  entry.count += 1;
  askRateLimit.set(userId, entry);
  return entry.count <= max;
}

async function requireActiveUser(req, res, next) {
  const result = await pool.query('SELECT active FROM users WHERE id = $1', [req.userId]);
  if (result.rowCount === 0 || !result.rows[0].active) {
    return res.status(403).json({ error: 'account is not active' });
  }
  next();
}

app.post('/api/ask', authUser, requireActiveUser, async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(500).json({ error: 'AI brain is not configured yet' });
  if (!checkRateLimit(req.userId)) return res.status(429).json({ error: 'Too many requests, slow down a bit.' });

  const message = String(req.body.message || '').trim().slice(0, 4000);
  if (!message) return res.status(400).json({ error: 'message is required' });
  const history = Array.isArray(req.body.history) ? req.body.history.slice(-10) : [];

  const messages = [{ role: 'system', content: JARVIS_SYSTEM_PROMPT }];
  for (const turn of history) {
    if (turn && (turn.role === 'user' || turn.role === 'assistant') && typeof turn.content === 'string') {
      messages.push({ role: turn.role, content: turn.content.slice(0, 2000) });
    }
  }
  messages.push({ role: 'user', content: message });

  try {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + OPENAI_API_KEY
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages,
        temperature: 0.7,
        max_tokens: 500
      })
    });
    const data = await r.json();
    if (!r.ok) {
      console.error('OpenAI error:', data);
      return res.status(502).json({ error: (data.error && data.error.message) || 'AI request failed' });
    }
    const text = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
    res.json({ text: text.trim() });
  } catch (err) {
    console.error('Error calling OpenAI:', err);
    res.status(502).json({ error: 'Could not reach the AI service' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  const password = String(req.body.password || '');
  const result = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  if (result.rowCount === 0) return res.status(500).json({ error: 'admin not configured' });
  const ok = await bcrypt.compare(password, result.rows[0].value);
  if (!ok) return res.status(401).json({ error: 'wrong password' });
  res.json({ token: signAdminToken() });
});

app.get('/api/admin/users', authAdmin, async (req, res) => {
  const result = await pool.query('SELECT id, email, active, created_at FROM users ORDER BY created_at DESC LIMIT 500');
  res.json({ users: result.rows });
});

app.post('/api/admin/grant', authAdmin, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const result = await pool.query('UPDATE users SET active = true WHERE email = $1 RETURNING id, email, active', [email]);
  if (result.rowCount === 0) return res.status(404).json({ error: 'no user with that email' });
  res.json({ user: result.rows[0] });
});

app.post('/api/admin/revoke', authAdmin, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const result = await pool.query('UPDATE users SET active = false WHERE email = $1 RETURNING id, email, active', [email]);
  if (result.rowCount === 0) return res.status(404).json({ error: 'no user with that email' });
  res.json({ user: result.rows[0] });
});

app.post('/api/admin/change-password', authAdmin, async (req, res) => {
  const newPassword = String(req.body.newPassword || '');
  if (newPassword.length < 6) return res.status(400).json({ error: 'password must be at least 6 characters' });
  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query("UPDATE settings SET value = $1 WHERE key = 'admin_password_hash'", [hash]);
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

const port = PORT || 3000;
initDb()
  .then(() => {
    app.listen(port, () => console.log('Jarvis auth server listening on ' + port));
  })
  .catch((e) => {
    console.error('Failed to init DB', e);
    process.exit(1);
  });
