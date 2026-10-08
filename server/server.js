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
  PORT
} = process.env;

if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const app = express();
app.use(cors());

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
