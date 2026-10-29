require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost') 
    ? { rejectUnauthorized: false } 
    : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'rotrade_secret_key_change_in_production';

// Auto-initialize Database Tables
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        balance_php DECIMAL(12, 2) DEFAULT 1000.00,
        trust_score INT DEFAULT 100,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS items (
        id SERIAL PRIMARY KEY,
        seller_id INT REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(100) NOT NULL,
        game_category VARCHAR(50) NOT NULL,
        price_php DECIMAL(10, 2) NOT NULL,
        image_url TEXT,
        status VARCHAR(20) DEFAULT 'ACTIVE',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        buyer_id INT REFERENCES users(id),
        seller_id INT REFERENCES users(id),
        item_id INT REFERENCES items(id),
        amount_php DECIMAL(10, 2) NOT NULL,
        status VARCHAR(20) DEFAULT 'IN_ESCROW',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Database tables initialized successfully.');
  } catch (err) {
    console.error('Error initializing database tables:', err);
  }
}
initDb();

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied, token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ==========================================
// API ROUTES
// ==========================================

// Health Check
app.get('/', (req, res) => {
  res.json({ status: 'RoTrade Center API is online' });
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, balance_php',
      [username, email, hashedPassword]
    );
    res.status(201).json({ message: 'User registered successfully', user: result.rows[0] });
  } catch (err) {
    res.status(400).json({ error: 'Username or Email already exists.' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) return res.status(400).json({ error: 'User not found' });

    const user = userResult.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, username: user.username, balance_php: user.balance_php } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Marketplace Listings
app.get('/api/items', async (req, res) => {
  try {
    const { category } = req.query;
    let query = 'SELECT items.*, users.username AS seller_name FROM items JOIN users ON items.seller_id = users.id WHERE status = $1';
    let params = ['ACTIVE'];

    if (category) {
      query += ' AND game_category = $2';
      params.push(category);
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create Item Listing
app.post('/api/items', authenticateToken, async (req, res) => {
  const { title, game_category, price_php, image_url } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO items (seller_id, title, game_category, price_php, image_url) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.id, title, game_category, price_php, image_url]
    );
    res.status(201).json({ message: 'Item listed successfully', item: result.rows[0] });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Create Escrow Purchase Order
app.post('/api/orders/escrow', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const buyerId = req.user.id;
    const { itemId } = req.body;

    const itemRes = await client.query('SELECT * FROM items WHERE id = $1 AND status = $2 FOR UPDATE', [itemId, 'ACTIVE']);
    if (itemRes.rows.length === 0) throw new Error('Item unavailable or already sold');
    const item = itemRes.rows[0];

    if (item.seller_id === buyerId) throw new Error('You cannot buy your own item');

    const buyerRes = await client.query('SELECT balance_php FROM users WHERE id = $1 FOR UPDATE', [buyerId]);
    const buyerBalance = parseFloat(buyerRes.rows[0].balance_php);

    if (buyerBalance < parseFloat(item.price_php)) {
      throw new Error('Insufficient PHP balance');
    }

    // Deduct balance from buyer (held in Escrow)
    await client.query('UPDATE users SET balance_php = balance_php - $1 WHERE id = $2', [item.price_php, buyerId]);

    // Set item status to IN_ESCROW
    await client.query('UPDATE items SET status = $1 WHERE id = $2', ['IN_ESCROW', itemId]);

    // Record order
    const orderRes = await client.query(
      'INSERT INTO orders (buyer_id, seller_id, item_id, amount_php, status) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [buyerId, item.seller_id, itemId, item.price_php, 'IN_ESCROW']
    );

    await client.query('COMMIT');
    res.json({ message: 'Escrow order created successfully!', order: orderRes.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`RoTrade backend running on port ${PORT}`);
});
