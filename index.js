const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

// CONFIG
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(cors());
app.use(express.json());

// DB SQLite
const db = new sqlite3.Database('./presence.db');

// Création des tables si elles n'existent pas
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS presences (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      tag_id TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// Helper pour créer un utilisateur (tu pourras appeler ça une fois au début)
function createUser(username, password) {
  const hash = bcrypt.hashSync(password, 10);
  db.run(
    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
    [username, hash],
    (err) => {
      if (err) {
        console.error('Erreur création user', username, err.message);
      } else {
        console.log('User créé :', username);
      }
    }
  );
}

// Exemple: décommenter pour créer des users puis re-commenter après exécution
// createUser('eleve1', 'mdp1');
// createUser('eleve2', 'mdp2');

// Middleware d’auth
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const [type, token] = auth.split(' ');
  if (type !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'No token' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || !decoded || !decoded.userId) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.userId = decoded.userId;
    next();
  });
}

// Route /login
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  db.get(
    'SELECT * FROM users WHERE username = ?',
    [username],
    (err, user) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const ok = bcrypt.compareSync(password, user.password_hash);
      if (!ok) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '90d' });
      res.json({ token });
    }
  );
});

// Route /checkin
app.post('/checkin', authMiddleware, (req, res) => {
  const { tagId } = req.body || {};
  if (!tagId) {
    return res.status(400).json({ error: 'Missing tagId' });
  }

  const userId = req.userId;
  db.run(
    'INSERT INTO presences (user_id, tag_id) VALUES (?, ?)',
    [userId, tagId],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ status: 'ok' });
    }
  );
});

// petite route test
app.get('/', (req, res) => {
  res.send('Backend présence OK');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});