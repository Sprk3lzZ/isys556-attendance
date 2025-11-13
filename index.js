const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

// Students
const initialStudents = [
  { name: "Sarah Almaznai", username: "salmaznai", password: "e%jorKd%" },
  { name: "Abigail Baniaga", username: "abaniaga", password: "VkIVjzp$" },
  { name: "Jan Beeker", username: "jbeeker", password: "*fcrlW!A" },
  { name: "Anastasia Boulby", username: "aboulby", password: "%qDQEFNV" },
  { name: "Bronson Coles", username: "bcoles", password: "@PL@xHaD" },
  { name: "Sulema Fausto", username: "sfausto", password: "UYG0K3dl" },
  { name: "Gabriela Gonzalez Rendon", username: "ggonzalezrendon", password: "QwJzQsFb" },
  { name: "D Hale", username: "dhale", password: "R?&kM*Hk" },
  { name: "Leigh Jin", username: "ljin", password: "Ch9wYHge" },
  { name: "Uzma Kadri", username: "ukadri", password: "zTl4A@u&" },
  { name: "Thomas Kob", username: "tkob", password: "CP0vErwa" },
  { name: "Tevi Lawson Hellm", username: "tlawsonhellm", password: "hwRYOv6z" },
  { name: "Mikayla Manzur", username: "mmanzur", password: "cbaHsLVh" },
  { name: "Travis Montgomery", username: "tmontgomery", password: "OnuaMl?C" },
  { name: "Xavier Provens", username: "xprovens", password: "mMG@Jcdv" },
  { name: "Hamid Rajaei Rizi", username: "hrajaeirizi", password: "v2DXOPD5" },
  { name: "Noah Segura", username: "nsegura", password: "sf@eah?F" },
  { name: "Alyssa Smith", username: "asmith", password: "E?pBemPL" },
  { name: "Phoebe Tang", username: "ptang", password: "d9ZF?t%e" },
  { name: "Jason Tate", username: "jtate", password: "w0rfYjdN" },
  { name: "Christopher Tivar", username: "ctivar", password: "4Y1&b%VP" },
  { name: "Julie Wang", username: "jwang", password: "G8mVwPMe" },
  { name: "Dawson Wu", username: "dwu", password: "Qi&gIGLo" },
  { name: "Yanis Zeghiche", username: "yzeghiche", password: "wfZpazwE" }
];

// CONFIG
const JWT_SECRET = process.env.JWT_SECRET || 'isys-556-210304';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(cors());
app.use(express.json());

// DB SQLite
const DB_PATH = process.env.DB_PATH || './presence.db';
const db = new sqlite3.Database(DB_PATH);

function seedInitialStudents() {
  initialStudents.forEach((student) => {
    const hash = bcrypt.hashSync(student.password, 10);
    db.run(
      'INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)',
      [student.username, hash],
      (err) => {
        if (err) {
          console.error('Erreur création user', student.username, err.message);
        } else {
          console.log('User ok :', student.username);
        }
      }
    );
  });
}

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

  seedInitialStudents();
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

  // 1) Vérifier si déjà checkin aujourd'hui sur ce tag
  db.get(
    `
    SELECT id FROM presences
    WHERE user_id = ?
      AND tag_id = ?
      AND DATE(created_at) = DATE('now', 'localtime')
    `,
    [userId, tagId],
    (err, row) => {
      if (err) {
        console.error('Erreur SELECT presences:', err);
        return res.status(500).json({ error: 'DB error' });
      }

      if (row) {
        // Déjà présent aujourd'hui
        return res.status(409).json({ error: 'already_checked_in' });
      }

      // 2) Sinon, on insère la présence
      db.run(
        'INSERT INTO presences (user_id, tag_id) VALUES (?, ?)',
        [userId, tagId],
        (err2) => {
          if (err2) {
            console.error('Erreur INSERT presences:', err2);
            return res.status(500).json({ error: 'DB error' });
          }
          return res.json({ status: 'ok' });
        }
      );
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

app.post('/admin/create-user', (req, res) => {
    const { secret, username, password } = req.body || {};
    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing params' });
    }
  
    const hash = bcrypt.hashSync(password, 10);
    db.run(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, hash],
      (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'DB error' });
        }
        res.json({ status: 'user created' });
      }
    );
  });

  app.get('/presences', (req, res) => {
    db.all(`
      SELECT p.id, p.user_id, u.username, p.tag_id, p.created_at
      FROM presences p
      LEFT JOIN users u ON u.id = p.user_id
      ORDER BY p.created_at DESC
    `, (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json(rows);
    });
  });

  // toutes les présences sans JOIN
app.get('/presences_raw', (req, res) => {
  db.all('SELECT * FROM presences ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

app.get('/users', (req, res) => {
  db.all('SELECT id, username FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

app.post('/admin/seed-students', (req, res) => {
  const { secret } = req.body || {};
  if (secret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const created = [];

  initialStudents.forEach((student) => {
    const hash = bcrypt.hashSync(student.password, 10);
    db.run(
      'INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)',
      [student.username, hash],
      (err) => {
        if (err) {
          console.error('Erreur création user', student.username, err.message);
        }
      }
    );
    created.push({
      name: student.name,
      username: student.username,
      password: student.password
    });
  });

  res.json({
    status: 'ok',
    users: created
  });
});