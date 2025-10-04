const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const db = new sqlite3.Database('./chat.db');

// Initialize database with error handling
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
  )`, (err) => {
    if (err) console.error('Error creating users table:', err);
  });
  
  // Add columns if they don't exist
  db.run(`ALTER TABLE contacts ADD COLUMN status TEXT DEFAULT 'accepted'`, () => {});
  db.run(`ALTER TABLE contacts ADD COLUMN requested_at DATETIME DEFAULT CURRENT_TIMESTAMP`, () => {});
  db.run(`ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0`, () => {});
  
  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    contact_id INTEGER,
    status TEXT DEFAULT 'accepted',
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(contact_id) REFERENCES users(id)
  )`, (err) => {
    if (err) console.error('Error creating contacts table:', err);
  });
  
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER DEFAULT 0,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(receiver_id) REFERENCES users(id)
  )`, (err) => {
    if (err) console.error('Error creating messages table:', err);
  });
});

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
    [username, email, hashedPassword], function(err) {
    if (err) return res.status(400).json({ error: 'User already exists' });
    res.json({ message: 'User created successfully' });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  });
});

app.get('/api/users', authenticateToken, (req, res) => {
  db.all('SELECT id, username, email FROM users WHERE id != ?', [req.user.id], (err, users) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(users);
  });
});

app.post('/api/contacts', authenticateToken, (req, res) => {
  const { contactId } = req.body;
  
  db.run('INSERT INTO contacts (user_id, contact_id, status) VALUES (?, ?, "pending")', 
    [req.user.id, contactId], function(err) {
    if (err) return res.status(400).json({ error: 'Request already sent' });
    res.json({ message: 'Contact request sent' });
  });
});

app.get('/api/contact-requests', authenticateToken, (req, res) => {
  db.all(`SELECT u.id, u.username, u.email, c.id as request_id FROM users u 
          JOIN contacts c ON u.id = c.user_id 
          WHERE c.contact_id = ? AND c.status = "pending"`, [req.user.id], (err, requests) => {
    if (err) {
      console.error('Error fetching contact requests:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    res.json(requests || []);
  });
});

app.post('/api/accept-request/:requestId', authenticateToken, (req, res) => {
  const { requestId } = req.params;
  
  db.run('UPDATE contacts SET status = "accepted" WHERE id = ?', [requestId], function(err) {
    if (err) return res.status(500).json({ error: 'Server error' });
    
    // Add reverse contact
    db.get('SELECT user_id, contact_id FROM contacts WHERE id = ?', [requestId], (err, contact) => {
      if (!err && contact) {
        db.run('INSERT INTO contacts (user_id, contact_id, status) VALUES (?, ?, "accepted")', 
          [contact.contact_id, contact.user_id]);
      }
    });
    
    res.json({ message: 'Request accepted' });
  });
});

app.get('/api/contacts', authenticateToken, (req, res) => {
  db.all(`SELECT u.id, u.username, u.email,
          (SELECT COUNT(*) FROM messages WHERE sender_id = u.id AND receiver_id = ? AND is_read = 0) as unread_count
          FROM users u 
          JOIN contacts c ON u.id = c.contact_id 
          WHERE c.user_id = ? AND c.status = "accepted"`, [req.user.id, req.user.id], (err, contacts) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(contacts);
  });
});

app.get('/api/messages/:contactId', authenticateToken, (req, res) => {
  const { contactId } = req.params;
  
  // Mark messages as read
  db.run('UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?', 
    [contactId, req.user.id]);
  
  db.all(`SELECT * FROM messages 
          WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
          ORDER BY timestamp ASC`, 
    [req.user.id, contactId, contactId, req.user.id], (err, messages) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(messages);
  });
});

// Socket.io
const connectedUsers = new Map();

io.on('connection', (socket) => {
  socket.on('join', (userId) => {
    connectedUsers.set(userId, socket.id);
    socket.userId = userId;
  });
  
  socket.on('sendMessage', (data) => {
    const { receiverId, message } = data;
    
    db.run('INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
      [socket.userId, receiverId, message], function(err) {
      if (!err) {
        const messageData = {
          id: this.lastID,
          sender_id: socket.userId,
          receiver_id: receiverId,
          message,
          timestamp: new Date().toISOString()
        };
        
        const receiverSocketId = connectedUsers.get(receiverId);
        if (receiverSocketId) {
          io.to(receiverSocketId).emit('newMessage', messageData);
        }
        socket.emit('messageConfirm', messageData);
      }
    });
  });
  
  socket.on('disconnect', () => {
    if (socket.userId) {
      connectedUsers.delete(socket.userId);
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});