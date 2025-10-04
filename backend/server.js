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

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    contact_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(contact_id) REFERENCES users(id)
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(receiver_id) REFERENCES users(id)
  )`);
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
  
  db.run('INSERT INTO contacts (user_id, contact_id) VALUES (?, ?)', 
    [req.user.id, contactId], function(err) {
    if (err) return res.status(400).json({ error: 'Contact already added' });
    res.json({ message: 'Contact added successfully' });
  });
});

app.get('/api/contacts', authenticateToken, (req, res) => {
  db.all(`SELECT u.id, u.username, u.email FROM users u 
          JOIN contacts c ON u.id = c.contact_id 
          WHERE c.user_id = ?`, [req.user.id], (err, contacts) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(contacts);
  });
});

app.get('/api/messages/:contactId', authenticateToken, (req, res) => {
  const { contactId } = req.params;
  
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