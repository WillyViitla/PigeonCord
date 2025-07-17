const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const PORT = 1488;

// Initialize SQLite database
const db = new sqlite3.Database('./pigoncord.db');

// Create tables
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            bio TEXT DEFAULT '',
            avatar TEXT DEFAULT '',
            status TEXT DEFAULT 'online',
            role_id INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (role_id) REFERENCES roles (id)
        )
    `);

    // Roles table
    db.run(`
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            color TEXT DEFAULT '#ffffff',
            permissions TEXT DEFAULT '{}',
            position INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Channels table
    db.run(`
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            type TEXT DEFAULT 'text',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Messages table
    db.run(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            channel_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            mentions TEXT DEFAULT '[]',
            edited_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (channel_id) REFERENCES channels (id)
        )
    `);

    // Insert default roles
    db.run(`INSERT OR IGNORE INTO roles (id, name, color, permissions, position) VALUES 
        (1, 'Member', '#99aab5', '{"read": true, "write": true}', 0),
        (2, 'Moderator', '#3498db', '{"read": true, "write": true, "kick": true, "ban": true, "manage_messages": true}', 1),
        (3, 'Admin', '#e74c3c', '{"read": true, "write": true, "kick": true, "ban": true, "manage_messages": true, "manage_channels": true, "manage_roles": true}', 2),
        (4, 'Owner', '#ffd700', '{"read": true, "write": true, "kick": true, "ban": true, "manage_messages": true, "manage_channels": true, "manage_roles": true, "manage_server": true}', 3)
    `);

    // Insert default channels
    db.run(`INSERT OR IGNORE INTO channels (id, name, description) VALUES 
        (1, 'general', 'General chat for all the cool pigeons'),
        (2, 'memes', 'Post your dankest memes here bestie'),
        (3, 'announcements', 'Important shit from the pigeon overlords'),
        (4, 'random', 'Random bullshit go brrrr')
    `);
});

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'public/uploads/';
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'pigoncord-secret-key-coo-coo-motherfucker',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Store active users
const activeUsers = new Map();

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/chat', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// API Routes
app.post('/api/register', async (req, res) => {
    const { username, password, email, dateOfBirth } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    if (username.length < 3) {
        return res.status(400).json({ error: 'Username must be at least 3 characters long' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            [username, hashedPassword, email || null],
            function(err) {
                if (err) {
                    if (err.code === 'SQLITE_CONSTRAINT') {
                        return res.status(400).json({ error: 'Username already exists' });
                    }
                    return res.status(500).json({ error: 'Registration failed' });
                }
                
                req.session.user = { id: this.lastID, username };
                res.json({ success: true, message: 'Registration successful' });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // First, try to get user with role info
    db.get(
        'SELECT u.*, r.name as role_name, r.color as role_color FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.username = ?',
        [username],
        async (err, user) => {
            if (err) {
                console.error('Database error in login:', err);
                return res.status(500).json({ error: 'Login failed' });
            }
            
            if (!user) {
                return res.status(400).json({ error: 'Invalid username or password' });
            }
            
            try {
                const validPassword = await bcrypt.compare(password, user.password);
                
                if (!validPassword) {
                    return res.status(400).json({ error: 'Invalid username or password' });
                }
                
                // Update last seen
                db.run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id], (updateErr) => {
                    if (updateErr) {
                        console.error('Error updating last seen:', updateErr);
                    }
                });
                
                req.session.user = { 
                    id: user.id, 
                    username: user.username,
                    role_id: user.role_id || 1,
                    role_name: user.role_name || 'Member',
                    role_color: user.role_color || '#99aab5'
                };
                
                res.json({ success: true, message: 'Login successful' });
            } catch (error) {
                console.error('Password comparison error:', error);
                res.status(500).json({ error: 'Login failed' });
            }
        }
    );
});

app.post('/api/logout', (req, res) => {
    if (req.session.user) {
        const userId = req.session.user.id;
        db.run('UPDATE users SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?', ['offline', userId]);
        activeUsers.delete(userId);
        io.emit('user_status_changed', { userId, status: 'offline' });
    }
    
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true, message: 'Logout successful' });
    });
});

app.get('/api/user', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.get(
        'SELECT u.*, r.name as role_name, r.color as role_color, r.permissions FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?',
        [req.session.user.id],
        (err, user) => {
            if (err || !user) {
                return res.status(500).json({ error: 'User not found' });
            }
            
            const { password, ...userWithoutPassword } = user;
            res.json(userWithoutPassword);
        }
    );
});

app.get('/api/users', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.all(
        'SELECT u.id, u.username, u.avatar, u.status, u.last_seen, r.name as role_name, r.color as role_color FROM users u JOIN roles r ON u.role_id = r.id ORDER BY r.position DESC, u.username',
        [],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch users' });
            }
            
            res.json(users);
        }
    );
});

app.get('/api/channels', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.all('SELECT * FROM channels ORDER BY id', [], (err, channels) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch channels' });
        }
        
        res.json(channels);
    });
});

app.get('/api/messages/:channelId', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const channelId = req.params.channelId;
    const limit = req.query.limit || 50;
    const offset = req.query.offset || 0;
    
    db.all(
        `SELECT m.*, u.username, u.avatar, r.name as role_name, r.color as role_color 
         FROM messages m 
         JOIN users u ON m.user_id = u.id 
         JOIN roles r ON u.role_id = r.id 
         WHERE m.channel_id = ? 
         ORDER BY m.created_at DESC 
         LIMIT ? OFFSET ?`,
        [channelId, limit, offset],
        (err, messages) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch messages' });
            }
            
            res.json(messages.reverse());
        }
    );
});

app.post('/api/profile/update', upload.single('avatar'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { bio } = req.body;
    const userId = req.session.user.id;
    let avatar = null;
    
    if (req.file) {
        avatar = '/uploads/' + req.file.filename;
    }
    
    let query = 'UPDATE users SET bio = ?';
    let params = [bio || ''];
    
    if (avatar) {
        query += ', avatar = ?';
        params.push(avatar);
    }
    
    query += ' WHERE id = ?';
    params.push(userId);
    
    db.run(query, params, function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to update profile' });
        }
        
        res.json({ success: true, message: 'Profile updated successfully' });
    });
});

app.get('/api/user/:userId', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const userId = req.params.userId;
    
    db.get(
        'SELECT u.id, u.username, u.bio, u.avatar, u.status, u.created_at, u.last_seen, r.name as role_name, r.color as role_color FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?',
        [userId],
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json(user);
        }
    );
});

// Admin routes
app.post('/api/admin/role/update', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // Check if user has admin permissions
    db.get(
        'SELECT r.permissions FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?',
        [req.session.user.id],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Permission check failed' });
            }
            
            const permissions = JSON.parse(result.permissions);
            if (!permissions.manage_roles) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            
            const { userId, roleId } = req.body;
            
            db.run(
                'UPDATE users SET role_id = ? WHERE id = ?',
                [roleId, userId],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to update role' });
                    }
                    
                    res.json({ success: true, message: 'Role updated successfully' });
                }
            );
        }
    );
});

app.get('/api/roles', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    db.all('SELECT * FROM roles ORDER BY position DESC', [], (err, roles) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch roles' });
        }
        
        res.json(roles);
    });
});

// Socket.io connection handling
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    socket.on('join', (userData) => {
        socket.userId = userData.id;
        socket.username = userData.username;
        activeUsers.set(userData.id, {
            id: userData.id,
            username: userData.username,
            socketId: socket.id,
            status: 'online'
        });
        
        // Update user status to online
        db.run('UPDATE users SET status = ? WHERE id = ?', ['online', userData.id]);
        
        socket.broadcast.emit('user_status_changed', {
            userId: userData.id,
            status: 'online'
        });
        
        console.log(`${userData.username} joined the chat`);
    });
    
    socket.on('send_message', (data) => {
        const { channelId, content, mentions } = data;
        
        if (!socket.userId) {
            return;
        }
        
        db.run(
            'INSERT INTO messages (user_id, channel_id, content, mentions) VALUES (?, ?, ?, ?)',
            [socket.userId, channelId, content, JSON.stringify(mentions || [])],
            function(err) {
                if (err) {
                    console.error('Error saving message:', err);
                    return;
                }
                
                // Fetch message with user info
                db.get(
                    `SELECT m.*, u.username, u.avatar, r.name as role_name, r.color as role_color 
                     FROM messages m 
                     JOIN users u ON m.user_id = u.id 
                     JOIN roles r ON u.role_id = r.id 
                     WHERE m.id = ?`,
                    [this.lastID],
                    (err, message) => {
                        if (err) {
                            console.error('Error fetching message:', err);
                            return;
                        }
                        
                        io.emit('new_message', message);
                    }
                );
            }
        );
    });
    
    socket.on('typing', (data) => {
        socket.broadcast.emit('user_typing', {
            userId: socket.userId,
            username: socket.username,
            channelId: data.channelId
        });
    });
    
    socket.on('stop_typing', (data) => {
        socket.broadcast.emit('user_stop_typing', {
            userId: socket.userId,
            channelId: data.channelId
        });
    });
    
    socket.on('disconnect', () => {
        if (socket.userId) {
            activeUsers.delete(socket.userId);
            
            // Update user status to offline
            db.run('UPDATE users SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?', ['offline', socket.userId]);
            
            socket.broadcast.emit('user_status_changed', {
                userId: socket.userId,
                status: 'offline'
            });
            
            console.log(`${socket.username} left the chat`);
        }
    });
});

server.listen(PORT, () => {
    console.log(`PigeonCord server running on http://localhost:${PORT}`);
    console.log('Coo coo motherfuckers, the nest is ready! 🕊️');
});

// Graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Database connection closed.');
        process.exit(0);
    });
});
