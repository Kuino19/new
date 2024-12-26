const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
}));

// Serve static files from the public directory
app.use(express.static('public'));

// Set up SQLite database
const db = new sqlite3.Database(':memory:'); // Use ':memory:' for in-memory database or specify a file path for persistent storage

// Create tables for users, events, and messages
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
    db.run("CREATE TABLE events (id INTEGER PRIMARY KEY, name TEXT, date TEXT, self_destruct_time INTEGER)");
    db.run("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, receiver TEXT, content TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, self_destruct_time INTEGER)");
});

// Middleware to check if user is logged in
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next(); // User is authenticated, proceed to the next middleware
    }
    res.redirect('/login.html'); // Redirect to login page if not authenticated
}

// Routes
app.get('/', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Registration route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await argon2.hash(password); // Hash the password
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
            if (err) {
                return res.send('Error registering user.');
            }
            res.redirect('/login.html'); // Redirect to login page after registration
        });
    } catch (err) {
        res.send('Error hashing password.');
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (user) {
            try {
                if (await argon2.verify(user.password, password)) { // Verify hashed password
                    req.session.user = user.username; // Store username in session
                    res.redirect('/'); // Redirect to main page after login
                } else {
                    res.send('Invalid username or password.');
                }
            } catch (err) {
                res.send('Error verifying password.');
            }
        } else {
            res.send('Invalid username or password.');
        }
    });
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.send('Error logging out.');
        }
        res.redirect('/login.html'); // Redirect to login page after logout
    });
});

// Route to add an event
app.post('/add-event', (req, res) => {
    const { eventName, eventDate, selfDestructTime } = req.body; // Get self-destruct time from the form
    db.run("INSERT INTO events (name, date, self_destruct_time) VALUES (?, ?, ?)", [eventName, eventDate, selfDestructTime], function(err) {
        if (err) {
            return res.send('Error adding event.');
        }
        const eventId = this.lastID; // Get the ID of the newly inserted event

        // Schedule the deletion of the event after the specified self-destruct time
        if (selfDestructTime) {
            setTimeout(() => {
                db.run("DELETE FROM events WHERE id = ?", [eventId], (err) => {
                    if (err) {
                        console.error('Error deleting event:', err);
                    } else {
                        console.log(`Event ${eventId} deleted after ${selfDestructTime} seconds.`);
                    }
                });
            }, selfDestructTime * 1000); // Convert seconds to milliseconds
        }

        res.redirect('/'); // Redirect to main page after adding the event 
    });
});

// Route to send a message
app.post('/send-message', (req, res) => {
        const { receiver, content, selfDestructTime } = req.body;
        const sender = req.session.user; // Get the sender from the session

        db.run("INSERT INTO messages (sender, receiver, content, self_destruct_time) VALUES (?, ?, ?, ?)", [sender, receiver, content, selfDestructTime], function(err) {
            if (err) {
                return res.send('Error sending message.');
            }
            const messageId = this.lastID; // Get the ID of the newly inserted message

            // Schedule the deletion of the message after the specified self-destruct time
            if (selfDestructTime) {
                setTimeout(() => {
                    db.run("DELETE FROM messages WHERE id = ?", [messageId], (err) => {
                        if (err) {
                            console.error('Error deleting message:', err);
                        } else {
                            console.log(`Message ${messageId} deleted after ${selfDestructTime} seconds.`);
                        }
                    });
                }, selfDestructTime * 1000); // Convert seconds to milliseconds
            }

            res.redirect('/messages.html'); // Redirect to messages page after sending
        });
    });

    // Route to get messages for a user
    app.get('/messages', (req, res) => {
        const username = req.session.user; // Get the logged-in user
        db.all("SELECT * FROM messages WHERE receiver = ? OR sender = ?", [username, username], (err, rows) => {
            if (err) {
                return res.send('Error retrieving messages.');
            }
            res.json(rows); // Send the messages as JSON
        });
    });

    // Route to delete self-destructive messages
    app.delete('/messages/:id', (req, res) => {
        const messageId = req.params.id;
        db.run("DELETE FROM messages WHERE id = ?", [messageId], function(err) {
            if (err) {
                return res.send('Error deleting message.');
            }
            res.send('Message deleted successfully.');
        });
    });

    // Start the server
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });