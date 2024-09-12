const express = require('express');
const bodyParser = require('body-parser');
const moment = require('moment-timezone');
const cors = require('cors');
const crypto = require('crypto');  // For generating hashes and encryption

const app = express();
const port = 8000;

// Middleware to parse URL-encoded form data
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware to parse JSON data
app.use(bodyParser.json());

// CORS middleware
app.use(cors());

// In-memory database (temporary)
const users = {
    "v": { password: "v", endTime: null, token: null },
    "asdf": { password: "asdf", endTime: null, token: null },
};

// In-memory sessions (temporary)
const sessions = {};

// Helper function to generate a unique hash based on the username
const generateHash = (username) => {
    return crypto.createHash('sha256').update(username).digest('hex');
};

// Helper function to encrypt the session end time using AES
const encryptTime = (time, key) => {
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.alloc(16, 0));  // Initialization Vector (IV) set to 0 for simplicity
    let encrypted = cipher.update(time, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
};

// Helper function to generate a unique token
const generateToken = () => {
    return crypto.randomBytes(32).toString('hex');  // Generate a 64-character token
};

// Helper function to generate end time (e.g., 1 minute from now)
const generateEndTime = () => {
    const now = new Date();
    const endTime = new Date(now.getTime() + 1 * 60000);  // Add 1 minute
    return endTime;
};


// Route for handling login requests
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.connection.remoteAddress;

    console.log(clientIp);
    // Validate input
    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    // Check user credentials
    const user = users[username];
    if (user && user.password === password) {
        // Generate unique hash for the client
        const userHash = generateHash(username);

        // Check if the user is already logged in
        if (sessions[username]) {
            return res.status(409).send('User already logged in.');
        }

        // Generate end time and encrypt it using the user's hash as the key
        const endTime = generateEndTime();
        const endTimeStr = moment(endTime).format('YYYY-MM-DDTHH:mm:ss');  // Standard time format
        const encryptedEndTime = encryptTime(endTimeStr, userHash);

        // Generate a token
        const token = generateToken();

        // Store session with generated end time and token
        sessions[username] = { endTime, userHash, token };

        // Save token in the user's record
        users[username].token = token;
        users[username].endTime = endTimeStr;  // Update endTime in the user's record

        console.log(username + " connected. Session will expire at " + endTimeStr);

        // Respond with the login success, unique hash, encrypted end time, and token
        return res.status(200).json({
            message: 'Login successful',
            encryptedEndTime,
            token
        });

    } else {
        console.log(username + " tried to connect with wrong credentials.");
        return res.status(401).send('Invalid username or password');
    }
});

app.post('/api/auth/endtime', (req, res) => {
    const { username, token } = req.body;

    // Validate input
    if (!username || !token) {
        return res.status(400).send('Username and token are required');
    }

        const userHash = generateHash(username);
    // Check if the user has an active session
    const session = sessions[username];
    if (session) {
        // Compare provided token with the token stored in the session
        if (session.token === token) {
            // Token is valid, return the end time and its hash
            const endTime = moment(session.endTime).format('YYYY-MM-DDTHH:mm:ss'); // Format end time for consistency
        const endTimeStr = moment(endTime).format('YYYY-MM-DDTHH:mm:ss');  // Standard time format
        const encryptedEndTime = encryptTime(endTimeStr, userHash);

            return res.status(200).json({
                // endTime: endTimeStr,
                hashedEndTime: encryptedEndTime
            });
        } else {
            // Token is invalid
            return res.status(403).send('Invalid token');
        }
    } else {
        // No active session for the user
        return res.status(404).send('No active session found for this user');
    }
});

// Route for handling client quit notification
app.post('/api/client/quit', (req, res) => {
    const { username, token } = req.body;

    // Validate input
    if (!username) {
        return res.status(400).send('Username is required');
    }

    // Handle client quit (remove the session or log the event)
    if (sessions[username]) {
        if (session.token === token) {
            delete sessions[username]; // Remove session when client quits
            console.log(`Client ${username} quit. Session removed.`);
            return res.status(200).send(`Client ${username} quit successfully.`);
        } else {
            // Token is invalid
            return res.status(403).send('Invalid token');
        }
    } else {
        return res.status(404).send(`No active session found for ${username}.`);
    }
});

// Middleware to check session validity
const checkSessionValidity = (req, res, next) => {
    const username = req.get('username');  // Extract username from request header
    if (sessions[username]) {
        const now = new Date();
        if (now > sessions[username].endTime) {
            delete sessions[username];
            return res.status(403).send('Session expired');
        }
    }
    next();
};

// Route to periodically clean up expired sessions
const cleanUpExpiredSessions = () => {
    const now = new Date();
    for (const [username, session] of Object.entries(sessions)) {
        if (now > session.endTime) {
            delete sessions[username];
        }
    }
};

// Set up a cleanup interval
setInterval(cleanUpExpiredSessions, 60000);  // Run every minute

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
