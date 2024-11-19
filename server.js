require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const validator = require('validator');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const session = require('express-session');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session middleware for secure token management
app.use(session({
    secret: crypto.randomBytes(64).toString('hex'), // Strong random secret
    resave: false,
    saveUninitialized: false,
    cookie: { 
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        maxAge: 30 * 60 * 1000 // 30 minutes session
    }
}));

// Rate limiting to prevent abuse
const validationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5 // limit each IP to 5 requests per windowMs
});
app.use('/validate', validationLimiter);

// Middleware to check if GitHub token is logged in
const requireGitHubTokenLogin = (req, res, next) => {
    if (!req.session.githubTokenVerified) {
        return res.status(401).json({ message: "GitHub token not authenticated. Please login first." });
    }
    next();
};

// GitHub Token Login Route
app.get('/login', (req, res) => {
    res.send(`
        <form action="/login" method="post">
            <h2>GitHub Token Authentication</h2>
            <label for="github_token">Enter GitHub Personal Access Token:</label>
            <input type="password" id="github_token" name="github_token" required>
            <button type="submit">Authenticate</button>
        </form>
    `);
});

app.post('/login', async (req, res) => {
    const { github_token } = req.body;

    if (!github_token) {
        return res.status(400).send('GitHub token is required');
    }

    try {
        // Verify GitHub token by making a simple API call
        const response = await axios.get('https://api.github.com/user', {
            headers: { Authorization: `Bearer ${github_token}` }
        });

        // If the call is successful, store token verification in session
        req.session.githubTokenVerified = true;
        req.session.githubToken = github_token;

        res.send(`
            <h2>Authentication Successful</h2>
            <p>Your GitHub token has been verified.</p>
            <a href="/validate-server">Proceed to Server Validation</a>
        `);
    } catch (error) {
        res.status(401).send('Invalid GitHub token. Authentication failed.');
    }
});

// Server Validation Route (now protected)
app.get('/validate-server', (req, res) => {
    res.send(`
        <form action="/validate" method="post">
            <h2>Server Validation</h2>
            <div>
                <label for="serverId">Server UUID:</label>
                <input type="text" id="serverId" name="serverId" required>
            </div>
            <div>
                <label for="serverIp">Server IP:</label>
                <input type="text" id="serverIp" name="serverIp" required>
            </div>
            <div>
                <label for="hostname">Hostname:</label>
                <input type="text" id="hostname" name="hostname" required>
            </div>
            <button type="submit">Validate Server</button>
        </form>
    `);
});

app.post('/validate', requireGitHubTokenLogin, async (req, res) => {
    const { serverId, serverIp, hostname } = req.body;
    const GITHUB_TOKEN = req.session.githubToken;

    // Enhanced input validation
    if (!serverId || !serverIp || !hostname) {
        return res.status(400).json({ message: "All fields are required." });
    }

    if (!validator.isUUID(serverId)) {
        return res.status(400).json({ message: "Invalid Server UUID format." });
    }

    if (!validator.isIP(serverIp)) {
        return res.status(400).json({ message: "Invalid IP address." });
    }

    if (!validator.isFQDN(hostname)) {
        return res.status(400).json({ message: "Invalid hostname." });
    }

    try {
        const REPO_OWNER = 'jefrygiglegroder';
        const REPO_NAME = 'PluginValidation';
        const FILE_PATH = 'servers.json';

        const url = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${FILE_PATH}`;
        const response = await axios.get(url, {
            headers: { Authorization: `Bearer ${GITHUB_TOKEN}` }
        });

        const fileContent = Buffer.from(response.data.content, 'base64').toString('utf-8');
        const jsonContent = JSON.parse(fileContent);

        const isDuplicate = jsonContent.approvedServers.some(
            server => server.serverId === serverId || 
                      server.ip === serverIp || 
                      server.hostname === hostname
        );

        if (isDuplicate) {
            return res.status(409).json({ message: "Server already validated." });
        }

        const validationToken = crypto.randomBytes(16).toString('hex');

        jsonContent.approvedServers.push({ 
            serverId, 
            ip: serverIp, 
            hostname,
            validatedAt: new Date().toISOString(),
            validationToken,
            status: 'pending'
        });

        const updatedContent = Buffer.from(JSON.stringify(jsonContent, null, 4)).toString('base64');
        await axios.put(url, {
            message: "Added new server to whitelist",
            content: updatedContent,
            sha: response.data.sha
        }, {
            headers: { Authorization: `Bearer ${GITHUB_TOKEN}` }
        });

        res.json({ 
            message: "Server validated and added successfully.",
            validationToken 
        });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ message: "Failed to validate server." });
    }
});

// Logout route to clear session
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Could not log out');
        }
        res.send(`
            <h2>Logged Out</h2>
            <p>Your GitHub token session has been cleared.</p>
            <a href="/login">Login Again</a>
        `);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
