require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const validator = require('validator');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(bodyParser.json());

// Rate limiting to prevent abuse
const validationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5 // limit each IP to 5 requests per windowMs
});
app.use('/validate', validationLimiter);

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
if (!GITHUB_TOKEN) {
    throw new Error("GITHUB_TOKEN is not defined in the environment variables.");
}

const REPO_OWNER = 'jefrygiglegroder';
const REPO_NAME = 'PluginValidation';
const FILE_PATH = 'servers.json';

app.post('/validate', async (req, res) => {
    const { serverId, serverIp, hostname } = req.body;

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
