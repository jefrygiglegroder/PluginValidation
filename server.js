const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());

const GITHUB_TOKEN = 'your_personal_access_token';
const REPO_OWNER = 'yourusername';
const REPO_NAME = 'PluginValidation';
const FILE_PATH = 'servers.json';

app.post('/validate', async (req, res) => {
    const { serverId, serverIp, hostname } = req.body;

    if (!serverId || !serverIp || !hostname) {
        return res.status(400).json({ message: "All fields are required." });
    }

    try {
        // Fetch the current servers.json file
        const url = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${FILE_PATH}`;
        const response = await axios.get(url, {
            headers: { Authorization: `token ${GITHUB_TOKEN}` }
        });

        const fileContent = Buffer.from(response.data.content, 'base64').toString('utf-8');
        const jsonContent = JSON.parse(fileContent);

        // Add the new server to the whitelist
        jsonContent.approvedServers.push({ serverId, ip: serverIp, hostname });

        // Update the servers.json file on GitHub
        const updatedContent = Buffer.from(JSON.stringify(jsonContent, null, 4)).toString('base64');
        await axios.put(url, {
            message: "Added new server to whitelist",
            content: updatedContent,
            sha: response.data.sha
        }, {
            headers: { Authorization: `token ${GITHUB_TOKEN}` }
        });

        res.json({ message: "Server validated and added successfully." });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ message: "Failed to validate server." });
    }
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
