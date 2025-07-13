require('dotenv').config();
const express = require('express');
const { google } = require('googleapis');
const { Gaxios } = require('gaxios');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

// --- Configuration ---
// CORRECTED: Use the /tmp directory for writable file storage on serverless environments
const SNIPPETS_PATH = path.join('/tmp', 'snippets');
const PASSWORDS_PATH = path.join('/tmp', 'passwords.json');
const TOKENS_PATH = path.join(__dirname, 'tokens.json'); // This is read-only, so it's fine here.


// Ensure temp directories and files exist in the /tmp folder
if (!fs.existsSync(SNIPPETS_PATH)) fs.mkdirSync(SNIPPETS_PATH, { recursive: true });
if (!fs.existsSync(PASSWORDS_PATH)) fs.writeFileSync(PASSWORDS_PATH, JSON.stringify({}));


const allowedAdminEmails = new Set(
    (process.env.ALLOWED_ADMIN_EMAILS || '').split(',').map(email => email.trim()).filter(Boolean)
);
const allowedClientEmails = new Set(
    (process.env.ALLOWED_CLIENT_EMAILS || '').split(',').map(email => email.trim()).filter(Boolean)
);

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  `${process.env.APP_URL}/api/auth/google/callback`
);

// --- Middleware ---
app.use(express.static('public'));
app.use(express.json({ limit: '10mb' }));

// --- Helper Functions ---

const verifyClient = async (req, res, next) => {
    try {
        const clientToken = req.headers['x-client-auth-token'];
        if (!clientToken) return res.status(401).json({ success: false, message: 'Client token missing.' });
        const ticket = await oauth2Client.verifyIdToken({
            idToken: clientToken,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        req.clientEmail = ticket.getPayload()['email'];
        if (!allowedClientEmails.has(req.clientEmail)) {
            return res.status(403).json({ success: false, message: 'Not authorized.' });
        }
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid token.' });
    }
};

// This function is less critical on serverless as the /tmp is cleared anyway, but good practice.
function cleanupTempFolders() {
    console.log('Running startup cleanup...');
    fs.readdir(SNIPPETS_PATH, (err, files) => {
        if (err) {
            // Ignore errors if the directory doesn't exist yet on first run
            if (err.code === 'ENOENT') return;
            return console.error(`Could not list directory: ${SNIPPETS_PATH}`, err);
        }
        for (const file of files) {
            fs.unlink(path.join(SNIPPETS_PATH, file), err => {
                if (err) console.error(`Error deleting file: ${file}`, err);
            });
        }
        console.log(`Cleaned up ${SNIPPETS_PATH}.`);
    });
}

function readPasswords() {
    try {
        // Ensure the file exists before trying to read it
        if (!fs.existsSync(PASSWORDS_PATH)) {
            fs.writeFileSync(PASSWORDS_PATH, JSON.stringify({}));
        }
        return JSON.parse(fs.readFileSync(PASSWORDS_PATH));
    } catch {
        return {};
    }
}

function writePasswords(data) {
    fs.writeFileSync(PASSWORDS_PATH, JSON.stringify(data, null, 2));
}

function loadTokens() {
  // tokens.json should be part of the deployment, so it's read-only.
  if (fs.existsSync(TOKENS_PATH)) return JSON.parse(fs.readFileSync(TOKENS_PATH));
  return [];
}

function saveTokens(tokens) {
  // This will fail on a read-only filesystem. Admin auth flow should be run locally.
  // On a serverless deploy, the tokens.json should be pre-populated and deployed with the service.
  try {
    fs.writeFileSync(TOKENS_PATH, JSON.stringify(tokens, null, 2));
  } catch (error) {
    console.warn("Could not save tokens. This is expected on a read-only filesystem. Ensure tokens.json is deployed with the service.");
  }
}

function getAvailableAccount() {
  const accounts = loadTokens();
  if (accounts.length === 0) return null;
  return accounts[Math.floor(Math.random() * accounts.length)];
}

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));


// --- API Routes ---

// Admin Auth (Unchanged, but note saveTokens will not work on Vercel)
app.get('/api/auth/google/callback', async (req, res) => { /* ... */ });
app.post('/api/verify-client', async (req, res) => { /* ... */ });


// Initiate Batch Upload with optional password
app.post('/api/initiate-batch-upload', verifyClient, async (req, res) => {
    try {
        const { files, password } = req.body;
        if (!files || !Array.isArray(files) || files.length === 0) {
            return res.status(400).json({ success: false, message: 'File list is required.' });
        }
        
        const account = getAvailableAccount();
        if (!account) return res.status(503).json({ success: false, message: 'Service unavailable.' });
        
        oauth2Client.setCredentials(account.tokens);
        const drive = google.drive({ version: 'v3', auth: oauth2Client });
        const folder = await drive.files.create({
            resource: { name: `DriveShare Batch - ${new Date().toISOString()}`, mimeType: 'application/vnd.google-apps.folder' },
            fields: 'id',
        });
        const folderId = folder.data.id;

        await drive.permissions.create({ fileId: folderId, resource: { role: 'reader', type: 'anyone' } });

        if (password) {
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(password, salt);
            const passwords = readPasswords();
            passwords[folderId] = hash;
            writePasswords(passwords);
        }

        const gaxios = new Gaxios();
        const { token } = await oauth2Client.getAccessToken();
        const origin = req.headers.origin || `http://localhost:${port}`;

        const uploadPromises = files.map(file => gaxios.request({
            method: 'POST',
            url: 'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json; charset=UTF-8',
                'X-Upload-Content-Type': file.fileType,
                'Origin': origin,
            },
            data: JSON.stringify({ name: file.fileName, parents: [folderId], mimeType: file.fileType })
        }));
        
        const responses = await Promise.all(uploadPromises);
        const uploadUrls = responses.map(response => response.headers.location);

        if (uploadUrls.some(url => !url)) throw new Error("Could not get all resumable upload URLs.");

        res.json({ success: true, uploadUrls, folderId });
    } catch (error) {
        console.error('Batch upload initiation failed:', error.message);
        res.status(500).json({ success: false, message: 'Failed to initiate batch upload.' });
    }
});

// UPDATED: Check if file share is protected, with backend retry logic
app.get('/api/files/:folderId', async (req, res) => {
    const { folderId } = req.params;
    const passwords = readPasswords();
    if (passwords[folderId]) {
        return res.json({ protected: true });
    }

    let retries = 3;
    while (retries > 0) {
        try {
            const account = getAvailableAccount();
            if (!account) return res.status(503).json({ message: 'Service unavailable.' });
            
            oauth2Client.setCredentials(account.tokens);
            const drive = google.drive({ version: 'v3', auth: oauth2Client });
            const fileList = await drive.files.list({
                q: `'${folderId}' in parents and trashed = false`,
                fields: 'files(id, name, size, iconLink)',
            });
            // Success
            return res.json({ protected: false, files: fileList.data.files });
        } catch (error) {
            if (error.code === 404 && retries > 0) {
                retries--;
                console.log(`Folder ${folderId} not found, retrying... (${retries} attempts left)`);
                await delay(2000); // Wait 2 seconds
            } else {
                console.error(`Final attempt failed for folder ${folderId}:`, error.message);
                return res.status(error.code || 500).json({ message: 'Folder not found or could not be accessed.' });
            }
        }
    }
    // This is only reached if all retries fail with a 404
    console.error(`Could not find folder ${folderId} after all retries.`);
    return res.status(404).json({ message: 'Folder not found after multiple attempts.' });
});


// Share Code Snippet with optional password
app.post('/api/share-code', verifyClient, async (req, res) => {
    const { code, password } = req.body;
    if (!code) return res.status(400).json({ success: false, message: 'Code cannot be empty.' });
    
    const snippetId = crypto.randomBytes(8).toString('hex');
    const filePath = path.join(SNIPPETS_PATH, `${snippetId}.txt`);
    
    fs.writeFile(filePath, code, async (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Failed to save snippet.' });
        
        if (password) {
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(password, salt);
            const passwords = readPasswords();
            passwords[snippetId] = hash;
            writePasswords(passwords);
        }
        res.json({ success: true, snippetId });
    });
});

// Check if code snippet is protected
app.get('/api/get-code/:snippetId', (req, res) => {
    const { snippetId } = req.params;
    const passwords = readPasswords();
    if (passwords[snippetId]) {
        return res.json({ protected: true });
    }
    const filePath = path.join(SNIPPETS_PATH, path.basename(snippetId));
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).json({ message: 'Snippet not found.' });
        res.json({ protected: false, code: data });
    });
});

// NEW: Verify password and grant access to content
app.post('/api/access-content', async (req, res) => {
    try {
        const { id, password, type } = req.body;
        if (!id || !password || !type) return res.status(400).json({ message: 'Missing parameters.' });

        const passwords = readPasswords();
        const hash = passwords[id];
        if (!hash) return res.status(404).json({ message: 'Content not found or not protected.' });

        const isValid = await bcrypt.compare(password, hash);
        if (!isValid) return res.status(401).json({ message: 'Invalid password.' });

        // If password is valid, return the content
        if (type === 'files') {
            const account = getAvailableAccount();
            if (!account) return res.status(503).json({ message: 'Service unavailable.' });
            oauth2Client.setCredentials(account.tokens);
            const drive = google.drive({ version: 'v3', auth: oauth2Client });
            const fileList = await drive.files.list({
                q: `'${id}' in parents and trashed = false`,
                fields: 'files(id, name, size, iconLink)',
            });
            return res.json({ success: true, files: fileList.data.files });
        } else if (type === 'code') {
            const filePath = path.join(SNIPPETS_PATH, path.basename(id));
            const code = fs.readFileSync(filePath, 'utf8');
            return res.json({ success: true, code: code });
        } else {
            return res.status(400).json({ message: 'Invalid content type.' });
        }
    } catch (error) {
        console.error("Access content error:", error.message);
        res.status(500).json({ message: 'An error occurred while accessing content.' });
    }
});


// Download routes (Unchanged)
app.get('/api/download/:fileId', async (req, res) => { /* ... */ });
app.get('/api/download-all/:folderId', async (req, res) => { /* ... */ });


// --- Start Server ---
cleanupTempFolders();
app.listen(port, () => {
  console.log(`Server listening at ${process.env.APP_URL || `http://localhost:${port}`}`);
});
