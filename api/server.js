// Use path.join to create a reliable path to the .env file in the project root
const path = require('path');
const fs = require('fs');

// Add a check to see if the .env file is found, and log it for debugging.
const dotenvPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(dotenvPath)) {
    console.log(`Loading environment variables from: ${dotenvPath}`);
    require('dotenv').config({ path: dotenvPath });
} else {
    console.warn(`Warning: .env file not found at ${dotenvPath}. Using Vercel environment variables.`);
}


const express = require('express');
const { google } = require('googleapis');
const { Gaxios } = require('gaxios');
const os = require('os');
const archiver = require('archiver');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;

// --- Configuration ---
// Use the OS's temporary directory for writable files to ensure Vercel compatibility
const WRITABLE_DIR = os.tmpdir();
const TOKENS_PATH = path.join(WRITABLE_DIR, 'driveshare_tokens.json');
const SNIPPETS_PATH = path.join(WRITABLE_DIR, 'driveshare_snippets');
const DELETION_SCHEDULE_PATH = path.join(WRITABLE_DIR, 'driveshare_deletions.json');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SALT_ROUNDS = 10;

// --- Startup Environment Check ---
const requiredEnvVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'APP_URL'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
    throw new Error(`FATAL ERROR: Missing required environment variables: ${missingEnvVars.join(', ')}. Please set them in your Vercel project settings.`);
}


// Ensure temp directories exist
if (!fs.existsSync(SNIPPETS_PATH)) fs.mkdirSync(SNIPPETS_PATH);

const allowedAdminEmails = new Set(
    (process.env.ALLOWED_ADMIN_EMAILS || '').split(',').map(email => email.trim()).filter(Boolean)
);
const allowedClientEmails = new Set(
    (process.env.ALLOWED_CLIENT_EMAILS || '').split(',').map(email => email.trim()).filter(Boolean)
);

// This is the main client for the initial auth flow
const mainOauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  `${process.env.APP_URL}/api/auth/google/callback`
);

// --- Middleware ---
app.use(cors()); // Allow cross-origin requests
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.json({ limit: '10mb' }));

// --- Helper Functions ---

const verifyClient = async (req, res, next) => {
    try {
        const clientToken = req.headers['x-client-auth-token'];
        if (!clientToken) {
            return res.status(401).json({ success: false, message: 'Client authentication token is missing.' });
        }
        // Use the main client for verifying user tokens
        const ticket = await mainOauth2Client.verifyIdToken({
            idToken: clientToken,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const clientEmail = payload['email'];
        if (!allowedClientEmails.has(clientEmail)) {
            console.warn(`Unauthorized API access attempt by client: ${clientEmail}`);
            return res.status(403).json({ success: false, message: 'You are not authorized to perform this action.' });
        }
        req.clientEmail = clientEmail;
        next();
    } catch (error) {
        console.error('Client verification middleware failed:', error);
        return res.status(401).json({ success: false, message: 'Invalid authentication token.' });
    }
};

const verifyAccessJWT = (req, res, next) => {
    try {
        const token = req.headers['x-access-token'] || req.query.token;
        if (!token) {
            return res.status(401).json({ message: 'Access token is missing.' });
        }
        const decoded = jwt.verify(token, JWT_SECRET);
        req.jwtPayload = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired access token.' });
    }
};


function cleanupTempFolders() {
    console.log('Running startup cleanup...');
    fs.readdir(SNIPPETS_PATH, (err, files) => {
        if (err) {
            // Ignore error if directory doesn't exist yet
            if (err.code === 'ENOENT') return;
            console.error(`Could not list the directory: ${SNIPPETS_PATH}`, err);
            return;
        }
        for (const file of files) {
            fs.unlink(path.join(SNIPPETS_PATH, file), err => {
                if (err) console.error(`Error deleting file: ${file}`, err);
            });
        }
        console.log(`Cleaned up ${SNIPPETS_PATH}.`);
    });
}

function loadTokens() {
  if (fs.existsSync(TOKENS_PATH)) {
    return JSON.parse(fs.readFileSync(TOKENS_PATH));
  }
  return [];
}

function saveTokens(tokens) {
  fs.writeFileSync(TOKENS_PATH, JSON.stringify(tokens, null, 2));
}

// --- Deletion Scheduling Functions ---
function loadDeletions() {
    if (fs.existsSync(DELETION_SCHEDULE_PATH)) {
        try {
            return JSON.parse(fs.readFileSync(DELETION_SCHEDULE_PATH));
        } catch (e) {
            console.error("Could not parse deletion schedule, returning empty.", e);
            return [];
        }
    }
    return [];
}

function saveDeletions(deletions) {
    fs.writeFileSync(DELETION_SCHEDULE_PATH, JSON.stringify(deletions, null, 2));
}

function scheduleDeletion(type, id, retentionDays) {
    if (!retentionDays || retentionDays <= 0) {
        return; // Do not schedule if retention is 0 or invalid
    }
    const deletions = loadDeletions();
    const deleteAt = new Date();
    deleteAt.setDate(deleteAt.getDate() + retentionDays);

    deletions.push({ type, id, deleteAt: deleteAt.toISOString() });
    saveDeletions(deletions);
    console.log(`Scheduled ${type} ${id} for deletion on ${deleteAt.toISOString()}`);
}


// Gets an account that has enough storage for the upload
async function getAccountWithSufficientStorage(requiredSize) {
    const accounts = loadTokens();
    if (accounts.length === 0) return null;

    // Shuffle accounts to distribute load randomly
    for (let i = accounts.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [accounts[i], accounts[j]] = [accounts[j], accounts[i]];
    }

    for (const account of accounts) {
        try {
            // Create a new, isolated client for each account check
            const tempOauth2Client = new google.auth.OAuth2(
                process.env.GOOGLE_CLIENT_ID,
                process.env.GOOGLE_CLIENT_SECRET
            );
            tempOauth2Client.setCredentials(account.tokens);
            const drive = google.drive({ version: 'v3', auth: tempOauth2Client });
            const about = await drive.about.get({ fields: 'storageQuota' });
            
            const { limit, usage } = about.data.storageQuota;
            const availableSpace = BigInt(limit) - BigInt(usage);
            
            console.log(`Account ${account.email} has ${availableSpace} bytes available.`);

            if (availableSpace > BigInt(requiredSize)) {
                console.log(`Found suitable account: ${account.email}`);
                return account; // Found a suitable account
            }
        } catch (error) {
            console.error(`Could not check storage for account ${account.email}:`, error.message);
            // Continue to the next account
        }
    }

    return null; // No suitable account found
}


// --- API Routes ---

// Serve the frontend for the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Admin Auth Flow
app.get('/api/auth/google', (req, res) => {
  const authUrl = mainOauth2Client.generateAuthUrl({
    access_type: 'offline', prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/drive.readonly.metadata'],
  });
  res.redirect(authUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { tokens } = await mainOauth2Client.getToken(req.query.code);
    mainOauth2Client.setCredentials(tokens);
    const userInfo = await google.oauth2({ version: 'v2', auth: mainOauth2Client }).userinfo.get();
    const userEmail = userInfo.data.email;
    if (allowedAdminEmails.size > 0 && !allowedAdminEmails.has(userEmail)) {
        return res.status(403).send('<h1>Access Denied</h1>');
    }
    const allTokens = loadTokens();
    const existingAccountIndex = allTokens.findIndex(t => t.email === userEmail);
    if (existingAccountIndex >= 0) allTokens[existingAccountIndex] = { email: userEmail, tokens };
    else allTokens.push({ email: userEmail, tokens });
    saveTokens(allTokens);
    res.send('<h1>Authentication successful!</h1><p>You can now close this tab.</p>');
  } catch (error) {
    console.error('Error getting tokens', error);
    res.status(500).send('Authentication failed.');
  }
});

// Client Verification
app.post('/api/verify-client', async (req, res) => {
    try {
        const ticket = await mainOauth2Client.verifyIdToken({
            idToken: req.headers['x-client-auth-token'],
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const clientEmail = ticket.getPayload()['email'];
        if (allowedClientEmails.has(clientEmail)) {
            res.json({ success: true, authorized: true, email: clientEmail });
        } else {
            res.status(403).json({ success: false, authorized: false, message: 'Account not authorized.' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Could not verify account.' });
    }
});

// Initiate Batch Upload
app.post('/api/initiate-batch-upload', verifyClient, async (req, res) => {
    try {
        const { files, password, retentionDays } = req.body;
        if (!files || !Array.isArray(files) || files.length === 0) {
            return res.status(400).json({ success: false, message: 'File list is required.' });
        }
        
        const totalUploadSize = files.reduce((sum, file) => sum + (file.size || 0), 0);
        if (totalUploadSize === 0) {
             return res.status(400).json({ success: false, message: 'Cannot upload empty files.' });
        }

        const account = await getAccountWithSufficientStorage(totalUploadSize);
        if (!account) {
            return res.status(507).json({ success: false, message: 'Insufficient storage space across all available admin accounts.' });
        }
        
        // Create a new, dedicated client for this upload operation
        const operationOauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );
        operationOauth2Client.setCredentials(account.tokens);

        const drive = google.drive({ version: 'v3', auth: operationOauth2Client });
        
        // --- New Folder Naming Logic ---
        let folderNameParts = [];
        if (password) {
            folderNameParts.push("Encrypted");
        }
        if (retentionDays && retentionDays > 0) {
            const expirationDate = new Date();
            expirationDate.setDate(expirationDate.getDate() + retentionDays);
            const dateString = expirationDate.toISOString().split('T')[0]; // Format as YYYY-MM-DD
            folderNameParts.push(`Expires ${dateString}`);
        }
        folderNameParts.push(`Share ${crypto.randomBytes(4).toString('hex')}`);
        const folderName = folderNameParts.join(' - ');
        
        const folderMetadata = {
            name: folderName,
            mimeType: 'application/vnd.google-apps.folder',
        };

        if (password) {
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
            folderMetadata.description = JSON.stringify({ p: hashedPassword });
        }

        const folder = await drive.files.create({
            resource: folderMetadata,
            fields: 'id',
        });
        const folderId = folder.data.id;

        // Schedule deletion if retentionDays is set
        scheduleDeletion('driveFolder', folderId, retentionDays);

        await drive.permissions.create({
            fileId: folderId,
            resource: { role: 'reader', type: 'anyone' },
        });

        const gaxios = new Gaxios();
        const { token } = await operationOauth2Client.getAccessToken();
        
        const origin = process.env.APP_URL || `http://localhost:${port}`;

        const uploadPromises = files.map(file => {
            return gaxios.request({
                method: 'POST',
                url: 'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json; charset=UTF-8',
                    'X-Upload-Content-Type': file.fileType,
                    'Origin': origin,
                },
                data: JSON.stringify({
                    name: file.fileName,
                    parents: [folderId],
                    mimeType: file.fileType,
                })
            });
        });
        
        const responses = await Promise.all(uploadPromises);
        const uploadUrls = responses.map(response => response.headers.location);

        if (uploadUrls.some(url => !url)) {
            throw new Error("Could not get resumable upload URLs for all files.");
        }

        res.json({ success: true, uploadUrls, folderId });

    } catch (error) {
        console.error('Batch upload initiation failed:', error.message);
        res.status(500).json({ success: false, message: 'Failed to initiate batch upload session with Google Drive.' });
    }
});

// Verify Password for a File Batch
app.post('/api/verify-password/file/:folderId', async (req, res) => {
    try {
        const { folderId } = req.params;
        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ message: 'Password is required.' });
        }

        const accounts = loadTokens();
        if (accounts.length === 0) return res.status(503).json({ message: 'Service unavailable.' });
        
        const tempOauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );
        tempOauth2Client.setCredentials(accounts[0].tokens); // Use any account to check metadata
        const drive = google.drive({ version: 'v3', auth: tempOauth2Client });

        const folder = await drive.files.get({ fileId: folderId, fields: 'description' });
        const description = folder.data.description;
        if (!description) return res.status(403).json({ message: 'Incorrect password.' });

        const descJson = JSON.parse(description);
        const hashedPassword = descJson.p;
        if (!hashedPassword) return res.status(403).json({ message: 'Incorrect password.' });

        const match = await bcrypt.compare(password, hashedPassword);
        if (match) {
            const token = jwt.sign({ id: folderId }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ success: true, token });
        } else {
            res.status(403).json({ message: 'Incorrect password.' });
        }
    } catch (error) {
        console.error('File password verification failed:', error.message);
        res.status(500).json({ message: 'Could not verify password.' });
    }
});


// Get File List for Download Page
app.get('/api/files/:folderId', async (req, res) => {
    try {
        const accounts = loadTokens();
        if (accounts.length === 0) {
            return res.status(503).json({ message: 'Service unavailable: No admin accounts configured.' });
        }
        const tempOauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );
        tempOauth2Client.setCredentials(accounts[0].tokens);
        const drive = google.drive({ version: 'v3', auth: tempOauth2Client });

        const folderInfo = await drive.files.get({
            fileId: req.params.folderId,
            fields: 'description'
        });

        if (folderInfo.data.description) {
            try {
                const descJson = JSON.parse(folderInfo.data.description);
                if (descJson.p) { // Password exists
                    const token = req.headers['x-access-token'];
                    if (!token) {
                        return res.status(401).json({ message: 'Password required.', passwordRequired: true });
                    }
                    
                    try {
                        const decoded = jwt.verify(token, JWT_SECRET);
                        if (decoded.id !== req.params.folderId) {
                            return res.status(403).json({ message: 'Forbidden: Invalid token for this resource.', passwordRequired: true });
                        }
                    } catch (jwtError) {
                        return res.status(401).json({ message: 'Invalid or expired access token.', passwordRequired: true });
                    }
                }
            } catch (e) { /* Not a JSON description, treat as no password */ }
        }

        const fileList = await drive.files.list({
            q: `'${req.params.folderId}' in parents and trashed = false`,
            fields: 'files(id, name, size, iconLink)',
        });
        return res.json(fileList.data.files);
    } catch (error) {
        console.error('Failed to list files:', error.message);
        if (error.response && error.response.data) {
             return res.status(error.response.status || 500).json(error.response.data);
        }
        return res.status(404).json({ message: 'Folder not found or could not be accessed.' });
    }
});

// Download Single File
app.get('/api/download/:fileId', async (req, res) => {
    try {
        const accounts = loadTokens();
        if (accounts.length === 0) return res.status(503).send('Service not available.');
        
        const tempOauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );
        tempOauth2Client.setCredentials(accounts[0].tokens);
        const drive = google.drive({ version: 'v3', auth: tempOauth2Client });
        
        const fileMetadata = await drive.files.get({ fileId: req.params.fileId, fields: 'name, mimeType, size, parents' });
        
        const parentFolderId = fileMetadata.data.parents[0];
        if (parentFolderId) {
             const folderInfo = await drive.files.get({ fileId: parentFolderId, fields: 'description' });
             if (folderInfo.data.description) {
                try {
                    const descJson = JSON.parse(folderInfo.data.description);
                    if (descJson.p) {
                        const token = req.headers['x-access-token'] || req.query.token;
                         if (!token) {
                             return res.status(401).json({ message: 'Password required.', passwordRequired: true });
                         }
                         try {
                            const decoded = jwt.verify(token, JWT_SECRET);
                            if (decoded.id !== parentFolderId) {
                                return res.status(403).json({ message: 'Forbidden: Invalid token for this resource.', passwordRequired: true });
                            }
                        } catch (jwtError) {
                            return res.status(401).json({ message: 'Invalid or expired access token.', passwordRequired: true });
                        }
                    }
                } catch(e) { /* Not a JSON description, treat as no password */ }
             }
        }
        
        res.setHeader('Content-Disposition', `attachment; filename="${fileMetadata.data.name}"`);
        res.setHeader('Content-Type', fileMetadata.data.mimeType);
        res.setHeader('Content-Length', fileMetadata.data.size);
        const driveRes = await drive.files.get({ fileId: req.params.fileId, alt: 'media' }, { responseType: 'stream' });
        driveRes.data.pipe(res);
    } catch (error) {
        console.error(`Download failed for fileId ${req.params.fileId}:`, error.message);
        if (!res.headersSent) {
            res.status(404).send('File not found or download failed.');
        }
    }
});

// Download All as ZIP
app.get('/api/download-all/:folderId', async (req, res) => {
    try {
        const { folderId } = req.params;
        const accounts = loadTokens();
        if (accounts.length === 0) return res.status(503).send('Service not available.');
        
        const tempOauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );
        tempOauth2Client.setCredentials(accounts[0].tokens);
        const drive = google.drive({ version: 'v3', auth: tempOauth2Client });

        // Check for password protection
        const folderInfo = await drive.files.get({ fileId: folderId, fields: 'description' });
        if (folderInfo.data.description) {
            try {
                const descJson = JSON.parse(folderInfo.data.description);
                if (descJson.p) { // Password exists, so JWT is required
                    const token = req.query.token; // Get token from query
                    if (!token) {
                        return res.status(401).json({ message: 'Access token is missing.' });
                    }
                    try {
                        const decoded = jwt.verify(token, JWT_SECRET);
                        if (decoded.id !== folderId) {
                            return res.status(403).send('Forbidden: Invalid token for this resource.');
                        }
                    } catch (jwtError) {
                        return res.status(401).json({ message: 'Invalid or expired access token.' });
                    }
                }
            } catch (e) { /* Not a JSON description, treat as no password */ }
        }

        // --- If we get here, access is granted (either public or valid token) ---

        const fileListResponse = await drive.files.list({
            q: `'${folderId}' in parents and trashed = false`,
            fields: 'files(id, name)',
        });
        const files = fileListResponse.data.files;
        if (!files || files.length === 0) return res.status(404).send('No files found.');

        const archive = archiver('zip');
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="driveshare_${folderId}.zip"`);
        archive.pipe(res);

        for (const file of files) {
            // We need a fresh readable stream for each file
            const fileStream = await drive.files.get({ fileId: file.id, alt: 'media' }, { responseType: 'stream' });
            archive.append(fileStream.data, { name: file.name });
        }
        await archive.finalize();

    } catch (error) {
        console.error('Download all failed:', error.message);
        res.status(500).send('Failed to create zip archive.');
    }
});

// --- Code Snippet Routes ---

// Share Code Snippet
app.post('/api/share-code', verifyClient, async (req, res) => {
    try {
        const { code, password, retentionDays } = req.body;
        const snippetId = crypto.randomBytes(8).toString('hex');
        const filePath = path.join(SNIPPETS_PATH, `${snippetId}.json`);
        
        const dataToStore = { code };
        if (password) {
            dataToStore.password = await bcrypt.hash(password, SALT_ROUNDS);
        }

        fs.writeFile(filePath, JSON.stringify(dataToStore), (err) => {
            if (err) return res.status(500).json({ success: false, message: 'Failed to save snippet.' });
            
            // Schedule deletion if retentionDays is set
            scheduleDeletion('snippet', snippetId, retentionDays);
            
            res.json({ success: true, snippetId });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to process snippet.' });
    }
});

// Verify Password for a Code Snippet
app.post('/api/verify-password/code/:snippetId', async (req, res) => {
    try {
        const { snippetId } = req.params;
        const { password } = req.body;
        if (!password) return res.status(400).json({ message: 'Password is required.' });

        const filePath = path.join(SNIPPETS_PATH, path.basename(`${snippetId}.json`));
        if (!fs.existsSync(filePath)) return res.status(404).json({ message: 'Snippet not found.'});

        const fileContent = fs.readFileSync(filePath, 'utf8');
        const data = JSON.parse(fileContent);

        if (!data.password) return res.status(403).json({ message: 'Incorrect password.' });

        const match = await bcrypt.compare(password, data.password);
        if (match) {
            const token = jwt.sign({ id: snippetId }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ success: true, token });
        } else {
            res.status(403).json({ message: 'Incorrect password.' });
        }
    } catch (error) {
        console.error('Code password verification failed:', error.message);
        res.status(500).json({ message: 'Could not verify password.' });
    }
});

// Get Code Snippet
app.get('/api/get-code/:snippetId', (req, res) => {
    const filePath = path.join(SNIPPETS_PATH, path.basename(`${req.params.snippetId}.json`));
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ success: false, message: 'Snippet not found.' });
    }

    fs.readFile(filePath, 'utf8', (err, fileContent) => {
        if (err) return res.status(500).json({ success: false, message: 'Could not read snippet.' });
        
        const data = JSON.parse(fileContent);
        if (data.password) {
            try {
                const token = req.headers['x-access-token'];
                if (!token) throw new Error();
                const decoded = jwt.verify(token, JWT_SECRET);
                if (decoded.id !== req.params.snippetId) throw new Error();
            } catch (e) {
                return res.status(401).json({ success: false, message: 'Password required.', passwordRequired: true });
            }
        }
        res.json({ success: true, code: data.code });
    });
});


// --- Deletion Job ---
async function runDeletionJob() {
    console.log('Running scheduled deletion job...');
    const allDeletions = loadDeletions();
    const now = new Date();
    
    const expired = allDeletions.filter(item => new Date(item.deleteAt) <= now);
    const remaining = allDeletions.filter(item => new Date(item.deleteAt) > now);

    if (expired.length === 0) {
        console.log('No expired items to delete.');
        return;
    }

    console.log(`Found ${expired.length} item(s) to delete.`);

    // Use the first available admin account for all deletions in this job run
    const accounts = loadTokens();
    if (accounts.length === 0) {
        console.error('Deletion job failed: No admin accounts configured.');
        return;
    }
    const deletionClient = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET
    );
    deletionClient.setCredentials(accounts[0].tokens);
    const drive = google.drive({ version: 'v3', auth: deletionClient });

    for (const item of expired) {
        try {
            if (item.type === 'driveFolder') {
                console.log(`Deleting Drive folder: ${item.id}`);
                await drive.files.delete({ fileId: item.id });
                console.log(`Successfully deleted Drive folder: ${item.id}`);
            } else if (item.type === 'snippet') {
                console.log(`Deleting snippet: ${item.id}`);
                const filePath = path.join(SNIPPETS_PATH, `${item.id}.json`);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                    console.log(`Successfully deleted snippet: ${item.id}`);
                }
            }
        } catch (error) {
            console.error(`Failed to delete ${item.type} ${item.id}:`, error.message);
        }
    }

    saveDeletions(remaining);
    console.log('Deletion job finished.');
}


// --- Start Server ---
cleanupTempFolders();
app.listen(port, () => {
  console.log(`Server listening at ${process.env.APP_URL || `http://localhost:${port}`}`);
  console.log(`JWT Secret is configured.`);
  // Run the deletion job every hour
  setInterval(runDeletionJob, 3600000);
  // Also run it once on startup after a short delay
  setTimeout(runDeletionJob, 5000); 
});
