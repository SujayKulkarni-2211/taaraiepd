/**
 * TAARA Electron Main Process
 * ============================
 * 1. Starts the Python FastAPI server as a child process using the project venv
 * 2. Waits for the server to be ready (polls /api/health)
 * 3. Opens the BrowserWindow once the server responds
 * 4. Kills the server cleanly on app exit
 */

const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');

// ── Paths ─────────────────────────────────────────────────────────────────────
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const VENV_PYTHON  = path.join(PROJECT_ROOT, 'venv', 'bin', 'python');
const SERVER_SCRIPT = path.join(PROJECT_ROOT, 'server.py');
const SERVER_URL   = 'http://127.0.0.1:8765';
const SERVER_PORT  = 8765;
// IS_DEV only when explicitly set — running `electron .` is production mode
const IS_DEV       = process.env.NODE_ENV === 'development';

let mainWindow   = null;
let pythonServer = null;
let serverReady  = false;

// ── Start Python FastAPI server ───────────────────────────────────────────────
function startPythonServer() {
  // Verify venv python exists
  if (!fs.existsSync(VENV_PYTHON)) {
    console.error('[TAARA] venv python not found at:', VENV_PYTHON);
    return;
  }
  if (!fs.existsSync(SERVER_SCRIPT)) {
    console.error('[TAARA] server.py not found at:', SERVER_SCRIPT);
    return;
  }

  console.log('[TAARA] Starting Python server...');
  console.log('[TAARA] Python:', VENV_PYTHON);
  console.log('[TAARA] Script:', SERVER_SCRIPT);

  pythonServer = spawn(VENV_PYTHON, ['-m', 'uvicorn', 'server:app', '--host', '127.0.0.1', '--port', String(SERVER_PORT), '--log-level', 'info'], {
    cwd: PROJECT_ROOT,
    env: { ...process.env, PYTHONPATH: PROJECT_ROOT },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  pythonServer.stdout.on('data', (data) => {
    const line = data.toString().trim();
    console.log('[server]', line);
    // uvicorn logs "Application startup complete" when ready
    if (line.includes('Application startup complete') || line.includes('Uvicorn running')) {
      serverReady = true;
    }
  });

  pythonServer.stderr.on('data', (data) => {
    const line = data.toString().trim();
    console.log('[server:err]', line);
    // uvicorn also logs startup on stderr in some versions
    if (line.includes('Application startup complete') || line.includes('Uvicorn running') || line.includes('Started server process')) {
      serverReady = true;
    }
  });

  pythonServer.on('exit', (code, signal) => {
    console.log(`[TAARA] Python server exited — code: ${code}, signal: ${signal}`);
    pythonServer = null;
    serverReady = false;
  });

  pythonServer.on('error', (err) => {
    console.error('[TAARA] Failed to spawn Python server:', err.message);
  });
}

// ── Poll until server responds on /api/health ─────────────────────────────────
// Note: uvicorn logs "Application startup complete" BEFORE _init_systems() finishes
// loading torch/pennylane models (~60s cold start). Trust only HTTP health check.
function waitForServer(maxAttempts = 90, intervalMs = 1000) {
  return new Promise((resolve, reject) => {
    let attempts = 0;

    const check = () => {
      attempts++;
      const req = http.get(`${SERVER_URL}/api/health`, { timeout: 3000 }, (res) => {
        if (res.statusCode === 200) {
          console.log(`[TAARA] Server ready after ${attempts} attempt(s)`);
          resolve();
        } else {
          retry();
        }
      });
      req.on('error', retry);
      req.on('timeout', () => { req.destroy(); retry(); });
    };

    const retry = () => {
      if (attempts >= maxAttempts) {
        reject(new Error(`Server did not respond after ${maxAttempts} attempts`));
        return;
      }
      setTimeout(check, intervalMs);
    };

    // First check after 2s — give uvicorn time to bind the port
    setTimeout(check, 2000);
  });
}

// ── Create the main window ─────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#0a0a1a',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      // Allow file:// to load local assets — IPC bridge handles all API calls
      webSecurity: false,
    },
    show: false, // show once ready-to-show fires
  });

  // Load the React app
  if (IS_DEV) {
    console.log('[TAARA] Loading dev server: http://localhost:3000');
    mainWindow.loadURL('http://localhost:3000');
  } else {
    const indexPath = path.join(__dirname, '..', 'build', 'index.html');
    console.log('[TAARA] Loading build:', indexPath);
    mainWindow.loadFile(indexPath); // loadFile handles relative asset paths correctly
  }

  // Show window once paint is ready — avoids white flash
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    // Only open DevTools in explicit dev mode
    if (IS_DEV) mainWindow.webContents.openDevTools();
  });

  // Catch page load failures and show a useful message
  mainWindow.webContents.on('did-fail-load', (_e, code, desc, url) => {
    console.error('[TAARA] Page failed to load:', url, code, desc);
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Open external links in the system browser, not Electron
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      shell.openExternal(url);
      return { action: 'deny' };
    }
    return { action: 'allow' };
  });
}

// ── IPC handlers — renderer calls these via preload ───────────────────────────

// Generic API proxy — renderer sends { endpoint, method, body }
// main process makes the http call (avoids CORS entirely)
ipcMain.handle('taara:api', async (_event, { endpoint, method = 'GET', body = null }) => {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, SERVER_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers: { 'Content-Type': 'application/json' },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    // Fast endpoints get short timeout; slow SSH/analysis/deploy get long timeout
    const fastEndpoints = ['/api/health', '/api/status', '/api/alerts', '/api/train/status',
                           '/api/taaraware/status', '/api/taaraware/deployed', '/api/actions',
                           '/api/agent/stats', '/api/taara/basis-status'];
    const isFast = fastEndpoints.some(p => url.pathname.startsWith(p));
    req.setTimeout(isFast ? 8000 : 300000);

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
});

// Open a local file path in the system default viewer
ipcMain.handle('taara:openPDF', async (_event, filePath) => {
  // Resolve relative paths from PROJECT_ROOT
  const resolved = path.isAbsolute(filePath) ? filePath : path.join(PROJECT_ROOT, filePath);
  await shell.openPath(resolved);
});

// Open a URL in the system default browser
ipcMain.handle('taara:openExternal', async (_event, url) => {
  await shell.openExternal(url);
});

// Open a specific view in a new Electron window
ipcMain.handle('taara:openWindow', async (_event, { view, title }) => {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0a0a14',
    title: title || 'TAARA',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: false,
    },
  });
  const IS_DEV_WIN = process.env.NODE_ENV === 'development';
  if (IS_DEV_WIN) {
    win.loadURL(`http://localhost:3000?view=${encodeURIComponent(view)}`);
  } else {
    const indexPath = path.join(__dirname, '..', 'build', 'index.html');
    win.loadFile(indexPath, { query: { view } });
  }
});

// Return server status for renderer startup check
ipcMain.handle('taara:serverStatus', () => ({
  ready: serverReady,
  url: SERVER_URL,
}));

// ── App lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  // Show window immediately with boot screen
  createWindow();

  // Check if server is already running (e.g., dev mode or stale process)
  const alreadyUp = await new Promise(resolve => {
    const req = http.get(`${SERVER_URL}/api/health`, { timeout: 1000 }, (res) => {
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });

  if (alreadyUp) {
    console.log('[TAARA] Server already running — skipping spawn');
    serverReady = true;
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('taara:serverReady');
    }
    return;
  }

  // Start fresh Python server
  startPythonServer();

  try {
    // Wait for server, update window when ready
    await waitForServer(90, 1000); // up to 90 seconds — uvicorn+torch can take 60s cold start
    serverReady = true;

    // Tell the renderer the server is ready
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('taara:serverReady');
    }
  } catch (err) {
    console.error('[TAARA] Server failed to start:', err.message);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('taara:serverError', err.message);
    }
  }
});

app.on('window-all-closed', () => {
  killServer();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on('before-quit', killServer);

function killServer() {
  if (pythonServer) {
    console.log('[TAARA] Killing Python server...');
    pythonServer.kill('SIGTERM');
    // Force kill after 3 seconds if it doesn't exit
    setTimeout(() => {
      if (pythonServer) {
        pythonServer.kill('SIGKILL');
        pythonServer = null;
      }
    }, 3000);
  }
}
