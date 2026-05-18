/**
 * TAARA Preload Script
 * =====================
 * Runs in the renderer process with Node access (contextIsolation = true).
 * Exposes a clean window.taara API — renderer never touches Node or Electron directly.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('taara', {
  /**
   * Make an API call to the Python FastAPI server.
   * @param {string} endpoint - e.g. '/api/health'
   * @param {string} method   - 'GET' | 'POST' | 'DELETE'
   * @param {object} body     - JSON body for POST requests
   * @returns {Promise<{status: number, data: any}>}
   */
  api: (endpoint, method = 'GET', body = null) =>
    ipcRenderer.invoke('taara:api', { endpoint, method, body }),

  /**
   * Open a local file path in the system default viewer.
   */
  openPDF: (filePath) =>
    ipcRenderer.invoke('taara:openPDF', filePath),

  /**
   * Open a URL in the system default browser.
   */
  openExternal: (url) =>
    ipcRenderer.invoke('taara:openExternal', url),

  /**
   * Get current server status (ready or not).
   */
  serverStatus: () =>
    ipcRenderer.invoke('taara:serverStatus'),

  /**
   * Listen for server lifecycle events from main process.
   * Returns a cleanup function to remove the listener.
   */
  onServerReady: (callback) => {
    ipcRenderer.on('taara:serverReady', callback);
    return () => ipcRenderer.removeListener('taara:serverReady', callback);
  },

  onServerError: (callback) => {
    ipcRenderer.on('taara:serverError', (_event, msg) => callback(msg));
    return () => ipcRenderer.removeListener('taara:serverError', callback);
  },

  /**
   * Open a view in a new window (right-click tab).
   */
  openWindow: (view, title) =>
    ipcRenderer.invoke('taara:openWindow', { view, title }),

  /**
   * Platform information.
   */
  platform: process.platform,
});
