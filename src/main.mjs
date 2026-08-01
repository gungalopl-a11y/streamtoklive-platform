import {
  app,
  BrowserWindow,
  ipcMain,
  Notification,
  safeStorage,
  session as electronSession,
  shell,
} from 'electron';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import {
  appendFile,
  chmod,
  mkdir,
  readFile,
  rename,
  stat,
  writeFile,
} from 'node:fs/promises';
import { hostname, platform, release } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const productionWebUrl = 'https://streamtoklive.com';
const productionApiUrl = 'https://appi.streamtoklive.com';
const webUrl = app.isPackaged ? productionWebUrl : (process.env.WEB_URL ?? productionWebUrl);
const apiUrl = app.isPackaged ? productionApiUrl : (process.env.API_URL ?? process.env.VITE_API_URL ?? productionApiUrl);
const webOrigin = new URL(webUrl).origin;
const offlinePage = resolve(here, 'offline.html');
const maxLogSize = 2 * 1024 * 1024;

app.setName('StreamTokLive');
app.commandLine.removeSwitch('remote-debugging-port');
app.commandLine.removeSwitch('remote-debugging-pipe');
if (process.platform === 'win32') app.setAppUserModelId('com.streamtoklive.desktop');
app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');
app.commandLine.appendSwitch('disable-http-cache');

const allowedExternalHosts = new Set([
  'accounts.google.com',
  'localhost',
  '127.0.0.1',
  't.me',
  'telegram.me',
  'tiktok.com',
  'www.tiktok.com',
]);
for (const configuredUrl of [webUrl, apiUrl, process.env.SUPPORT_URL ?? 'https://t.me/Evgenyevgg']) {
  try {
    allowedExternalHosts.add(new URL(configuredUrl).hostname);
  } catch {}
}

const allowedProofPrefixes = new Set([
  'launchertok-device-exchange-v1',
  'launchertok-device-refresh-v1',
  'launchertok-game-launch-v1',
]);

const accessNoticeCopy = new Map([
  ['USER_SUSPENDED', ['Аккаунт заблокирован', 'Доступ к StreamTokLive ограничен администратором.']],
  ['DEVICE_REVOKED', ['Устройство отключено', 'Это устройство отвязано администратором.']],
  ['ALL_DEVICES_REVOKED', ['Устройства отключены', 'Устройства аккаунта отвязаны администратором.']],
  ['SESSION_REVOKED', ['Сеанс завершён', 'Этот сеанс завершён администратором.']],
  ['ALL_SESSIONS_REVOKED', ['Сеансы завершены', 'Все сеансы аккаунта завершены администратором.']],
  ['SESSION_EXPIRED', ['Сеанс истёк', 'Выполните вход в StreamTokLive снова.']],
  ['SIGNED_OUT', ['Вход завершён', 'Сеанс StreamTokLive больше не активен.']],
]);

let cachedIdentity = null;
let mainWindow = null;
let lastAccessNoticeAt = 0;
let logFile = null;
let quitting = false;

const allowDevTools = !app.isPackaged
  && ['1', 'true', 'yes', 'on'].includes(String(process.env.ELECTRON_ALLOW_DEVTOOLS ?? '').trim().toLowerCase());
const openDevToolsOnStart = allowDevTools
  && ['1', 'true', 'yes', 'on'].includes(String(process.env.ELECTRON_OPEN_DEVTOOLS_ON_START ?? '').trim().toLowerCase());

function sanitizedUrl(value) {
  try {
    const url = new URL(String(value));
    return `${url.origin}${url.pathname}`;
  } catch {
    return 'invalid-url';
  }
}

async function initializeLogging() {
  try {
    const logDirectory = process.platform === 'win32' && process.env.LOCALAPPDATA
      ? resolve(process.env.LOCALAPPDATA, 'StreamTokLive', 'logs')
      : app.getPath('logs');
    await mkdir(logDirectory, { recursive: true });
    app.setAppLogsPath(logDirectory);
    logFile = resolve(logDirectory, 'main.log');
    try {
      const info = await stat(logFile);
      if (info.size >= maxLogSize) {
        await rename(logFile, resolve(logDirectory, 'main.previous.log')).catch(() => {});
      }
    } catch {}
    await logEvent('info', 'launcher-start', {
      version: app.getVersion(),
      packaged: app.isPackaged,
      platform: process.platform,
      web: sanitizedUrl(webUrl),
      api: sanitizedUrl(apiUrl),
    });
  } catch {
    logFile = null;
  }
}

async function logEvent(level, event, details = {}) {
  if (!logFile) return;
  const safeDetails = {};
  for (const [key, value] of Object.entries(details)) {
    if (value === undefined || value === null) continue;
    safeDetails[key] = typeof value === 'string' && /url|target|source/i.test(key)
      ? sanitizedUrl(value)
      : value;
  }
  const line = JSON.stringify({
    time: new Date().toISOString(),
    level,
    event,
    ...safeDetails,
  });
  await appendFile(logFile, `${line}\n`, 'utf8').catch(() => {});
}

function focusMainWindow() {
  const window = mainWindow && !mainWindow.isDestroyed() ? mainWindow : BrowserWindow.getAllWindows()[0];
  if (!window || window.isDestroyed()) return false;
  if (window.isMinimized()) window.restore();
  window.show();
  window.focus();
  window.flashFrame(false);
  return true;
}

const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    void logEvent('info', 'second-instance');
    focusMainWindow();
  });
}

function assertTrustedRenderer(event) {
  const source = event.senderFrame?.url || event.sender?.getURL?.() || '';
  if (!source || new URL(source).origin !== webOrigin) throw new Error('Untrusted renderer');
}

function validateExternalUrl(value) {
  const url = new URL(value);
  if (!['https:', 'http:'].includes(url.protocol)) throw new Error('Unsupported external protocol');
  if (!allowedExternalHosts.has(url.hostname)) throw new Error(`External host is not allowed: ${url.hostname}`);
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(url.hostname)) {
    throw new Error('HTTP is allowed only for localhost');
  }
  return url.toString();
}

function identityPath() {
  return resolve(app.getPath('userData'), 'device-identity-v1.json');
}

function requireSecureStorage() {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Secure operating-system key storage is unavailable. StreamTokLive will not save a plaintext device key.');
  }
}

function encryptedPrivateKey(privateKeyPem) {
  requireSecureStorage();
  return safeStorage.encryptString(privateKeyPem).toString('base64');
}

function decryptedPrivateKey(value) {
  requireSecureStorage();
  return safeStorage.decryptString(Buffer.from(value, 'base64'));
}

function validateStoredIdentity(value) {
  if (!value || typeof value !== 'object') throw new Error('Invalid identity');
  for (const key of ['publicId', 'publicKeyPem', 'privateKeyEncrypted']) {
    if (typeof value[key] !== 'string' || !value[key]) throw new Error(`Missing ${key}`);
  }
  if (!value.publicKeyPem.includes('BEGIN PUBLIC KEY')) throw new Error('Invalid device public key format');
  const privateKeyPem = decryptedPrivateKey(value.privateKeyEncrypted);
  if (!privateKeyPem.includes('BEGIN PRIVATE KEY')) throw new Error('Invalid encrypted device key format');
  return { ...value, privateKeyPem };
}

async function persistDeviceIdentity(value) {
  const stored = {
    version: 2,
    publicId: value.publicId,
    publicKeyPem: value.publicKeyPem,
    privateKeyEncrypted: value.privateKeyEncrypted,
    createdAt: value.createdAt,
  };
  const path = identityPath();
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(stored, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, path);
  await chmod(path, 0o600).catch(() => {});
}

async function createDeviceIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const value = {
    version: 2,
    publicId: randomUUID(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyEncrypted: encryptedPrivateKey(privateKeyPem),
    privateKeyPem,
    createdAt: new Date().toISOString(),
  };
  await persistDeviceIdentity(value);
  return value;
}

async function migrateLegacyIdentity(value) {
  if (!value || typeof value !== 'object') throw new Error('Invalid legacy identity');
  for (const key of ['publicId', 'publicKeyPem', 'privateKeyPem']) {
    if (typeof value[key] !== 'string' || !value[key]) throw new Error(`Missing ${key}`);
  }
  if (!value.publicKeyPem.includes('BEGIN PUBLIC KEY') || !value.privateKeyPem.includes('BEGIN PRIVATE KEY')) {
    throw new Error('Invalid legacy device key format');
  }
  const migrated = {
    version: 2,
    publicId: value.publicId,
    publicKeyPem: value.publicKeyPem,
    privateKeyEncrypted: encryptedPrivateKey(value.privateKeyPem),
    privateKeyPem: value.privateKeyPem,
    createdAt: typeof value.createdAt === 'string' ? value.createdAt : new Date().toISOString(),
  };
  await persistDeviceIdentity(migrated);
  return migrated;
}

async function deviceIdentity() {
  if (cachedIdentity) return cachedIdentity;
  try {
    const stored = JSON.parse(await readFile(identityPath(), 'utf8'));
    cachedIdentity = stored?.version === 2
      ? validateStoredIdentity(stored)
      : await migrateLegacyIdentity(stored);
  } catch {
    cachedIdentity = await createDeviceIdentity();
  }
  return cachedIdentity;
}

async function publicDeviceMetadata() {
  const identity = await deviceIdentity();
  return {
    publicId: identity.publicId,
    publicKeyPem: identity.publicKeyPem,
    displayName: `${hostname()} · StreamTokLive`,
    platform: `${platform()} ${release()}`,
    appVersion: app.getVersion(),
  };
}

ipcMain.handle('external:open', async (event, value) => {
  assertTrustedRenderer(event);
  const url = validateExternalUrl(String(value));
  await logEvent('info', 'external-open', { targetUrl: url });
  await shell.openExternal(url);
  return true;
});

ipcMain.handle('app:quit', async (event) => {
  assertTrustedRenderer(event);
  app.quit();
  return true;
});

ipcMain.handle('app:focus', async (event) => {
  assertTrustedRenderer(event);
  return focusMainWindow();
});

ipcMain.handle('access:notify', async (event, rawCode) => {
  assertTrustedRenderer(event);
  const code = String(rawCode);
  const copy = accessNoticeCopy.get(code);
  if (!copy) return false;

  const now = Date.now();
  focusMainWindow();
  if (now - lastAccessNoticeAt >= 3000 && Notification.isSupported()) {
    lastAccessNoticeAt = now;
    const notification = new Notification({
      title: copy[0],
      body: copy[1],
      icon: resolve(here, '../assets/icon.ico'),
      silent: false,
    });
    notification.on('click', focusMainWindow);
    notification.show();
  }
  return true;
});

ipcMain.handle('device:identity', async (event) => {
  assertTrustedRenderer(event);
  return publicDeviceMetadata();
});

ipcMain.handle('device:sign', async (event, rawPayload) => {
  assertTrustedRenderer(event);
  const payload = String(rawPayload);
  if (payload.length < 20 || payload.length > 4096) throw new Error('Invalid device proof payload');
  const prefix = payload.split('\n', 1)[0];
  if (!allowedProofPrefixes.has(prefix)) throw new Error('Unsupported device proof purpose');
  const identity = await deviceIdentity();
  return sign(null, Buffer.from(payload, 'utf8'), identity.privateKeyPem).toString('base64url');
});

async function showOfflinePage(window, reason = '') {
  if (!window || window.isDestroyed() || quitting) return;
  await logEvent('warn', 'offline-page', { reason });
  await window.loadFile(offlinePage, {
    query: {
      target: webUrl,
      reason: String(reason).slice(0, 180),
    },
  }).catch(async (error) => {
    await logEvent('error', 'offline-page-failed', { message: error?.message ?? String(error) });
  });
}

function installNavigationGuards(window) {
  window.webContents.on('before-input-event', (event, input) => {
    const key = String(input.key ?? '').toLowerCase();
    const devToolsShortcut = key === 'f12'
      || ((input.control || input.meta) && input.shift && key === 'i');

    if (allowDevTools && devToolsShortcut && input.type === 'keyDown') {
      event.preventDefault();
      if (window.webContents.isDevToolsOpened()) window.webContents.closeDevTools();
      else window.webContents.openDevTools({ mode: 'detach', activate: true });
      return;
    }

    if (allowDevTools) return;
    const blocked = devToolsShortcut
      || ((input.control || input.meta) && input.shift && ['j', 'c'].includes(key))
      || ((input.control || input.meta) && key === 'u');
    if (blocked) event.preventDefault();
  });

  window.webContents.on('devtools-opened', () => {
    if (!allowDevTools) window.webContents.closeDevTools();
  });
  window.webContents.on('context-menu', (event) => {
    if (!allowDevTools) event.preventDefault();
  });
  window.webContents.on('will-attach-webview', (event) => event.preventDefault());

  window.webContents.setWindowOpenHandler(({ url }) => {
    try {
      void shell.openExternal(validateExternalUrl(url));
    } catch {}
    return { action: 'deny' };
  });

  window.webContents.on('will-navigate', (event, target) => {
    try {
      if (new URL(target).origin !== webOrigin) event.preventDefault();
    } catch {
      event.preventDefault();
    }
  });

  window.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedUrl, isMainFrame) => {
    if (!isMainFrame || quitting || errorCode === -3) return;
    try {
      if (new URL(validatedUrl).origin !== webOrigin) return;
    } catch {
      return;
    }
    void logEvent('error', 'load-failed', {
      code: errorCode,
      description: errorDescription,
      targetUrl: validatedUrl,
    });
    void showOfflinePage(window, `Ошибка подключения: ${errorDescription} (${errorCode})`);
  });

  window.webContents.on('render-process-gone', (_event, details) => {
    void logEvent('error', 'renderer-gone', { reason: details.reason, exitCode: details.exitCode });
    void showOfflinePage(window, 'Интерфейс приложения был перезапущен.');
  });

  window.webContents.on('unresponsive', () => {
    void logEvent('warn', 'renderer-unresponsive');
  });
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1024,
    minHeight: 680,
    backgroundColor: '#080b12',
    title: 'StreamTokLive',
    icon: resolve(here, '../assets/icon.ico'),
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: resolve(here, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      devTools: allowDevTools,
    },
  });

  window.setMenu(null);
  installNavigationGuards(window);
  window.once('ready-to-show', () => window.show());
  window.on('closed', () => {
    if (mainWindow === window) mainWindow = null;
  });

  mainWindow = window;
  window.webContents.once('did-finish-load', () => {
    if (!window.isVisible()) window.show();
    if (openDevToolsOnStart && !window.webContents.isDevToolsOpened()) {
      window.webContents.openDevTools({ mode: 'detach', activate: true });
    }
  });
  void window.loadURL(webUrl).catch((error) => {
    void logEvent('error', 'initial-load-failed', { message: error?.message ?? String(error) });
    void showOfflinePage(window, 'Не удалось подключиться к серверу StreamTokLive.');
  });
  return window;
}

process.on('uncaughtException', (error) => {
  void logEvent('error', 'uncaught-exception', { message: error?.message ?? String(error) });
});
process.on('unhandledRejection', (error) => {
  void logEvent('error', 'unhandled-rejection', { message: error instanceof Error ? error.message : String(error) });
});

if (hasSingleInstanceLock) {
  app.whenReady().then(async () => {
    await initializeLogging();
    await electronSession.defaultSession.clearCache().catch(() => {});
    try {
      await deviceIdentity();
    } catch (error) {
      await logEvent('error', 'device-identity-failed', { message: error?.message ?? String(error) });
      throw error;
    }
    createWindow();
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
      else focusMainWindow();
    });
  }).catch(async (error) => {
    await logEvent('error', 'startup-failed', { message: error?.message ?? String(error) });
    app.quit();
  });
}

app.on('before-quit', () => {
  quitting = true;
  void logEvent('info', 'launcher-stop');
  void electronSession.defaultSession.clearCache().catch(() => {});
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
