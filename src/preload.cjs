const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('launcherTok', {
  isElectron: true,
  platform: process.platform,
  version: process.versions.electron,
  openExternal: (url) => ipcRenderer.invoke('external:open', url),
  focus: () => ipcRenderer.invoke('app:focus'),
  quit: () => ipcRenderer.invoke('app:quit'),
  notifyAccessChange: (code) => ipcRenderer.invoke('access:notify', code),
  getDeviceIdentity: () => ipcRenderer.invoke('device:identity'),
  signDevicePayload: (payload) => ipcRenderer.invoke('device:sign', payload),
});
