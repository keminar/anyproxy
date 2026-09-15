# Blurry icons in mstsc remote desktop

## Controlled-side (server) optimization

Enable RDP hardware GPU acceleration (Win10/11 Pro):

1. `Win+R`, type `gpedit.msc` (Home edition has no Group Policy, edit the registry instead)
2. Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Remote Session Environment
3. Set "Use hardware graphics adapter for all Remote Desktop Services sessions" → Enabled

Restart the remote controlled computer, then reconnect to test.
