# Force Extension Reload Instructions

If changes aren't appearing, follow these steps:

## Method 1: Standard Reload
1. Go to `chrome://extensions/`
2. Enable "Developer mode" (top right toggle)
3. Click the RELOAD button on "Chrome Sentry"
4. Open dashboard and do **Cmd+Shift+R** (Mac) or **Ctrl+Shift+R** (Windows)

## Method 2: Complete Reinstall
1. Go to `chrome://extensions/`
2. Click "Remove" on "Chrome Sentry"
3. Close ALL Chrome windows
4. Reopen Chrome
5. Go to `chrome://extensions/`
6. Click "Load unpacked"
7. Select this folder: `/Users/stevesouza/my/data/gitrepo/chrome-sentry-extension`
8. Click the extension icon → "View Full Dashboard"

## Method 3: Clear Chrome Cache
1. Open Chrome settings
2. Search for "Clear browsing data"
3. Select "Cached images and files"
4. Click "Clear data"
5. Reload extension (Method 1)

## Verify Changes Loaded

Open dashboard → Press F12 → Console → Run:
```javascript
console.log('viewDetails:', typeof window.viewDetails);
console.log('Modal:', !!document.getElementById('details-modal'));
```

Should see:
- `viewDetails: "function"`
- `Modal: true`

If you see `undefined` or `false`, Chrome is still using old cached files!
