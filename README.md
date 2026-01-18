# Chrome Sentry

A Chrome extension that monitors your installed browser extensions for security risks. Analyze permissions, identify high-risk extensions, and protect your browser security.

## 🔒 Security & Privacy First

**Chrome Sentry is 100% read-only and privacy-focused:**
- ✅ Analyzes extensions locally - no data ever leaves your browser
- ✅ Cannot access web pages, browsing history, cookies, or passwords
- ✅ Does not modify, enable, or disable extensions
- ✅ No external servers, tracking, or analytics
- ✅ Open source - audit the code yourself
- ✅ Minimal permissions (only reads extension data and stores your tags)

**You remain in complete control.** Chrome Sentry only provides information - you decide what to do with it.

## Features

- **Risk Scoring**: Each extension gets a security risk score (0-100) based on its permissions
- **Permission Analysis**: Understand what each permission actually allows
- **Risk Categories**: Extensions are categorized as High, Medium, or Low risk
- **Source Verification**: Identify extensions not from the Chrome Web Store
- **Export Reports**: Generate JSON reports of your extension security audit

## Installation

### Developer Mode (Recommended for Testing)

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in the top right)
4. Click "Load unpacked"
5. Select the extension folder (the one containing `manifest.json`)

### From Chrome Web Store

*Coming soon*

## Usage

### Quick View (Popup)

Click the extension icon in your toolbar to see:
- Overall security score
- Count of high/medium/low risk extensions
- Total extensions installed

### Full Dashboard

Click "Open Full Dashboard" to access:
- Detailed security overview
- Complete extension list with risk scores
- Search and filter functionality
- Export audit report

## Risk Scoring

Extensions are scored based on:

### Permission Weights

| Permission | Risk Weight | Reason |
|------------|-------------|--------|
| `<all_urls>` | 30 | Full access to all websites |
| `webRequestBlocking` | 25 | Can modify network traffic |
| `debugger` | 25 | Can debug any tab |
| `nativeMessaging` | 20 | Can communicate with native apps |
| `webRequest` | 15 | Can observe network traffic |
| `cookies` | 15 | Can access cookies |
| `proxy` | 15 | Can route traffic |

### Installation Source Modifiers

| Source | Risk Modifier |
|--------|---------------|
| Chrome Web Store | +0 |
| Developer Mode | +15 |
| Sideloaded | +20 |
| Unknown | +10 |

### Risk Levels

- **Low Risk** (0-20): Minimal permissions, generally safe
- **Medium Risk** (21-50): Some concerning permissions
- **High Risk** (51-100): Significant security or privacy concerns

## Development

### Project Structure

```
chrome-sentry-extension/
├── manifest.json           # Extension configuration
├── popup/                  # Popup UI (quick view)
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── dashboard/              # Full dashboard
│   ├── dashboard.html
│   ├── dashboard.css
│   └── dashboard.js
├── lib/                    # Shared libraries
├── data/                   # Static data files
│   └── permission-risks.json
├── background/             # Service worker
│   └── service-worker.js
└── icons/                  # Extension icons
```

### Permissions Used & Privacy

Chrome Sentry is designed with **privacy and security first**. Here's exactly what permissions we use and why:

#### Required Permissions

**`management` - Read Extension Data**
- **Purpose:** Scan and analyze your installed extensions
- **What we do:** Read extension names, versions, permissions, and metadata
- **What we DON'T do:** Enable, disable, install, or uninstall extensions
- **Risk level:** MEDIUM (API can modify extensions, but we never use that capability)
- **Read-only:** ✅ Yes

**`storage` - Save User Preferences**
- **Purpose:** Remember your extension tags and dashboard preferences
- **What we do:** Store which extensions you've tagged as "I use this", "Can remove", etc.
- **What we DON'T do:** Store any browsing data or personal information
- **Risk level:** LOW
- **Read-only:** ❌ (writes user preferences locally)

#### What Chrome Sentry CANNOT Access

This extension is **completely isolated** from your browsing activity:

- ❌ **NO access to web pages** - Cannot read, modify, or see any website content
- ❌ **NO access to browsing history** - Cannot see which sites you visit
- ❌ **NO access to cookies** - Cannot read or modify any cookies
- ❌ **NO access to passwords** - Cannot see stored passwords
- ❌ **NO access to bookmarks** - Cannot read your bookmarks
- ❌ **NO network requests** - Does not phone home or send any data externally
- ❌ **NO tracking** - Zero analytics, no telemetry, no data collection

#### Privacy Guarantee

**100% Local & Private:**
- All analysis happens locally in your browser
- No data ever leaves your computer
- No external servers, APIs, or analytics
- No ads, no tracking, no monetization
- Your extension tags are stored locally (synced via Chrome's built-in sync if enabled)

**Open Source & Auditable:**
- All source code is visible in this repository
- You can audit exactly what the extension does
- No minified or obfuscated code
- No hidden functionality

**Practicing What We Preach:**
- Chrome Sentry has a LOW security risk score when scanning itself
- Uses minimal permissions (only what's absolutely necessary)
- No `<all_urls>` or host permissions
- No access to sensitive APIs (cookies, history, tabs, etc.)

#### How to Verify

You can verify Chrome Sentry's limited permissions:
1. Go to `chrome://extensions`
2. Find "Chrome Sentry"
3. Click "Details"
4. Check "Permissions" - you'll only see:
   - "Read and change data for extensions you manage"
   - "Store data on this device"

**Or scan Chrome Sentry with itself!** It will show exactly which permissions it uses and its risk score.

## Roadmap

- [x] Extension detail view with full permission breakdown
- [x] Manual usage tracking ("I use this" / "Can remove")
- [x] Browser settings security audit (7 automated + 13 manual checks)
- [ ] Cookie and tracking analysis
- [ ] Site permissions review
- [ ] Toggleable security alerts

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License - see LICENSE file for details
