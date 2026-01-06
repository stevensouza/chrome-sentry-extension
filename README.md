# Chrome Sentry

A Chrome extension that monitors your installed browser extensions for security risks. Analyze permissions, identify high-risk extensions, and protect your browser security.

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

### Permissions Used

This extension only requests minimal permissions:

- `management` - Required to inspect other extensions
- `storage` - Store user preferences

**Note:** This extension practices what it preaches - no `<all_urls>` or host permissions.

## Roadmap

- [ ] Extension detail view with full permission breakdown
- [ ] Manual usage tracking ("I use this" / "Can remove")
- [ ] Browser settings security audit
- [ ] Cookie and tracking analysis
- [ ] Site permissions review
- [ ] Toggleable security alerts

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License - see LICENSE file for details
