# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Chrome Sentry is a Manifest V3 Chrome extension that audits and scores browser extensions for security risks based on their permissions. It provides both a quick-view popup and a comprehensive dashboard for analyzing extension permissions, calculating risk scores, and tracking usage.

## Loading & Testing the Extension

### Installing in Chrome

1. Navigate to `chrome://extensions/`
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select this repository folder (containing `manifest.json`)

### Testing Changes

After modifying code:

1. Go to `chrome://extensions/`
2. Click the RELOAD button on "Chrome Sentry"
3. For dashboard changes: Open dashboard and press **Cmd+Shift+R** (Mac) or **Ctrl+Shift+R** (Windows) to hard refresh

**Note:** Chrome aggressively caches extension files. If changes don't appear after reload, see `RELOAD_INSTRUCTIONS.md` for advanced cache-clearing techniques.

## Architecture

### Manifest V3 Structure

This extension uses Chrome's Manifest V3 architecture:

- **Service Worker** (`background/service-worker.js`): Listens for extension install/enable/disable events and updates the toolbar badge with the current security score
- **Popup** (`popup/`): Quick-view UI showing security score and risk counts
- **Dashboard** (`dashboard/`): Full-featured analysis interface
- **Shared Data** (`data/permission-risks.json`): Centralized permission risk definitions

### Risk Scoring System

Risk scores (0-100) are calculated by summing weighted values:

1. **Host Permissions:**
   - `<all_urls>` or `*://*/*`: 30 points (HIGH)
   - `https://*/*` or `http://*/*`: 15 points each (MEDIUM)
   - Wildcard domains: 15 points (MEDIUM)
   - Specific domains: 0 points

2. **API Permissions:** See `data/permission-risks.json` for complete list
   - High-risk (15-25 pts): `webRequestBlocking`, `debugger`, `nativeMessaging`, `cookies`, `proxy`
   - Medium-risk (3-10 pts): `management`, `tabs`, `history`, `bookmarks`
   - Low/Safe (0 pts): `storage`, `alarms`, `notifications`

3. **Installation Source:**
   - Chrome Web Store: 0 points
   - Developer Mode: 15 points
   - Sideloaded: 20 points
   - Other/Unknown: 10 points

**Important:** Risk calculation logic is duplicated in three places and must stay synchronized:
- `popup/popup.js`: `calculateQuickRiskScore()` (lines 80-138)
- `dashboard/dashboard.js`: `calculateRiskScore()` (lines 607-710)
- `background/service-worker.js`: `calculateRiskScore()` (lines 7-64)

**When modifying risk scoring:** Update all three files to maintain consistency between popup, dashboard, and badge displays.

### Risk Score Display Logic

The extension uses an **inverse scoring system**:
- **Risk Score**: 0-100 (higher = more dangerous)
- **Security Score**: 100 - average risk (higher = safer)

**Risk Levels:**
- High: 51-100 points
- Medium: 21-50 points
- Low: 0-20 points

### HTTP/HTTPS Wildcard Combination

**Special handling for wildcard permissions:**

When an extension has BOTH `http://*/*` AND `https://*/*`:
- Each permission is worth 15 points individually (MEDIUM risk)
- Combined = 30 points total (HIGH risk)
- Dashboard displays them as a single combined row for clarity
- See `dashboard/dashboard.js` lines 616-640 and 967-1007

## Data Storage

### Extension Tags (User Data)

Users can tag extensions as "I use this", "Rarely use", or "Can remove". Tags are stored in `chrome.storage.sync` with fallback to `chrome.storage.local`:

```javascript
extensionTags = {
  "extension-id-123": {
    tag: "actively-used",
    taggedAt: 1234567890
  }
}
```

**Orphan Cleanup:** Tags for uninstalled extensions are automatically removed on dashboard load (see `cleanupOrphanedTags()` at line 437).

### Browser Security Audit State

Manual verification checkboxes and automated check preferences are stored in `chrome.storage.local`:

```javascript
{
  automatedChecksEnabled: true/false,
  manualSecurityChecks: {
    "check-id": {
      verified: true,
      verifiedAt: 1234567890  // Timestamp for "Last verified: X ago"
    }
  }
}
```

## Key Features & Code Locations

### 1. Dynamic Toolbar Badge

The extension icon badge shows the overall security score:
- **Green (80-100):** Low risk
- **Orange (50-79):** Medium risk
- **Red (0-49):** High risk

Updated automatically when extensions are installed/removed/enabled/disabled via `background/service-worker.js` listeners (lines 134-152).

### 2. Extension Details Modal

Clicking "Details" on any extension shows:
- Full risk score breakdown (which permissions contribute how many points)
- Sortable permissions table
- Security recommendations
- Usage tagging interface

**Important:** The modal uses **combined display** for HTTP+HTTPS wildcards (see lines 967-1007) - shows as single row but maintains accurate 30-point total.

### 3. Browser Security Audit (Phase 4)

**Automated Checks** (requires optional `privacy` permission):
- Reads Chrome privacy settings via `chrome.privacy` API
- Checks 7 settings: WebRTC IP handling, DNS prefetching, Safe Browsing, etc.
- Configuration in `SECURITY_SETTINGS_CONFIG` (lines 16-88)
- Error handling: Individual setting failures don't crash entire audit (R5)

**Manual Checklist:**
- 13 verification items for settings Chrome doesn't expose via API
- Includes critical security flags (Site Isolation, insecure origins whitelist)
- Privacy flags (Fingerprinting protection, IP protection, canvas protection)
- Stores verification timestamps for "Last verified: X ago" display
- Configuration in `MANUAL_SECURITY_CHECKS` (lines 91-262)

**Permission Handling:**
- Privacy permission is OPTIONAL (not required in manifest)
- User must explicitly grant via toggle in Browser Security tab
- Toggle state reflects ACTUAL Chrome permission (not just saved preference) - see line 1717

### 4. Export Functionality

Generate JSON audit reports with schema versioning for future compatibility:

```javascript
{
  schemaVersion: '2.0',
  generatedAt: ISO timestamp,
  summary: { counts by risk/status/usage },
  extensionTags: { user tagging data },
  extensions: [ { extension details } ]
}
```

## Common Development Tasks

### Adding a New Permission to Risk Data

1. Update `data/permission-risks.json` with weight, level, description, explanation
2. Update inline `PERMISSION_RISK_DATA` in `dashboard/dashboard.js` (lines 470-552)
3. Update risk calculation in all three files:
   - `popup/popup.js`: `calculateQuickRiskScore()`
   - `dashboard/dashboard.js`: `calculateRiskScore()`
   - `background/service-worker.js`: `calculateRiskScore()`

### Adding a New Browser Security Check

**For automated checks (via `chrome.privacy` API):**
1. Add to `SECURITY_SETTINGS_CONFIG` in `dashboard/dashboard.js` (line 16)
2. Define setting path (e.g., `'network.webRTCIPHandlingPolicy'`)
3. Specify recommended value and risk levels
4. Provide explanation and fix instructions

**For manual checks:**
1. Add to `MANUAL_SECURITY_CHECKS` in `dashboard/dashboard.js` (line 91)
2. Assign unique ID
3. Specify category (Critical, Important, Privacy)
4. Provide check instructions and fix guidance

### Modifying Risk Thresholds

Risk level thresholds are defined in multiple places:

1. **Dashboard:** `getRiskLevel()` at line 715
2. **Popup:** Inline at lines 48-54
3. **Badge Colors:** `background/service-worker.js` lines 98-104

**Consistency required:** All three must use same thresholds (currently 51 for high, 21 for medium).

## Privacy & Security Philosophy

Chrome Sentry is designed to be **read-only and privacy-focused**:

- **Never modifies** extensions (only reads via `chrome.management` API)
- **No external network requests** (100% local analysis)
- **No tracking or analytics**
- **Minimal permissions** (only `management` and `storage` required; `privacy` optional)
- **Open source** (all code visible and auditable)

When adding features, maintain this philosophy - never add capabilities that:
- Modify user's extensions or browser settings without explicit action
- Send data to external servers
- Track user behavior

## File Organization

```
chrome-sentry-extension/
├── manifest.json              # Manifest V3 configuration
├── background/
│   └── service-worker.js      # Background service worker (badge updates)
├── popup/
│   ├── popup.html             # Quick-view UI
│   ├── popup.css              # Popup styles
│   └── popup.js               # Popup logic + risk calculation
├── dashboard/
│   ├── dashboard.html         # Full dashboard UI
│   ├── dashboard.css          # Dashboard styles
│   └── dashboard.js           # Dashboard logic (~2200 lines)
├── data/
│   └── permission-risks.json  # Centralized permission risk definitions
├── icons/                     # Extension icons (16, 32, 48, 128px)
└── RELOAD_INSTRUCTIONS.md     # Cache-busting guide for development
```

## Testing Checklist

When making changes, verify:

- [ ] Popup displays correct security score and counts
- [ ] Dashboard loads all extensions and calculates scores correctly
- [ ] Extension details modal shows accurate permission breakdown
- [ ] HTTP+HTTPS wildcard combo displays as single row (30 pts total)
- [ ] Toolbar badge updates when extensions are installed/removed
- [ ] Export generates valid JSON with correct schema version
- [ ] User tags persist after browser restart (check sync/local fallback)
- [ ] Browser Security tab loads without errors (with and without privacy permission)

## Common Pitfalls

1. **Cache Issues:** Chrome caches extension files aggressively. Always hard-reload (`Cmd+Shift+R`) after changes. If issues persist, see `RELOAD_INSTRUCTIONS.md`.

2. **Risk Score Sync:** When modifying risk calculation, update ALL three files (popup, dashboard, service worker) to prevent inconsistent scores across UI surfaces.

3. **Permission Arrays:** Some extensions have `permissions` array, others have `hostPermissions`. Always check both arrays when calculating risk.

4. **Storage Fallback:** Always implement `chrome.storage.sync` with `chrome.storage.local` fallback for robustness (see `saveExtensionTags()` at line 390).

5. **Privacy Permission:** The `privacy` permission is OPTIONAL and must be requested at runtime. Never assume it's granted - always check actual Chrome state (line 1717).
