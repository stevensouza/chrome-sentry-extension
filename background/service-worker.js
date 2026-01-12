// Background service worker for Chrome Sentry
// Manifest V3 requires service workers instead of background pages

// Browser security configuration (subset needed for scoring)
const BROWSER_SECURITY_POINTS = {
  automated: {
    'network.webRTCIPHandlingPolicy': { 'default': -10, 'default_public_interface_only': 0, 'disable_non_proxied_udp': 0 },
    'network.networkPredictionEnabled': { true: -5, false: 0 },
    'services.safeBrowsingEnabled': { false: -20, true: 0 },
    'services.alternateErrorPagesEnabled': { true: -5, false: 0 },
    'websites.thirdPartyCookiesAllowed': { true: -10, false: 0 },
    'websites.hyperlinkAuditingEnabled': { true: -5, false: 0 },
    'websites.referrersEnabled': { true: -5, false: 0 }
  },
  manual: {
    'enhanced-protection': { notEnabled: -15, enabled: 0 },
    'password-manager': { notEnabled: -10, enabled: 0 },
    'https-first': { notEnabled: -10, enabled: 0 },
    'privacy-sandbox': { enabled: -5, disabled: 0 },
    'do-not-track': { notEnabled: -3, enabled: 0 },
    'site-permissions': { allow: -15, ask: 0, block: 0 },
    'site-isolation': { disabled: -30, default: 0 },
    'insecure-origins-whitelist': { enabled: -20, disabled: 0 },
    'webtransport-dev-mode': { enabled: -15, disabled: 0 },
    'fingerprinting-protection': { disabled: -10, default: 0 },
    'ip-protection': { optedOut: -10, default: 0 },
    'canvas-protection-incognito': { disabled: -8, default: 0 },
    'unsafe-webgpu': { enabled: -10, disabled: 0 }
  }
};

/**
 * Calculate browser security score from stored audit data
 */
async function calculateBrowserSecurityScore() {
  try {
    const data = await chrome.storage.local.get(['browserSecurityAudit', 'automatedChecksEnabled', 'manualSecurityChecks']);

    if (!data.automatedChecksEnabled) {
      return 0; // No permission = unknown security = worst score
    }

    let totalPoints = 0;

    // Add automated checks points
    if (data.browserSecurityAudit && data.browserSecurityAudit.automatedChecks) {
      for (const [settingPath, check] of Object.entries(data.browserSecurityAudit.automatedChecks)) {
        if (!check.error && BROWSER_SECURITY_POINTS.automated[settingPath]) {
          const points = BROWSER_SECURITY_POINTS.automated[settingPath][check.value] ||
                         BROWSER_SECURITY_POINTS.automated[settingPath][String(check.value)] || 0;
          totalPoints += points;
        }
      }
    }

    // Add manual checks points (only verified ones)
    if (data.manualSecurityChecks) {
      for (const [checkId, checkState] of Object.entries(data.manualSecurityChecks)) {
        if (checkState.verified && BROWSER_SECURITY_POINTS.manual[checkId]) {
          // For manual checks, assume they verified it's in the safe state
          // If they verified it, they likely fixed it, so count as 0 points (secure)
          // If NOT verified, we don't count it (unknown state)
        }
      }
    }

    return Math.max(0, Math.min(100, 100 + totalPoints));
  } catch (error) {
    console.error('Error calculating browser security score:', error);
    return 0;
  }
}

/**
 * Calculate risk score for an extension
 */
function calculateRiskScore(extension) {
  let score = 0;

  const permissions = extension.permissions || [];
  const hostPermissions = extension.hostPermissions || [];

  // Host permissions
  if (hostPermissions.includes('<all_urls>') ||
      hostPermissions.some(h => h.includes('*://*/*'))) {
    score += 30;
  } else if (hostPermissions.some(h => h.includes('*'))) {
    score += 15;
  }

  // High-risk permissions
  const highRiskPerms = {
    'webRequestBlocking': 25,
    'debugger': 25,
    'nativeMessaging': 20,
    'webRequest': 15,
    'cookies': 15,
    'proxy': 15,
    'privacy': 10
  };

  // Medium-risk permissions
  const mediumRiskPerms = {
    'management': 10,
    'tabs': 5,
    'history': 5,
    'bookmarks': 3,
    'downloads': 5,
    'geolocation': 5
  };

  permissions.forEach(perm => {
    if (highRiskPerms[perm]) {
      score += highRiskPerms[perm];
    } else if (mediumRiskPerms[perm]) {
      score += mediumRiskPerms[perm];
    }
  });

  // Installation source risk
  switch (extension.installType) {
    case 'development':
      score += 15;
      break;
    case 'sideload':
      score += 20;
      break;
    case 'other':
      score += 10;
      break;
  }

  return Math.min(score, 100);
}

/**
 * Calculate overall security score and update badge
 * Combines extension security + browser security (50/50)
 */
async function updateSecurityIcon() {
  try {
    const extensions = await chrome.management.getAll();

    // Filter to extensions only (including this extension for full transparency)
    const extensionsOnly = extensions.filter(ext =>
      ext.type === 'extension'
    );

    // Calculate extension security score
    let extensionScore = 100; // Default if no extensions
    if (extensionsOnly.length > 0) {
      let totalRiskScore = 0;
      extensionsOnly.forEach(ext => {
        const riskScore = calculateRiskScore(ext);
        totalRiskScore += riskScore;
      });
      const avgRisk = totalRiskScore / extensionsOnly.length;
      extensionScore = Math.round(100 - avgRisk);
    }

    // Calculate browser security score
    const browserScore = await calculateBrowserSecurityScore();

    // Combined score logic:
    // - If browser security not enabled (score = 0), show extension score only
    // - If browser security enabled, use 50/50 weighted average
    const data = await chrome.storage.local.get(['automatedChecksEnabled']);
    const browserSecurityEnabled = data.automatedChecksEnabled || false;

    const combinedScore = browserSecurityEnabled
      ? Math.round((extensionScore + browserScore) / 2)
      : extensionScore;

    // Determine icon color based on combined score (5 levels - 20% increments)
    let iconColor;
    if (combinedScore >= 81) {
      iconColor = 'green';        // 81-100: Excellent (Very safe)
    } else if (combinedScore >= 61) {
      iconColor = 'light-green';  // 61-80: Good (Safe)
    } else if (combinedScore >= 41) {
      iconColor = 'yellow';       // 41-60: Fair (Moderate risk)
    } else if (combinedScore >= 21) {
      iconColor = 'orange';       // 21-40: Poor (Concerning)
    } else {
      iconColor = 'red';          // 0-20: Critical (Dangerous)
    }

    // Remove badge text (no more number display)
    chrome.action.setBadgeText({ text: '' });

    // Switch icon based on score
    chrome.action.setIcon({
      path: {
        16: `icons/icon16-${iconColor}.png`,
        32: `icons/icon32-${iconColor}.png`,
        48: `icons/icon48-${iconColor}.png`,
        128: `icons/icon128-${iconColor}.png`
      }
    });

    console.log(`Security scores - Extensions: ${extensionScore}, Browser: ${browserScore}, Combined: ${combinedScore} (${iconColor} icon)`);

  } catch (error) {
    console.error('Error updating security icon:', error);
  }
}

/**
 * Extension installation handler
 */
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('Chrome Sentry installed');
  } else if (details.reason === 'update') {
    console.log('Chrome Sentry updated to version', chrome.runtime.getManifest().version);
  }

  // Update icon on install/update
  updateSecurityIcon();
});

/**
 * Listen for extension changes and update icon
 */
chrome.management.onInstalled.addListener((info) => {
  console.log('New extension installed:', info.name);
  updateSecurityIcon();
});

chrome.management.onUninstalled.addListener((id) => {
  console.log('Extension uninstalled:', id);
  updateSecurityIcon();
});

chrome.management.onEnabled.addListener((info) => {
  console.log('Extension enabled:', info.name);
  updateSecurityIcon();
});

chrome.management.onDisabled.addListener((info) => {
  console.log('Extension disabled:', info.name);
  updateSecurityIcon();
});

/**
 * Listen for browser security audit changes and update badge
 */
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' &&
      (changes.browserSecurityAudit || changes.automatedChecksEnabled || changes.manualSecurityChecks)) {
    console.log('Browser security audit changed, updating badge');
    updateSecurityIcon();
  }
});

/**
 * Message handler for communication between popup/dashboard and service worker
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_EXTENSION_COUNT') {
    chrome.management.getAll((extensions) => {
      const count = extensions.filter(e =>
        e.type === 'extension' && e.id !== chrome.runtime.id
      ).length;
      sendResponse({ count });
    });
    return true; // Keep channel open for async response
  }

  if (message.type === 'UPDATE_ICON') {
    updateSecurityIcon();
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'GET_COMBINED_SCORES') {
    (async () => {
      try {
        const extensions = await chrome.management.getAll();
        const extensionsOnly = extensions.filter(ext => ext.type === 'extension');

        let extensionScore = 100;
        if (extensionsOnly.length > 0) {
          let totalRiskScore = 0;
          extensionsOnly.forEach(ext => {
            totalRiskScore += calculateRiskScore(ext);
          });
          extensionScore = Math.round(100 - (totalRiskScore / extensionsOnly.length));
        }

        const browserScore = await calculateBrowserSecurityScore();

        // Combined score logic: only include browser if enabled
        const data = await chrome.storage.local.get(['automatedChecksEnabled']);
        const browserSecurityEnabled = data.automatedChecksEnabled || false;

        const combinedScore = browserSecurityEnabled
          ? Math.round((extensionScore + browserScore) / 2)
          : extensionScore;

        sendResponse({ extensionScore, browserScore, combinedScore, browserSecurityEnabled });
      } catch (error) {
        console.error('Error getting combined scores:', error);
        sendResponse({ error: error.message });
      }
    })();
    return true; // Keep channel open for async response
  }
});

// Update icon when service worker starts
updateSecurityIcon();

console.log('Chrome Sentry service worker loaded');
