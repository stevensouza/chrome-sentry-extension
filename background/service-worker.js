// Background service worker for Extension Security Auditor
// Manifest V3 requires service workers instead of background pages

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
 * Uses Chrome's native badge API like tab-manager extension
 */
async function updateSecurityIcon() {
  try {
    const extensions = await chrome.management.getAll();

    // Filter to extensions only (including this extension for full transparency)
    const extensionsOnly = extensions.filter(ext =>
      ext.type === 'extension'
    );

    if (extensionsOnly.length === 0) {
      chrome.action.setBadgeText({ text: '100' });
      chrome.action.setBadgeBackgroundColor({ color: '#16a34a' }); // Green
      return;
    }

    // Calculate risk scores
    let totalRiskScore = 0;
    extensionsOnly.forEach(ext => {
      const riskScore = calculateRiskScore(ext);
      totalRiskScore += riskScore;
    });

    // Calculate overall security score (100 - average risk)
    const avgRisk = totalRiskScore / extensionsOnly.length;
    const securityScore = Math.round(100 - avgRisk);

    // Determine badge color based on risk level
    let badgeColor;
    if (securityScore >= 80) {
      badgeColor = '#16a34a'; // Green - low risk
    } else if (securityScore >= 50) {
      badgeColor = '#ea580c'; // Orange - medium risk
    } else {
      badgeColor = '#dc2626'; // Red - high risk
    }

    // Update badge using Chrome's native API
    chrome.action.setBadgeText({ text: String(securityScore) });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });

    console.log(`Security score updated: ${securityScore} (badge color: ${badgeColor})`);

  } catch (error) {
    console.error('Error updating security icon:', error);
  }
}

/**
 * Extension installation handler
 */
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('Extension Security Auditor installed');
  } else if (details.reason === 'update') {
    console.log('Extension Security Auditor updated to version', chrome.runtime.getManifest().version);
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
});

// Update icon when service worker starts
updateSecurityIcon();

console.log('Extension Security Auditor service worker loaded');
