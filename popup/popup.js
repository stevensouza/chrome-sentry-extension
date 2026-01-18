// Popup script for Chrome Sentry

document.addEventListener('DOMContentLoaded', init);

async function init() {
  // Set up event listeners
  document.getElementById('open-dashboard').addEventListener('click', openDashboard);

  // Load and display quick stats
  await loadQuickStats();
}

/**
 * Opens the full dashboard in a new tab
 */
function openDashboard() {
  chrome.tabs.create({
    url: chrome.runtime.getURL('dashboard/dashboard.html')
  });
}

/**
 * Loads extension data and displays quick statistics
 */
async function loadQuickStats() {
  try {
    // Get all installed extensions
    const extensions = await chrome.management.getAll();

    // Filter to only extensions (including this extension for full transparency)
    const extensionsOnly = extensions.filter(ext =>
      ext.type === 'extension'
    );

    // Calculate risk levels for each extension
    const riskCounts = {
      high: 0,
      medium: 0,
      low: 0
    };

    extensionsOnly.forEach(ext => {
      const riskScore = calculateQuickRiskScore(ext);

      if (riskScore > 50) {
        riskCounts.high++;
      } else if (riskScore > 20) {
        riskCounts.medium++;
      } else {
        riskCounts.low++;
      }
    });

    // Get combined scores from service worker (includes browser security)
    const scores = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'GET_COMBINED_SCORES' }, (response) => {
        if (response && !response.error) {
          resolve(response);
        } else {
          // Fallback if service worker doesn't respond
          resolve({
            extensionScore: 0,
            browserScore: 0,
            combinedScore: 0
          });
        }
      });
    });

    // Update UI
    updateUI({
      total: extensionsOnly.length,
      highRisk: riskCounts.high,
      mediumRisk: riskCounts.medium,
      lowRisk: riskCounts.low,
      combinedScore: scores.combinedScore,
      extensionScore: scores.extensionScore,
      browserScore: scores.browserScore
    });

  } catch (error) {
    console.error('Error loading extension stats:', error);
  }
}

/**
 * Comprehensive risk score calculation (synced with dashboard)
 */
function calculateQuickRiskScore(extension) {
  let score = 0;

  const permissions = extension.permissions || [];
  const hostPermissions = extension.hostPermissions || [];

  // Host permissions (most dangerous)
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

  // Cap at 100
  return Math.min(score, 100);
}

/**
 * Updates the popup UI with stats
 */
function updateUI(stats) {
  // Update counts
  document.getElementById('high-risk-count').textContent = stats.highRisk;
  document.getElementById('medium-risk-count').textContent = stats.mediumRisk;
  document.getElementById('low-risk-count').textContent = stats.lowRisk;
  document.getElementById('total-count').textContent = stats.total;

  // Update combined score
  const scoreElement = document.getElementById('overall-score');
  scoreElement.textContent = stats.combinedScore;

  // Update breakdown scores
  document.getElementById('extension-score').textContent = stats.extensionScore;
  const browserScoreEl = document.getElementById('browser-score');
  if (stats.browserSecurityEnabled) {
    browserScoreEl.textContent = stats.browserScore;
  } else {
    browserScoreEl.textContent = 'Not Scanned';
    browserScoreEl.style.fontSize = '11px';
  }

  // Update score indicator color based on combined score
  const indicatorElement = document.getElementById('score-indicator');
  indicatorElement.classList.remove('high-risk', 'medium-risk', 'low-risk');

  if (stats.combinedScore < 50) {
    indicatorElement.classList.add('high-risk');
  } else if (stats.combinedScore < 80) {
    indicatorElement.classList.add('medium-risk');
  } else {
    indicatorElement.classList.add('low-risk');
  }
}
