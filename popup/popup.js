// Popup script for Extension Security Auditor

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

    // Filter to only extensions (not themes, apps, etc.)
    const extensionsOnly = extensions.filter(ext =>
      ext.type === 'extension' && ext.id !== chrome.runtime.id
    );

    // Calculate risk levels for each extension
    const riskCounts = {
      high: 0,
      medium: 0,
      low: 0
    };

    let totalRiskScore = 0;

    extensionsOnly.forEach(ext => {
      const riskScore = calculateQuickRiskScore(ext);
      totalRiskScore += riskScore;

      if (riskScore > 50) {
        riskCounts.high++;
      } else if (riskScore > 20) {
        riskCounts.medium++;
      } else {
        riskCounts.low++;
      }
    });

    // Calculate overall security score (inverse of risk)
    const avgRisk = extensionsOnly.length > 0
      ? totalRiskScore / extensionsOnly.length
      : 0;
    const securityScore = Math.round(100 - avgRisk);

    // Update UI
    updateUI({
      total: extensionsOnly.length,
      highRisk: riskCounts.high,
      mediumRisk: riskCounts.medium,
      lowRisk: riskCounts.low,
      securityScore: securityScore
    });

  } catch (error) {
    console.error('Error loading extension stats:', error);
  }
}

/**
 * Quick risk score calculation for popup summary
 * Full calculation is in lib/risk-scorer.js for dashboard
 */
function calculateQuickRiskScore(extension) {
  let score = 0;

  const permissions = extension.permissions || [];
  const hostPermissions = extension.hostPermissions || [];

  // High-risk permissions
  if (hostPermissions.includes('<all_urls>') ||
      hostPermissions.some(h => h.includes('*://*/*'))) {
    score += 30;
  }

  if (permissions.includes('webRequest')) score += 15;
  if (permissions.includes('webRequestBlocking')) score += 25;
  if (permissions.includes('debugger')) score += 25;
  if (permissions.includes('nativeMessaging')) score += 20;
  if (permissions.includes('cookies')) score += 15;
  if (permissions.includes('proxy')) score += 15;

  // Medium-risk permissions
  if (permissions.includes('management')) score += 10;
  if (permissions.includes('history')) score += 5;
  if (permissions.includes('tabs')) score += 5;

  // Installation source risk
  if (extension.installType === 'development') {
    score += 15;
  } else if (extension.installType === 'sideload') {
    score += 20;
  } else if (extension.installType !== 'normal') {
    score += 10;
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

  // Update overall score
  const scoreElement = document.getElementById('overall-score');
  scoreElement.textContent = stats.securityScore;

  // Update score indicator color
  const indicatorElement = document.getElementById('score-indicator');
  indicatorElement.classList.remove('high-risk', 'medium-risk', 'low-risk');

  if (stats.securityScore < 50) {
    indicatorElement.classList.add('high-risk');
  } else if (stats.securityScore < 80) {
    indicatorElement.classList.add('medium-risk');
  } else {
    indicatorElement.classList.add('low-risk');
  }
}
