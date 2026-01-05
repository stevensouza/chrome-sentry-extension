// Dashboard script for Extension Security Auditor

// State
let allExtensions = [];
let filteredExtensions = [];

// Initialize dashboard
document.addEventListener('DOMContentLoaded', init);

async function init() {
  setupEventListeners();
  await loadExtensions();
  updateOverview();
  renderExtensions();
}

/**
 * Set up all event listeners
 */
function setupEventListeners() {
  // Tab navigation
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const tabId = item.dataset.tab;
      switchTab(tabId);
    });
  });

  // Search
  document.getElementById('search-input').addEventListener('input', (e) => {
    filterExtensions();
  });

  // Filters
  document.getElementById('risk-filter').addEventListener('change', filterExtensions);
  document.getElementById('status-filter').addEventListener('change', filterExtensions);

  // Scan button
  document.getElementById('scan-btn').addEventListener('click', async () => {
    await loadExtensions();
    updateOverview();
    renderExtensions();
  });

  // Export button
  document.getElementById('export-btn').addEventListener('click', exportReport);
}

/**
 * Switch between tabs
 */
function switchTab(tabId) {
  // Update nav items
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.tab === tabId);
  });

  // Update tab content
  document.querySelectorAll('.tab-content').forEach(tab => {
    tab.classList.toggle('active', tab.id === `${tabId}-tab`);
  });
}

/**
 * Load all extensions using chrome.management API
 */
async function loadExtensions() {
  try {
    const extensions = await chrome.management.getAll();

    // Filter and process extensions
    allExtensions = extensions
      .filter(ext => ext.type === 'extension' && ext.id !== chrome.runtime.id)
      .map(ext => ({
        ...ext,
        riskScore: calculateRiskScore(ext),
        riskLevel: getRiskLevel(calculateRiskScore(ext))
      }));

    // Sort by risk score (highest first)
    allExtensions.sort((a, b) => b.riskScore - a.riskScore);
    filteredExtensions = [...allExtensions];

  } catch (error) {
    console.error('Error loading extensions:', error);
  }
}

/**
 * Calculate risk score for an extension
 */
function calculateRiskScore(extension) {
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
 * Get risk level from score
 */
function getRiskLevel(score) {
  if (score > 50) return 'high';
  if (score > 20) return 'medium';
  return 'low';
}

/**
 * Update overview tab with stats
 */
function updateOverview() {
  const total = allExtensions.length;
  const enabled = allExtensions.filter(e => e.enabled).length;
  const disabled = total - enabled;

  const riskCounts = {
    high: allExtensions.filter(e => e.riskLevel === 'high').length,
    medium: allExtensions.filter(e => e.riskLevel === 'medium').length,
    low: allExtensions.filter(e => e.riskLevel === 'low').length
  };

  // Calculate overall score
  const avgRisk = total > 0
    ? allExtensions.reduce((sum, e) => sum + e.riskScore, 0) / total
    : 0;
  const overallScore = Math.round(100 - avgRisk);

  // Update UI
  document.getElementById('overall-score').textContent = overallScore;
  document.getElementById('high-count').textContent = riskCounts.high;
  document.getElementById('medium-count').textContent = riskCounts.medium;
  document.getElementById('low-count').textContent = riskCounts.low;
  document.getElementById('total-extensions').textContent = total;
  document.getElementById('enabled-extensions').textContent = enabled;
  document.getElementById('disabled-extensions').textContent = disabled;

  // Update score bar
  const scoreBar = document.getElementById('score-bar-fill');
  scoreBar.style.width = `${overallScore}%`;
  scoreBar.classList.remove('high-risk', 'medium-risk', 'low-risk');

  if (overallScore < 50) {
    scoreBar.classList.add('high-risk');
  } else if (overallScore < 80) {
    scoreBar.classList.add('medium-risk');
  } else {
    scoreBar.classList.add('low-risk');
  }

  // Update description
  const description = document.getElementById('score-description');
  if (overallScore >= 80) {
    description.textContent = 'Your extensions have minimal security risks.';
  } else if (overallScore >= 50) {
    description.textContent = 'Some extensions may pose moderate security risks.';
  } else {
    description.textContent = 'Multiple high-risk extensions detected. Review recommended.';
  }
}

/**
 * Filter extensions based on search and filter criteria
 */
function filterExtensions() {
  const searchTerm = document.getElementById('search-input').value.toLowerCase();
  const riskFilter = document.getElementById('risk-filter').value;
  const statusFilter = document.getElementById('status-filter').value;

  filteredExtensions = allExtensions.filter(ext => {
    // Search filter
    const matchesSearch = ext.name.toLowerCase().includes(searchTerm) ||
      (ext.description || '').toLowerCase().includes(searchTerm);

    // Risk filter
    const matchesRisk = riskFilter === 'all' || ext.riskLevel === riskFilter;

    // Status filter
    const matchesStatus = statusFilter === 'all' ||
      (statusFilter === 'enabled' && ext.enabled) ||
      (statusFilter === 'disabled' && !ext.enabled);

    return matchesSearch && matchesRisk && matchesStatus;
  });

  renderExtensions();
}

/**
 * Render extension list
 */
function renderExtensions() {
  const container = document.getElementById('extensions-list');

  if (filteredExtensions.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No extensions found</h3>
        <p>Try adjusting your search or filters</p>
      </div>
    `;
    return;
  }

  container.innerHTML = filteredExtensions.map(ext => `
    <div class="extension-item" data-id="${ext.id}">
      <div class="extension-icon">
        ${ext.icons && ext.icons.length > 0
          ? `<img src="${ext.icons[ext.icons.length - 1].url}" alt="${ext.name}">`
          : '<span>?</span>'
        }
      </div>
      <div class="extension-info">
        <div class="extension-name">${escapeHtml(ext.name)}</div>
        <div class="extension-meta">
          v${ext.version} &middot;
          ${ext.enabled ? 'Enabled' : 'Disabled'} &middot;
          ${getInstallTypeLabel(ext.installType)}
        </div>
      </div>
      <div class="extension-risk">
        <span class="risk-badge ${ext.riskLevel}">${ext.riskLevel.toUpperCase()}</span>
        <span class="risk-score">${ext.riskScore}/100</span>
      </div>
      <div class="extension-actions">
        <button onclick="viewDetails('${ext.id}')">Details</button>
      </div>
    </div>
  `).join('');
}

/**
 * Get human-readable install type label
 */
function getInstallTypeLabel(installType) {
  const labels = {
    'normal': 'Chrome Web Store',
    'development': 'Developer Mode',
    'sideload': 'Sideloaded',
    'admin': 'Enterprise Policy',
    'other': 'Unknown Source'
  };
  return labels[installType] || installType;
}

/**
 * View extension details (placeholder - will be expanded in Phase 3)
 */
function viewDetails(extensionId) {
  const ext = allExtensions.find(e => e.id === extensionId);
  if (!ext) return;

  // For now, show an alert with basic info
  // This will be replaced with a proper detail view in Phase 3
  const permissions = ext.permissions || [];
  const hostPermissions = ext.hostPermissions || [];

  alert(`Extension: ${ext.name}
Version: ${ext.version}
Risk Score: ${ext.riskScore}/100
Risk Level: ${ext.riskLevel.toUpperCase()}

Permissions:
${permissions.length > 0 ? permissions.join('\n') : 'None'}

Host Permissions:
${hostPermissions.length > 0 ? hostPermissions.join('\n') : 'None'}

Install Type: ${getInstallTypeLabel(ext.installType)}`);
}

/**
 * Export audit report
 */
function exportReport() {
  const report = {
    generatedAt: new Date().toISOString(),
    summary: {
      totalExtensions: allExtensions.length,
      enabledExtensions: allExtensions.filter(e => e.enabled).length,
      highRisk: allExtensions.filter(e => e.riskLevel === 'high').length,
      mediumRisk: allExtensions.filter(e => e.riskLevel === 'medium').length,
      lowRisk: allExtensions.filter(e => e.riskLevel === 'low').length
    },
    extensions: allExtensions.map(ext => ({
      name: ext.name,
      id: ext.id,
      version: ext.version,
      enabled: ext.enabled,
      installType: ext.installType,
      riskScore: ext.riskScore,
      riskLevel: ext.riskLevel,
      permissions: ext.permissions || [],
      hostPermissions: ext.hostPermissions || []
    }))
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `extension-security-audit-${new Date().toISOString().split('T')[0]}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Make viewDetails available globally for onclick handlers
window.viewDetails = viewDetails;
