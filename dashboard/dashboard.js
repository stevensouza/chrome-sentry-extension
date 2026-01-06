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
  populateReferenceTable();
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

  // Scan button with visual feedback
  document.getElementById('scan-btn').addEventListener('click', async (e) => {
    const btn = e.target;
    const originalText = btn.textContent;

    btn.textContent = 'Scanning...';
    btn.disabled = true;

    await loadExtensions();
    updateOverview();
    renderExtensions();

    // Show success feedback briefly
    btn.textContent = 'Scan Complete ✓';
    setTimeout(() => {
      btn.textContent = originalText;
      btn.disabled = false;
    }, 1500);
  });

  // Export button
  document.getElementById('export-btn').addEventListener('click', exportReport);

  // Risk stat cards - clickable to filter
  document.querySelectorAll('.risk-stat.clickable').forEach(stat => {
    stat.addEventListener('click', (e) => {
      const riskLevel = stat.dataset.risk;
      if (riskLevel) {
        filterByRisk(riskLevel);
      }
    });
  });

  // Modal close buttons
  document.getElementById('modal-close-btn').addEventListener('click', closeDetailsModal);
  document.getElementById('modal-close-footer-btn').addEventListener('click', closeDetailsModal);

  // Click outside modal to close
  document.getElementById('details-modal').addEventListener('click', (e) => {
    if (e.target.id === 'details-modal') {
      closeDetailsModal();
    }
  });

  // Event delegation for dynamically created Details buttons
  document.getElementById('extensions-list').addEventListener('click', (e) => {
    if (e.target.tagName === 'BUTTON' && e.target.textContent === 'Details') {
      const extensionItem = e.target.closest('.extension-item');
      if (extensionItem) {
        const extensionId = extensionItem.dataset.id;
        viewDetails(extensionId);
      }
    }
  });

  // Table sorting - event delegation for table headers
  document.getElementById('permissions-table').addEventListener('click', (e) => {
    const th = e.target.closest('th.sortable');
    if (th) {
      const column = th.dataset.sort;
      sortPermissionsTable(column);
    }
  });

  // Reference table sorting
  document.getElementById('reference-table').addEventListener('click', (e) => {
    const th = e.target.closest('th.sortable');
    if (th) {
      const column = th.dataset.sort;
      sortReferenceTable(column);
    }
  });

  // Summary stats - clickable to filter
  document.querySelectorAll('.summary-stat.clickable').forEach(stat => {
    stat.addEventListener('click', (e) => {
      const filter = stat.dataset.filter;
      filterByStatus(filter);
    });
  });
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

    // Filter and process extensions (including this extension for full transparency)
    allExtensions = extensions
      .filter(ext => ext.type === 'extension')
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
 * Permission risk data with weights and explanations
 */
const PERMISSION_RISK_DATA = {
  // High-risk permissions
  'webRequestBlocking': {
    weight: 25,
    level: 'high',
    description: 'Can intercept and modify all web traffic',
    recommendation: 'Only grant to trusted extensions like ad blockers'
  },
  'debugger': {
    weight: 25,
    level: 'high',
    description: 'Can debug and control other tabs and extensions',
    recommendation: 'Should only be used by development tools'
  },
  'nativeMessaging': {
    weight: 20,
    level: 'high',
    description: 'Can communicate with native applications on your computer',
    recommendation: 'Review carefully - can execute system-level operations'
  },
  'webRequest': {
    weight: 15,
    level: 'high',
    description: 'Can observe all network requests',
    recommendation: 'May collect browsing data'
  },
  'cookies': {
    weight: 15,
    level: 'high',
    description: 'Can read and modify cookies for all websites',
    recommendation: 'May access session tokens and login credentials'
  },
  'proxy': {
    weight: 15,
    level: 'high',
    description: 'Can control your network proxy settings',
    recommendation: 'Could route all traffic through third-party servers'
  },
  'privacy': {
    weight: 10,
    level: 'high',
    description: 'Can modify browser privacy settings',
    recommendation: 'Verify extension reputation before allowing'
  },

  // Medium-risk permissions
  'management': {
    weight: 10,
    level: 'medium',
    description: 'Can enable/disable other extensions',
    recommendation: 'Could be used to disable security extensions'
  },
  'tabs': {
    weight: 5,
    level: 'medium',
    description: 'Can see titles and URLs of open tabs',
    recommendation: 'May track browsing history'
  },
  'history': {
    weight: 5,
    level: 'medium',
    description: 'Can read and modify browsing history',
    recommendation: 'Full access to your browsing records'
  },
  'bookmarks': {
    weight: 3,
    level: 'medium',
    description: 'Can read and modify bookmarks',
    recommendation: 'Generally low risk but tracks your interests'
  },
  'downloads': {
    weight: 5,
    level: 'medium',
    description: 'Can manage downloads and access download history',
    recommendation: 'Could potentially inject malicious files'
  },
  'geolocation': {
    weight: 5,
    level: 'medium',
    description: 'Can access your physical location',
    recommendation: 'May track your whereabouts'
  }
};

/**
 * Host permission risk patterns
 */
const HOST_PERMISSION_PATTERNS = {
  allUrls: {
    patterns: ['<all_urls>', '*://*/*'],
    weight: 30,
    level: 'high',
    description: 'Full access to ALL websites you visit',
    recommendation: 'Very broad permission - only for extensions you fully trust'
  },
  wildcardDomain: {
    patterns: ['*'],
    weight: 15,
    level: 'medium',
    description: 'Access to multiple websites via wildcard patterns',
    recommendation: 'Review which domains are accessible'
  }
};

/**
 * Install type risk data
 */
const INSTALL_TYPE_RISK = {
  'development': {
    weight: 15,
    level: 'medium',
    description: 'Loaded from local files (Developer Mode)',
    recommendation: 'Ensure you trust the source code'
  },
  'sideload': {
    weight: 20,
    level: 'high',
    description: 'Installed from outside Chrome Web Store',
    recommendation: 'Not reviewed by Google - verify source carefully'
  },
  'other': {
    weight: 10,
    level: 'medium',
    description: 'Unknown installation source',
    recommendation: 'Investigate how this was installed'
  },
  'normal': {
    weight: 0,
    level: 'low',
    description: 'Installed from Chrome Web Store',
    recommendation: 'Reviewed by Google but still verify permissions'
  }
};

/**
 * Calculate risk score for an extension with detailed breakdown
 */
function calculateRiskScore(extension) {
  let score = 0;
  const breakdown = [];

  const permissions = extension.permissions || [];
  const hostPermissions = extension.hostPermissions || [];

  // Host permissions (most dangerous)
  if (hostPermissions.includes('<all_urls>') ||
      hostPermissions.some(h => h.includes('*://*/*'))) {
    const risk = HOST_PERMISSION_PATTERNS.allUrls;
    score += risk.weight;
    breakdown.push({
      type: 'host',
      name: 'All URLs Access',
      weight: risk.weight,
      level: risk.level,
      description: risk.description
    });
  } else if (hostPermissions.some(h => h.includes('*'))) {
    const risk = HOST_PERMISSION_PATTERNS.wildcardDomain;
    const wildcardCount = hostPermissions.filter(h => h.includes('*')).length;
    score += risk.weight;
    breakdown.push({
      type: 'host',
      name: `Wildcard Domains (${wildcardCount})`,
      weight: risk.weight,
      level: risk.level,
      description: risk.description
    });
  }

  // API Permissions
  permissions.forEach(perm => {
    const riskData = PERMISSION_RISK_DATA[perm];
    if (riskData) {
      score += riskData.weight;
      breakdown.push({
        type: 'permission',
        name: perm,
        weight: riskData.weight,
        level: riskData.level,
        description: riskData.description
      });
    }
  });

  // Installation source risk
  const installRisk = INSTALL_TYPE_RISK[extension.installType];
  if (installRisk && installRisk.weight > 0) {
    score += installRisk.weight;
    breakdown.push({
      type: 'install',
      name: getInstallTypeLabel(extension.installType),
      weight: installRisk.weight,
      level: installRisk.level,
      description: installRisk.description
    });
  }

  // Cap at 100
  const finalScore = Math.min(score, 100);

  // Store breakdown for later use
  extension.scoreBreakdown = breakdown;

  return finalScore;
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
        <button>Details</button>
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
 * View extension details in modal
 */
function viewDetails(extensionId) {
  const ext = allExtensions.find(e => e.id === extensionId);
  if (!ext) return;

  // Set current extension for table sorting
  currentExtensionId = extensionId;

  // Reset sort state
  currentSort = { column: 'risk', direction: 'desc' };

  const permissions = ext.permissions || [];
  const hostPermissions = ext.hostPermissions || [];

  // Populate basic info
  document.getElementById('modal-extension-name').textContent = ext.name;
  document.getElementById('detail-version').textContent = ext.version;
  document.getElementById('detail-status').textContent = ext.enabled ? 'Enabled' : 'Disabled';
  document.getElementById('detail-install-type').textContent = getInstallTypeLabel(ext.installType);
  document.getElementById('detail-id').textContent = ext.id;

  // Populate risk score
  document.getElementById('detail-score-number').textContent = ext.riskScore;
  const riskBadge = document.getElementById('detail-risk-badge');
  riskBadge.textContent = ext.riskLevel.toUpperCase();
  riskBadge.className = `risk-badge ${ext.riskLevel}`;

  // Update risk description
  const riskDescriptions = {
    high: 'This extension poses significant security risks. Review carefully and consider disabling if not essential.',
    medium: 'This extension has moderate security risks. Ensure you trust the developer.',
    low: 'This extension poses minimal security risks based on its permissions.'
  };
  document.getElementById('detail-risk-description').textContent = riskDescriptions[ext.riskLevel];

  // Color the score circle
  const scoreCircle = document.getElementById('detail-score-circle');
  scoreCircle.className = 'score-circle';
  scoreCircle.classList.add(`risk-${ext.riskLevel}`);

  // Populate score breakdown
  const scoreComponents = document.getElementById('score-components');
  if (ext.scoreBreakdown && ext.scoreBreakdown.length > 0) {
    scoreComponents.innerHTML = `
      <h4>Risk Factors (${ext.scoreBreakdown.length}):</h4>
      <div class="breakdown-list">
        ${ext.scoreBreakdown.map(item => `
          <div class="breakdown-item">
            <div class="breakdown-header">
              <span class="breakdown-name">${escapeHtml(item.name)}</span>
              <span class="breakdown-weight ${item.level}-risk">+${item.weight} pts</span>
            </div>
            <p class="breakdown-description">${escapeHtml(item.description)}</p>
          </div>
        `).join('')}
        ${ext.riskScore === 100 ? '<p class="breakdown-note"><strong>Note:</strong> Score capped at 100 (maximum risk)</p>' : ''}
      </div>
    `;
  } else {
    scoreComponents.innerHTML = '<p class="empty-text">No significant risk factors detected.</p>';
  }

  // Populate permissions table
  const permissionsData = [];

  // Add host permissions to table data
  hostPermissions.forEach(perm => {
    const isAllUrls = perm === '<all_urls>' || perm.includes('*://*/*');
    const riskLevel = isAllUrls ? 'high' : (perm.includes('*') ? 'medium' : 'low');
    const weight = isAllUrls ? 30 : (perm.includes('*') ? 15 : 0);
    const explanation = isAllUrls
      ? 'This extension can access and modify data on ALL websites'
      : perm.includes('*')
      ? 'This pattern matches multiple websites'
      : 'Specific website access';

    permissionsData.push({
      category: 'Host Permission',
      permission: perm,
      risk: riskLevel,
      points: weight,
      description: explanation
    });
  });

  // Add API permissions to table data
  permissions.forEach(perm => {
    const riskData = PERMISSION_RISK_DATA[perm];
    if (riskData) {
      permissionsData.push({
        category: 'API Permission',
        permission: perm,
        risk: riskData.level,
        points: riskData.weight,
        description: riskData.description
      });
    } else {
      permissionsData.push({
        category: 'API Permission',
        permission: perm,
        risk: 'low',
        points: 0,
        description: 'Standard permission with minimal risk'
      });
    }
  });

  // Add install type to table if it has risk
  const installRisk = INSTALL_TYPE_RISK[ext.installType];
  if (installRisk && installRisk.weight > 0) {
    permissionsData.push({
      category: 'Install Source',
      permission: getInstallTypeLabel(ext.installType),
      risk: installRisk.level,
      points: installRisk.weight,
      description: installRisk.description
    });
  }

  // Sort by risk level (high > medium > low), then by points (descending)
  const riskOrder = { high: 3, medium: 2, low: 1 };
  permissionsData.sort((a, b) => {
    const riskDiff = riskOrder[b.risk] - riskOrder[a.risk];
    if (riskDiff !== 0) return riskDiff;
    return b.points - a.points;
  });

  // Store sorted data for table sorting
  ext.permissionsTableData = permissionsData;

  // Render the table
  renderPermissionsTable(permissionsData);

  // Generate recommendations
  const recommendations = generateRecommendations(ext);
  const recommendationsList = document.getElementById('recommendations-list');
  const recommendationsSection = document.getElementById('recommendations-section');

  if (recommendations.length > 0) {
    recommendationsSection.style.display = 'block';
    recommendationsList.innerHTML = recommendations.map(rec => `
      <div class="recommendation-item ${rec.severity}">
        <div class="recommendation-icon">${rec.icon}</div>
        <div class="recommendation-content">
          <h4>${escapeHtml(rec.title)}</h4>
          <p>${escapeHtml(rec.message)}</p>
        </div>
      </div>
    `).join('');
  } else {
    recommendationsSection.style.display = 'none';
  }

  // Set up manage button - remove old listener first
  const manageBtn = document.getElementById('manage-extension-btn');
  const newManageBtn = manageBtn.cloneNode(true);
  manageBtn.parentNode.replaceChild(newManageBtn, manageBtn);

  newManageBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: `chrome://extensions/?id=${ext.id}` });
  });

  // Show modal
  document.getElementById('details-modal').classList.add('show');
}

/**
 * Close the details modal
 */
function closeDetailsModal() {
  document.getElementById('details-modal').classList.remove('show');
}

/**
 * Render permissions table
 */
function renderPermissionsTable(permissionsData) {
  const tbody = document.getElementById('permissions-table-body');

  if (permissionsData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-text">No permissions requested</td></tr>';
    return;
  }

  tbody.innerHTML = permissionsData.map(item => `
    <tr class="risk-${item.risk}">
      <td class="category-cell">${escapeHtml(item.category)}</td>
      <td class="permission-cell"><code>${escapeHtml(item.permission)}</code></td>
      <td class="risk-cell">
        <span class="risk-badge ${item.risk}">${item.risk.toUpperCase()}</span>
      </td>
      <td class="points-cell">
        <span class="points-value ${item.points > 0 ? 'has-points' : ''}">${item.points > 0 ? '+' : ''}${item.points}</span>
      </td>
      <td class="description-cell">${escapeHtml(item.description)}</td>
    </tr>
  `).join('');
}

/**
 * Sort permissions table
 */
let currentSort = { column: 'risk', direction: 'desc' };
let currentExtensionId = null;

function sortPermissionsTable(column) {
  if (!currentExtensionId) return;

  const currentExt = allExtensions.find(e => e.id === currentExtensionId);
  if (!currentExt || !currentExt.permissionsTableData) return;

  const data = [...currentExt.permissionsTableData];

  // Toggle direction if same column, otherwise default to ascending
  if (currentSort.column === column) {
    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
  } else {
    currentSort.column = column;
    currentSort.direction = column === 'risk' || column === 'points' ? 'desc' : 'asc';
  }

  // Sort the data
  data.sort((a, b) => {
    let aVal, bVal;

    switch (column) {
      case 'category':
        aVal = a.category;
        bVal = b.category;
        break;
      case 'permission':
        aVal = a.permission.toLowerCase();
        bVal = b.permission.toLowerCase();
        break;
      case 'risk':
        const riskOrder = { high: 3, medium: 2, low: 1 };
        aVal = riskOrder[a.risk];
        bVal = riskOrder[b.risk];
        break;
      case 'points':
        aVal = a.points;
        bVal = b.points;
        break;
      case 'description':
        aVal = a.description.toLowerCase();
        bVal = b.description.toLowerCase();
        break;
      default:
        return 0;
    }

    if (aVal < bVal) return currentSort.direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return currentSort.direction === 'asc' ? 1 : -1;
    return 0;
  });

  // Update sort icons
  document.querySelectorAll('.permissions-table th.sortable').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    th.classList.remove('sorted-asc', 'sorted-desc');
    icon.textContent = '';

    if (th.dataset.sort === column) {
      th.classList.add(`sorted-${currentSort.direction}`);
      icon.textContent = currentSort.direction === 'asc' ? '▲' : '▼';
    }
  });

  // Re-render table
  renderPermissionsTable(data);
}

/**
 * Generate security recommendations for an extension
 */
function generateRecommendations(ext) {
  const recommendations = [];
  const permissions = ext.permissions || [];
  const hostPermissions = ext.hostPermissions || [];

  // High-risk extension warning
  if (ext.riskLevel === 'high') {
    recommendations.push({
      severity: 'warning',
      icon: '⚠️',
      title: 'High Risk Extension',
      message: 'This extension has significant access to your browser and data. Only keep it enabled if absolutely necessary and from a trusted source.'
    });
  }

  // All URLs access
  if (hostPermissions.includes('<all_urls>') || hostPermissions.some(h => h.includes('*://*/*'))) {
    recommendations.push({
      severity: 'warning',
      icon: '🌐',
      title: 'Access to All Websites',
      message: 'This extension can read and modify data on every website you visit. Verify the extension developer is trustworthy.'
    });
  }

  // Dangerous permissions
  if (permissions.includes('debugger')) {
    recommendations.push({
      severity: 'critical',
      icon: '🔧',
      title: 'Debugger Permission',
      message: 'Can control other browser tabs and extensions. Should only be used by development tools you trust.'
    });
  }

  if (permissions.includes('nativeMessaging')) {
    recommendations.push({
      severity: 'warning',
      icon: '💻',
      title: 'Native Messaging',
      message: 'Can communicate with programs on your computer. Ensure you understand what native applications this connects to.'
    });
  }

  if (permissions.includes('webRequestBlocking')) {
    recommendations.push({
      severity: 'warning',
      icon: '🚦',
      title: 'Web Request Blocking',
      message: 'Can intercept and modify all your web traffic. Typically used by ad blockers - verify the extension purpose.'
    });
  }

  // Sideloaded or development
  if (ext.installType === 'sideload' || ext.installType === 'development') {
    recommendations.push({
      severity: 'info',
      icon: '📦',
      title: 'Unverified Source',
      message: `This extension was installed from ${getInstallTypeLabel(ext.installType)} and hasn't been reviewed by Google. Verify the source code if possible.`
    });
  }

  // Privacy-sensitive permissions
  const privacyPerms = ['history', 'cookies', 'tabs'];
  const hasPrivacyPerms = privacyPerms.filter(p => permissions.includes(p));
  if (hasPrivacyPerms.length > 0) {
    recommendations.push({
      severity: 'info',
      icon: '🔒',
      title: 'Privacy-Sensitive Permissions',
      message: `Has access to: ${hasPrivacyPerms.join(', ')}. Review the extension's privacy policy to understand how this data is used.`
    });
  }

  // Good - no major issues
  if (ext.riskLevel === 'low' && recommendations.length === 0) {
    recommendations.push({
      severity: 'success',
      icon: '✅',
      title: 'Looks Good',
      message: 'This extension has minimal permissions and appears safe based on our analysis.'
    });
  }

  return recommendations;
}

/**
 * Filter extensions by risk level and switch to extensions tab
 */
function filterByRisk(riskLevel) {
  // Switch to extensions tab
  switchTab('extensions');

  // Set the risk filter
  document.getElementById('risk-filter').value = riskLevel;

  // Clear other filters
  document.getElementById('status-filter').value = 'all';
  document.getElementById('search-input').value = '';

  // Apply filters
  filterExtensions();
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

/**
 * Populate reference table with all risk factors
 */
function populateReferenceTable() {
  const referenceData = [];

  // Add host permission patterns
  referenceData.push({
    points: HOST_PERMISSION_PATTERNS.allUrls.weight,
    permission: 'Access to All URLs (<all_urls>)',
    risk: HOST_PERMISSION_PATTERNS.allUrls.level,
    description: HOST_PERMISSION_PATTERNS.allUrls.description
  });

  referenceData.push({
    points: HOST_PERMISSION_PATTERNS.wildcardDomain.weight,
    permission: 'Wildcard Domain Access (*.example.com)',
    risk: HOST_PERMISSION_PATTERNS.wildcardDomain.level,
    description: HOST_PERMISSION_PATTERNS.wildcardDomain.description
  });

  // Add specific domain access (no risk)
  referenceData.push({
    points: 0,
    permission: 'Specific Domain Access (https://example.com)',
    risk: 'low',
    description: 'Access to specific websites only - minimal risk'
  });

  // Add all API permissions
  Object.entries(PERMISSION_RISK_DATA).forEach(([perm, data]) => {
    referenceData.push({
      points: data.weight,
      permission: perm,
      risk: data.level,
      description: data.description
    });
  });

  // Add low/no risk API permissions not in PERMISSION_RISK_DATA
  const lowRiskPerms = {
    'storage': 'Can store data locally in your browser',
    'alarms': 'Can schedule tasks to run at specific times',
    'notifications': 'Can display desktop notifications',
    'contextMenus': 'Can add items to right-click menus',
    'activeTab': 'Can access current tab when you click the extension',
    'scripting': 'Can run scripts on web pages (when combined with host permissions)',
    'declarativeContent': 'Can take actions based on page content without reading it',
    'identity': 'Can access your Google account info (with your permission)',
    'unlimitedStorage': 'Can store unlimited data locally'
  };

  Object.entries(lowRiskPerms).forEach(([perm, desc]) => {
    referenceData.push({
      points: 0,
      permission: perm,
      risk: 'low',
      description: desc
    });
  });

  // Add install types with risk
  Object.entries(INSTALL_TYPE_RISK).forEach(([type, data]) => {
    if (data.weight > 0) {
      referenceData.push({
        points: data.weight,
        permission: `Install Source: ${getInstallTypeLabel(type)}`,
        risk: data.level,
        description: data.description
      });
    }
  });

  // Add Chrome Web Store install (no risk)
  referenceData.push({
    points: 0,
    permission: 'Install Source: Chrome Web Store',
    risk: 'low',
    description: INSTALL_TYPE_RISK.normal.description
  });

  // Sort by points descending
  referenceData.sort((a, b) => b.points - a.points);

  // Store for sorting
  window.referenceTableData = referenceData;

  // Render table
  renderReferenceTable(referenceData);
}

/**
 * Render reference table
 */
function renderReferenceTable(data) {
  const tbody = document.getElementById('reference-table-body');

  tbody.innerHTML = data.map(item => `
    <tr class="risk-${item.risk}">
      <td class="points-cell">
        <span class="points-value has-points">+${item.points}</span>
      </td>
      <td class="permission-cell"><code>${escapeHtml(item.permission)}</code></td>
      <td class="risk-cell">
        <span class="risk-badge ${item.risk}">${item.risk.toUpperCase()}</span>
      </td>
      <td class="description-cell">${escapeHtml(item.description)}</td>
    </tr>
  `).join('');
}

/**
 * Sort reference table
 */
let referenceSort = { column: 'points', direction: 'desc' };

function sortReferenceTable(column) {
  if (!window.referenceTableData) return;

  const data = [...window.referenceTableData];

  // Toggle direction if same column
  if (referenceSort.column === column) {
    referenceSort.direction = referenceSort.direction === 'asc' ? 'desc' : 'asc';
  } else {
    referenceSort.column = column;
    referenceSort.direction = column === 'points' || column === 'risk' ? 'desc' : 'asc';
  }

  // Sort the data
  data.sort((a, b) => {
    let aVal, bVal;

    switch (column) {
      case 'points':
        aVal = a.points;
        bVal = b.points;
        break;
      case 'permission':
        aVal = a.permission.toLowerCase();
        bVal = b.permission.toLowerCase();
        break;
      case 'risk':
        const riskOrder = { high: 3, medium: 2, low: 1 };
        aVal = riskOrder[a.risk];
        bVal = riskOrder[b.risk];
        break;
      case 'description':
        aVal = a.description.toLowerCase();
        bVal = b.description.toLowerCase();
        break;
      default:
        return 0;
    }

    if (aVal < bVal) return referenceSort.direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return referenceSort.direction === 'asc' ? 1 : -1;
    return 0;
  });

  // Update sort icons
  document.querySelectorAll('#reference-table th.sortable').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    th.classList.remove('sorted-asc', 'sorted-desc');
    icon.textContent = '';

    if (th.dataset.sort === column) {
      th.classList.add(`sorted-${referenceSort.direction}`);
      icon.textContent = referenceSort.direction === 'asc' ? '▲' : '▼';
    }
  });

  // Re-render table
  renderReferenceTable(data);
}

/**
 * Filter extensions by status and switch to extensions tab
 */
function filterByStatus(status) {
  // Switch to extensions tab
  switchTab('extensions');

  // Set the status filter
  if (status === 'all') {
    document.getElementById('status-filter').value = 'all';
    document.getElementById('risk-filter').value = 'all';
  } else {
    document.getElementById('status-filter').value = status;
    document.getElementById('risk-filter').value = 'all';
  }

  // Clear search
  document.getElementById('search-input').value = '';

  // Apply filters
  filterExtensions();
}
