// Dashboard script for Chrome Sentry

// State
let allExtensions = [];
let filteredExtensions = [];
let extensionTags = {}; // { extensionId: { tag: string, taggedAt: timestamp } }
let browserSecurityAudit = {
  automatedChecks: {},
  manualChecks: {},
  lastChecked: null,
  score: 0,
  permissionGranted: false
};

// Configuration for Browser Security automated checks
const SECURITY_SETTINGS_CONFIG = {
  'network.webRTCIPHandlingPolicy': {
    name: 'WebRTC IP Handling',
    recommendedValue: 'default_public_interface_only',
    risk: {
      'default': { level: 'warning', points: -10, label: 'May Leak IP' },
      'default_public_interface_only': { level: 'secure', points: 0, label: 'Protected' },
      'disable_non_proxied_udp': { level: 'secure', points: 0, label: 'Protected' }
    },
    explanation: 'WebRTC can leak your real IP address even when using a VPN. Restricting WebRTC IP handling prevents this privacy leak.',
    howToFix: 'Go to chrome://settings/privacy → Security → Use secure connections → Enable "Use secure DNS"'
  },
  'network.networkPredictionEnabled': {
    name: 'Network Prediction (DNS Prefetching)',
    recommendedValue: false,
    risk: {
      true: { level: 'warning', points: -5, label: 'Privacy Risk' },
      false: { level: 'secure', points: 0, label: 'Disabled' }
    },
    explanation: 'Network prediction pre-loads resources for faster browsing, but reveals your browsing intent to DNS servers before you click links.',
    howToFix: 'Go to chrome://settings/performance → Disable "Preload pages for faster browsing and searching"'
  },
  'services.safeBrowsingEnabled': {
    name: 'Safe Browsing',
    recommendedValue: true,
    risk: {
      false: { level: 'risky', points: -20, label: 'DISABLED - Critical Risk' },
      true: { level: 'secure', points: 0, label: 'Enabled' }
    },
    explanation: 'Safe Browsing protects you from malicious websites, phishing, and dangerous downloads. Disabling this is extremely risky.',
    howToFix: 'Go to chrome://settings/security → Enable "Safe Browsing" (at minimum Standard protection)'
  },
  'services.alternateErrorPagesEnabled': {
    name: 'Alternate Error Pages',
    recommendedValue: false,
    risk: {
      true: { level: 'warning', points: -5, label: 'Sends URLs to Google' },
      false: { level: 'secure', points: 0, label: 'Disabled' }
    },
    explanation: 'When enabled, Chrome sends URLs of pages that fail to load to Google to suggest alternatives. This reveals some browsing data.',
    howToFix: 'Go to chrome://settings/privacy → Disable "Show suggestions for similar pages when a page can\'t be found"'
  },
  'websites.thirdPartyCookiesAllowed': {
    name: 'Third-Party Cookies',
    recommendedValue: false,
    risk: {
      true: { level: 'warning', points: -10, label: 'Tracking Enabled' },
      false: { level: 'secure', points: 0, label: 'Blocked' }
    },
    explanation: 'Third-party cookies enable cross-site tracking by advertisers and analytics companies. Blocking them improves privacy.',
    howToFix: 'Go to chrome://settings/cookies → Select "Block third-party cookies"'
  },
  'websites.hyperlinkAuditingEnabled': {
    name: 'Hyperlink Auditing',
    recommendedValue: false,
    risk: {
      true: { level: 'warning', points: -5, label: 'Click Tracking' },
      false: { level: 'secure', points: 0, label: 'Disabled' }
    },
    explanation: 'Hyperlink auditing allows websites to track which links you click via ping requests, revealing your browsing behavior.',
    howToFix: 'Cannot be changed via UI - requires Chrome policy or enterprise management'
  },
  'websites.referrersEnabled': {
    name: 'Referrer Headers',
    recommendedValue: false,
    risk: {
      true: { level: 'warning', points: -5, label: 'Privacy Leak' },
      false: { level: 'secure', points: 0, label: 'Limited' }
    },
    explanation: 'Referrer headers tell websites where you came from, potentially leaking private URLs and browsing patterns.',
    howToFix: 'Cannot be fully disabled via UI - Chrome uses reduced referrers by default'
  }
};

// Configuration for Browser Security manual checks
const MANUAL_SECURITY_CHECKS = [
  {
    id: 'enhanced-protection',
    name: 'Enhanced Safe Browsing Protection',
    category: 'Critical',
    recommended: true,
    risk: {
      notEnabled: { level: 'risky', points: -15, label: 'Not Enabled' },
      enabled: { level: 'secure', points: 0, label: 'Enabled' }
    },
    explanation: 'Enhanced Protection provides the strongest defense against dangerous sites and downloads, with proactive detection and warnings.',
    howToCheck: 'chrome://settings/security → Check if "Enhanced protection" is selected',
    howToFix: 'chrome://settings/security → Select "Enhanced protection"'
  },
  {
    id: 'password-manager',
    name: 'Password Manager with Breach Detection',
    category: 'Critical',
    recommended: true,
    risk: {
      notEnabled: { level: 'risky', points: -10, label: 'Weak Passwords Risk' },
      enabled: { level: 'secure', points: 0, label: 'Enabled' }
    },
    explanation: 'Chrome\'s password manager generates strong passwords and alerts you if your passwords are found in data breaches.',
    howToCheck: 'chrome://settings/passwords → Check if "Offer to save passwords" is ON',
    howToFix: 'chrome://settings/passwords → Enable "Offer to save passwords" and run "Check passwords"'
  },
  {
    id: 'https-first',
    name: 'HTTPS-First Mode',
    category: 'Important',
    recommended: true,
    risk: {
      notEnabled: { level: 'warning', points: -10, label: 'Unencrypted Connections' },
      enabled: { level: 'secure', points: 0, label: 'Enabled' }
    },
    explanation: 'HTTPS-First mode upgrades all connections to encrypted HTTPS, protecting your data from eavesdropping and tampering.',
    howToCheck: 'chrome://settings/security → Check if "Always use secure connections" is ON',
    howToFix: 'chrome://settings/security → Enable "Always use secure connections"'
  },
  {
    id: 'privacy-sandbox',
    name: 'Privacy Sandbox Ad Topics',
    category: 'Privacy',
    recommended: false,
    risk: {
      enabled: { level: 'warning', points: -5, label: 'Interest Tracking' },
      disabled: { level: 'secure', points: 0, label: 'Disabled' }
    },
    explanation: 'Privacy Sandbox builds an interest profile based on your browsing. While more private than cookies, disabling stops interest tracking entirely.',
    howToCheck: 'chrome://settings/adPrivacy → Check Ad topics, Site-suggested ads, and Ad measurement settings',
    howToFix: 'chrome://settings/adPrivacy → Disable all three options'
  },
  {
    id: 'do-not-track',
    name: 'Do Not Track Header',
    category: 'Privacy',
    recommended: true,
    risk: {
      notEnabled: { level: 'info', points: -3, label: 'Not Sent' },
      enabled: { level: 'secure', points: 0, label: 'Enabled' }
    },
    explanation: 'Do Not Track is a signal to websites requesting they don\'t track you. Not all sites honor it, but it doesn\'t hurt to enable.',
    howToCheck: 'chrome://settings/security → Check if "Send a \'Do Not Track\' request" is ON',
    howToFix: 'chrome://settings/security → Enable "Send a \'Do Not Track\' request with your browsing traffic"'
  },
  {
    id: 'site-permissions',
    name: 'Default Site Permissions (Location, Camera, Mic)',
    category: 'Important',
    recommended: 'Ask',
    risk: {
      allow: { level: 'risky', points: -15, label: 'Always Allow' },
      ask: { level: 'secure', points: 0, label: 'Ask First' },
      block: { level: 'secure', points: 0, label: 'Blocked' }
    },
    explanation: 'Websites shouldn\'t have automatic access to sensitive permissions like location, camera, or microphone. Always require explicit user consent.',
    howToCheck: 'chrome://settings/content → Check Location, Camera, and Microphone are set to "Ask"',
    howToFix: 'chrome://settings/content → Set Location, Camera, and Microphone to "Ask before accessing" or "Don\'t allow sites to access"'
  },
  {
    id: 'site-isolation',
    name: 'Site Isolation (Spectre Protection)',
    category: 'Critical',
    recommended: 'Default',
    risk: {
      disabled: { level: 'risky', points: -30, label: 'DISABLED - Critical Vulnerability' },
      default: { level: 'secure', points: 0, label: 'Enabled' }
    },
    explanation: 'Site isolation protects against Spectre CPU vulnerabilities by isolating websites in separate processes. Disabling this is extremely dangerous and exposes you to severe security risks.',
    howToCheck: 'chrome://flags/#site-isolation-trial-opt-out → Should be "Default" (NOT "Disabled")',
    howToFix: 'chrome://flags/#site-isolation-trial-opt-out → Set to "Default" and restart Chrome'
  },
  {
    id: 'insecure-origins-whitelist',
    name: 'Insecure Origins Treated as Secure',
    category: 'Critical',
    recommended: 'Disabled/Empty',
    risk: {
      enabled: { level: 'risky', points: -20, label: 'Security Bypass Active' },
      disabled: { level: 'secure', points: 0, label: 'Disabled' }
    },
    explanation: 'This flag allows bypassing HTTPS requirements for specific sites, treating insecure HTTP connections as secure. Any site in this list is vulnerable to eavesdropping and tampering.',
    howToCheck: 'chrome://flags/#unsafely-treat-insecure-origin-as-secure → Should be "Disabled" or empty',
    howToFix: 'chrome://flags/#unsafely-treat-insecure-origin-as-secure → Set to "Disabled" and remove any URLs, then restart Chrome'
  },
  {
    id: 'webtransport-dev-mode',
    name: 'WebTransport Developer Mode',
    category: 'Critical',
    recommended: false,
    risk: {
      enabled: { level: 'risky', points: -15, label: 'Certificate Verification Disabled' },
      disabled: { level: 'secure', points: 0, label: 'Disabled' }
    },
    explanation: 'WebTransport Developer Mode removes certificate verification requirements, allowing connections to untrusted servers. This should only be enabled during development and testing.',
    howToCheck: 'chrome://flags/#webtransport-developer-mode → Should be "Disabled"',
    howToFix: 'chrome://flags/#webtransport-developer-mode → Set to "Disabled" and restart Chrome'
  },
  {
    id: 'fingerprinting-protection',
    name: 'Fingerprinting Protection',
    category: 'Privacy',
    recommended: 'Default',
    risk: {
      disabled: { level: 'warning', points: -10, label: 'Tracking Risk' },
      default: { level: 'secure', points: 0, label: 'Enabled' }
    },
    explanation: 'Fingerprinting protection blocks scripts that attempt to track you by creating a unique "fingerprint" of your browser configuration. Disabling this increases your tracking exposure.',
    howToCheck: 'chrome://flags/#enable-fingerprinting-protection-blocklist → Should be "Default" (enabled)\nchrome://flags/#enable-fingerprinting-protection-blocklist-incognito → Should be "Default" (enabled)',
    howToFix: 'Set both flags to "Default" and restart Chrome'
  },
  {
    id: 'ip-protection',
    name: 'IP Protection Proxy',
    category: 'Privacy',
    recommended: 'Default',
    risk: {
      optedOut: { level: 'warning', points: -10, label: 'IP Tracking Enabled' },
      default: { level: 'secure', points: 0, label: 'Protected' }
    },
    explanation: 'IP Protection helps mask your IP address from third-party trackers. Opting out allows websites to more easily track your physical location and browsing patterns.',
    howToCheck: 'chrome://flags/#ip-protection-proxy-opt-out → Should be "Default" (NOT opted out)',
    howToFix: 'chrome://flags/#ip-protection-proxy-opt-out → Set to "Default" and restart Chrome'
  },
  {
    id: 'canvas-protection-incognito',
    name: 'Canvas Fingerprinting Protection (Incognito)',
    category: 'Privacy',
    recommended: 'Default',
    risk: {
      disabled: { level: 'warning', points: -8, label: 'Incognito Fingerprinting' },
      default: { level: 'secure', points: 0, label: 'Protected' }
    },
    explanation: 'Canvas fingerprinting is a tracking technique that uses HTML5 canvas to identify users. In Incognito mode, Chrome can add noise or block canvas readbacks to prevent this tracking.',
    howToCheck: 'chrome://flags/#enable-canvas-noise → Should be "Default"\nchrome://flags/#enable-block-canvas-readback → Should be "Default"',
    howToFix: 'Set both flags to "Default" and restart Chrome'
  },
  {
    id: 'unsafe-webgpu',
    name: 'Unsafe WebGPU Support',
    category: 'Important',
    recommended: false,
    risk: {
      enabled: { level: 'warning', points: -10, label: 'Security Risk' },
      disabled: { level: 'secure', points: 0, label: 'Disabled' }
    },
    explanation: 'Unsafe WebGPU enables experimental GPU features on unsupported configurations, potentially exposing security vulnerabilities. Only enable for local development.',
    howToCheck: 'chrome://flags/#enable-unsafe-webgpu → Should be "Disabled"',
    howToFix: 'chrome://flags/#enable-unsafe-webgpu → Set to "Disabled" and restart Chrome'
  }
];

/**
 * Load previously saved browser security audit data from storage
 */
async function loadBrowserSecurityData() {
  try {
    const data = await chrome.storage.local.get(['browserSecurityAudit', 'automatedChecksEnabled', 'manualSecurityChecks']);

    if (data.browserSecurityAudit) {
      browserSecurityAudit.automatedChecks = data.browserSecurityAudit.automatedChecks || {};
      browserSecurityAudit.lastChecked = data.browserSecurityAudit.lastChecked || null;
    }

    if (data.manualSecurityChecks) {
      browserSecurityAudit.manualChecks = data.manualSecurityChecks;
    }

    browserSecurityAudit.permissionGranted = data.automatedChecksEnabled || false;

    // Calculate the browser security score from loaded data
    calculateBrowserSecurityScore();
  } catch (error) {
    console.error('Error loading browser security data:', error);
  }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', init);

async function init() {
  setupEventListeners();
  await loadExtensionTags();
  await loadExtensions();
  cleanupOrphanedTags();

  // Load browser security data BEFORE calculating overview score
  await loadBrowserSecurityData();
  await loadAutomatedChecksPreference(); // Phase 4: Load browser security settings

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
  document.getElementById('usage-filter').addEventListener('change', filterExtensions);

  // Tag selector buttons in modal (event delegation)
  document.querySelector('.usage-tag-selector').addEventListener('click', (e) => {
    const btn = e.target.closest('.tag-btn');
    if (btn && currentExtensionId) {
      const tag = btn.dataset.tag;
      setExtensionTag(currentExtensionId, tag);
    }
  });

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

  // Manual checklist table sorting
  document.getElementById('manual-checklist-table').addEventListener('click', (e) => {
    const th = e.target.closest('th.sortable');
    if (th) {
      const column = th.dataset.sort;
      sortManualChecklistTable(column);
    }
  });

  // Automated checks table sorting
  document.getElementById('automated-checks-table').addEventListener('click', (e) => {
    const th = e.target.closest('th.sortable');
    if (th) {
      const column = th.dataset.sort;
      sortAutomatedChecksTable(column);
    }
  });

  // Summary stats - clickable to filter
  document.querySelectorAll('.summary-stat.clickable').forEach(stat => {
    stat.addEventListener('click', (e) => {
      const filter = stat.dataset.filter;
      filterByStatus(filter);
    });
  });

  // Usage stats - clickable to filter by tag
  document.querySelectorAll('.usage-stat.clickable').forEach(stat => {
    stat.addEventListener('click', (e) => {
      const usageTag = stat.dataset.usage;
      filterByUsageTag(usageTag);
    });
  });

  // Phase 4: Browser Security event handlers
  const automatedChecksToggle = document.getElementById('automated-checks-toggle');
  if (automatedChecksToggle) {
    automatedChecksToggle.addEventListener('change', async (e) => {
      if (e.target.checked) {
        await requestAutomatedChecksPermission();
      } else {
        await revokeAutomatedChecksPermission();
      }
    });
  }

  const recheckBtn = document.getElementById('recheck-settings-btn');
  if (recheckBtn) {
    recheckBtn.addEventListener('click', async (e) => {
      await runBrowserSecurityAudit();
    });
  }
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
 * Load extension tags from chrome.storage.sync (with local fallback per R6)
 */
async function loadExtensionTags() {
  try {
    const result = await chrome.storage.sync.get(['extensionTags']);
    extensionTags = result.extensionTags || {};
  } catch (error) {
    console.warn('Error loading tags from sync storage, trying local:', error);
    try {
      const result = await chrome.storage.local.get(['extensionTags']);
      extensionTags = result.extensionTags || {};
    } catch (localError) {
      console.error('Error loading tags from local storage:', localError);
      extensionTags = {};
    }
  }
}

/**
 * Save extension tags to chrome.storage.sync (with local fallback per R6)
 */
async function saveExtensionTags() {
  try {
    await chrome.storage.sync.set({ extensionTags });
  } catch (error) {
    console.warn('Sync storage failed, falling back to local:', error);
    try {
      await chrome.storage.local.set({ extensionTags });
    } catch (localError) {
      console.error('Error saving tags to local storage:', localError);
    }
  }
}

/**
 * Set or clear a tag for an extension
 */
async function setExtensionTag(extensionId, tag) {
  if (!tag) {
    delete extensionTags[extensionId];
  } else {
    extensionTags[extensionId] = {
      tag: tag,
      taggedAt: Date.now()
    };
  }
  await saveExtensionTags();

  // Update UI
  updateOverview();
  renderExtensions();

  // Update modal tag buttons if modal is open for this extension
  if (currentExtensionId === extensionId) {
    updateModalTagButtons(extensionId);
  }
}

/**
 * Get tag for an extension
 */
function getExtensionTag(extensionId) {
  return extensionTags[extensionId]?.tag || null;
}

/**
 * Remove tags for extensions that are no longer installed (R1)
 */
function cleanupOrphanedTags() {
  const currentIds = new Set(allExtensions.map(e => e.id));
  let changed = false;

  for (const id of Object.keys(extensionTags)) {
    if (!currentIds.has(id)) {
      delete extensionTags[id];
      changed = true;
    }
  }

  if (changed) {
    saveExtensionTags();
    console.log('Cleaned up orphaned extension tags');
  }
}

/**
 * Update tag button states in the modal
 */
function updateModalTagButtons(extensionId) {
  const currentTag = getExtensionTag(extensionId);
  const tagButtons = document.querySelectorAll('.usage-tag-selector .tag-btn');

  tagButtons.forEach(btn => {
    const btnTag = btn.dataset.tag;
    btn.classList.toggle('active', btnTag === currentTag);
  });
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
    description: 'Can read extension data and potentially enable/disable extensions',
    recommendation: 'Note: Chrome Sentry only uses this to READ extension data, never to modify or disable extensions'
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
  const hasHttpWildcard = hostPermissions.includes('http://*/*');
  const hasHttpsWildcard = hostPermissions.includes('https://*/*');

  if (hostPermissions.includes('<all_urls>') ||
      hostPermissions.some(h => h.includes('*://*/*'))) {
    // <all_urls> or *://*/* explicitly granted
    const risk = HOST_PERMISSION_PATTERNS.allUrls;
    score += risk.weight;
    breakdown.push({
      type: 'host',
      name: 'All URLs Access',
      weight: risk.weight,
      level: risk.level,
      description: risk.description
    });
  } else if (hasHttpWildcard && hasHttpsWildcard) {
    // Both http://*/* and https://*/* present (15 points each = 30 total)
    // Treat as single "all URLs" entry in breakdown for clarity
    score += 30;
    breakdown.push({
      type: 'host',
      name: 'All URLs Access (HTTP + HTTPS)',
      weight: 30,
      level: 'high',
      description: 'Full access to ALL websites (both HTTP and HTTPS protocols)'
    });
  } else if (hasHttpsWildcard) {
    // HTTPS wildcard alone = 15 points
    score += 15;
    breakdown.push({
      type: 'host',
      name: 'HTTPS Wildcard Access',
      weight: 15,
      level: 'medium',
      description: 'Access to all HTTPS websites'
    });
  } else if (hasHttpWildcard) {
    // HTTP wildcard alone = 15 points
    score += 15;
    breakdown.push({
      type: 'host',
      name: 'HTTP Wildcard Access',
      weight: 15,
      level: 'medium',
      description: 'Access to all HTTP websites'
    });
  } else if (hostPermissions.some(h => h.includes('*'))) {
    // Other wildcard patterns (e.g., https://*.google.com/*)
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

  // Calculate usage tag counts
  const tagCounts = {
    'actively-used': 0,
    'rarely-used': 0,
    'can-remove': 0,
    'untagged': 0
  };

  allExtensions.forEach(ext => {
    const tag = getExtensionTag(ext.id);
    if (tag) {
      tagCounts[tag]++;
    } else {
      tagCounts.untagged++;
    }
  });

  // Calculate extension security score
  const avgRisk = total > 0
    ? allExtensions.reduce((sum, e) => sum + e.riskScore, 0) / total
    : 0;
  const extensionScore = Math.round(100 - avgRisk);

  // Calculate combined score (extension + browser security)
  // Only include browser score if browser security is enabled
  const browserScore = browserSecurityAudit.score || 0;
  const browserEnabled = browserSecurityAudit.permissionGranted;

  const combinedScore = browserEnabled
    ? Math.round((extensionScore + browserScore) / 2)
    : extensionScore;

  // Update UI
  document.getElementById('overall-score').textContent = combinedScore;
  document.getElementById('extension-score-dash').textContent = extensionScore;

  const browserScoreDashEl = document.getElementById('browser-score-dash');
  if (browserEnabled) {
    browserScoreDashEl.textContent = browserScore;
  } else {
    browserScoreDashEl.textContent = 'Not Scanned';
    browserScoreDashEl.style.fontSize = '12px';
  }
  document.getElementById('high-count').textContent = riskCounts.high;
  document.getElementById('medium-count').textContent = riskCounts.medium;
  document.getElementById('low-count').textContent = riskCounts.low;
  document.getElementById('total-extensions').textContent = total;
  document.getElementById('enabled-extensions').textContent = enabled;
  document.getElementById('disabled-extensions').textContent = disabled;

  // Update usage analytics counts
  document.getElementById('actively-used-count').textContent = tagCounts['actively-used'];
  document.getElementById('rarely-used-count').textContent = tagCounts['rarely-used'];
  document.getElementById('can-remove-count').textContent = tagCounts['can-remove'];
  document.getElementById('untagged-count').textContent = tagCounts.untagged;

  // Update score bar
  const scoreBar = document.getElementById('score-bar-fill');
  scoreBar.style.width = `${combinedScore}%`;
  scoreBar.classList.remove('high-risk', 'medium-risk', 'low-risk');

  if (combinedScore < 50) {
    scoreBar.classList.add('high-risk');
  } else if (combinedScore < 80) {
    scoreBar.classList.add('medium-risk');
  } else {
    scoreBar.classList.add('low-risk');
  }

  // Update description
  const description = document.getElementById('score-description');
  if (!browserEnabled) {
    if (combinedScore >= 80) {
      description.textContent = 'Extension security is strong. Enable browser security scan for complete protection.';
    } else if (combinedScore >= 50) {
      description.textContent = 'Some extension risks detected. Enable browser security scan for full analysis.';
    } else {
      description.textContent = 'High-risk extensions detected. Review extensions and enable browser security scan.';
    }
  } else {
    if (combinedScore >= 80) {
      description.textContent = 'Strong overall security posture with both extensions and browser settings.';
    } else if (combinedScore >= 50) {
      description.textContent = 'Moderate security risks detected in extensions or browser settings.';
    } else {
      description.textContent = 'Significant security risks detected. Review extensions and browser settings.';
    }
  }
}

/**
 * Filter extensions based on search and filter criteria
 */
function filterExtensions() {
  const searchTerm = document.getElementById('search-input').value.toLowerCase();
  const riskFilter = document.getElementById('risk-filter').value;
  const statusFilter = document.getElementById('status-filter').value;
  const usageFilter = document.getElementById('usage-filter').value;

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

    // Usage tag filter
    const extTag = getExtensionTag(ext.id);
    const matchesUsage = usageFilter === 'all' ||
      (usageFilter === 'untagged' && !extTag) ||
      (usageFilter !== 'untagged' && extTag === usageFilter);

    return matchesSearch && matchesRisk && matchesStatus && matchesUsage;
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

  container.innerHTML = filteredExtensions.map(ext => {
    const tag = getExtensionTag(ext.id);
    const tagBadgeHTML = tag ? `
      <span class="tag-badge tag-${tag}">
        ${tag === 'actively-used' ? '✓ I use this' :
          tag === 'rarely-used' ? '~ Rarely use' :
          '✗ Can remove'}
      </span>
    ` : '';

    return `
      <div class="extension-item" data-id="${ext.id}">
        <div class="extension-icon">
          ${ext.icons && ext.icons.length > 0
            ? `<img src="${ext.icons[ext.icons.length - 1].url}" alt="${ext.name}">`
            : '<span>?</span>'
          }
        </div>
        <div class="extension-info">
          <div class="extension-name">${escapeHtml(ext.name)}${tagBadgeHTML}</div>
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
    `;
  }).join('');
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
  // Special handling: detect if both http://*/* and https://*/* are present
  const hasHttpWildcard = hostPermissions.includes('http://*/*');
  const hasHttpsWildcard = hostPermissions.includes('https://*/*');
  const processedPerms = new Set(); // Track which permissions we've already processed

  hostPermissions.forEach(perm => {
    // Skip if we already processed this permission
    if (processedPerms.has(perm)) return;

    // Check for <all_urls> or *://*/* (covers both protocols)
    const isAllUrls = perm === '<all_urls>' || perm.includes('*://*/*');

    // Special case: Both http://*/* and https://*/* present
    // Combine them into a single entry for clarity (15 pts each = 30 total)
    if ((perm === 'http://*/*' || perm === 'https://*/*') && hasHttpWildcard && hasHttpsWildcard) {
      // Only add combined entry once (when we hit the first one)
      if (!processedPerms.has('http://*/*') && !processedPerms.has('https://*/*')) {
        permissionsData.push({
          category: 'Host Permission',
          permission: 'http://*/* + https://*/*',
          risk: 'high',
          points: 30,
          description: 'Full access to ALL websites (both HTTP and HTTPS)'
        });
        processedPerms.add('http://*/*');
        processedPerms.add('https://*/*');
      }
      return;
    }

    // HTTPS wildcard alone (15 points, MEDIUM risk)
    if (perm === 'https://*/*') {
      permissionsData.push({
        category: 'Host Permission',
        permission: perm,
        risk: 'medium',
        points: 15,
        description: 'Access to all HTTPS websites'
      });
      processedPerms.add(perm);
      return;
    }

    // HTTP wildcard alone (15 points, MEDIUM risk)
    if (perm === 'http://*/*') {
      permissionsData.push({
        category: 'Host Permission',
        permission: perm,
        risk: 'medium',
        points: 15,
        description: 'Access to all HTTP websites'
      });
      processedPerms.add(perm);
      return;
    }

    // Handle <all_urls> and *://*/*
    if (isAllUrls) {
      permissionsData.push({
        category: 'Host Permission',
        permission: perm,
        risk: 'high',
        points: 30,
        description: 'This extension can access and modify data on ALL websites'
      });
      processedPerms.add(perm);
      return;
    }

    // Other wildcard patterns (e.g., https://*.google.com/*)
    if (perm.includes('*')) {
      permissionsData.push({
        category: 'Host Permission',
        permission: perm,
        risk: 'medium',
        points: 15,
        description: 'This pattern matches multiple websites'
      });
      processedPerms.add(perm);
      return;
    }

    // Specific domain (no wildcards)
    permissionsData.push({
      category: 'Host Permission',
      permission: perm,
      risk: 'low',
      points: 0,
      description: 'Specific website access'
    });
    processedPerms.add(perm);
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

  // Update tag button states for this extension
  updateModalTagButtons(extensionId);

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
  document.getElementById('usage-filter').value = 'all';
  document.getElementById('search-input').value = '';

  // Apply filters
  filterExtensions();
}

/**
 * Export audit report (R4: includes schemaVersion for future compatibility)
 */
function exportReport() {
  const report = {
    schemaVersion: '2.0',
    generatedAt: new Date().toISOString(),
    summary: {
      totalExtensions: allExtensions.length,
      enabledExtensions: allExtensions.filter(e => e.enabled).length,
      highRisk: allExtensions.filter(e => e.riskLevel === 'high').length,
      mediumRisk: allExtensions.filter(e => e.riskLevel === 'medium').length,
      lowRisk: allExtensions.filter(e => e.riskLevel === 'low').length,
      activelyUsed: allExtensions.filter(e => getExtensionTag(e.id) === 'actively-used').length,
      rarelyUsed: allExtensions.filter(e => getExtensionTag(e.id) === 'rarely-used').length,
      canRemove: allExtensions.filter(e => getExtensionTag(e.id) === 'can-remove').length,
      untagged: allExtensions.filter(e => !getExtensionTag(e.id)).length
    },
    extensionTags: extensionTags,
    extensions: allExtensions.map(ext => ({
      name: ext.name,
      id: ext.id,
      version: ext.version,
      enabled: ext.enabled,
      installType: ext.installType,
      riskScore: ext.riskScore,
      riskLevel: ext.riskLevel,
      usageTag: getExtensionTag(ext.id),
      permissions: ext.permissions || [],
      hostPermissions: ext.hostPermissions || []
    }))
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `chrome-sentry-audit-${new Date().toISOString().split('T')[0]}.json`;
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
    document.getElementById('usage-filter').value = 'all';
  } else {
    document.getElementById('status-filter').value = status;
    document.getElementById('risk-filter').value = 'all';
    document.getElementById('usage-filter').value = 'all';
  }

  // Clear search
  document.getElementById('search-input').value = '';

  // Apply filters
  filterExtensions();
}

/**
 * Filter extensions by usage tag and switch to extensions tab
 */
function filterByUsageTag(usageTag) {
  // Switch to extensions tab
  switchTab('extensions');

  // Set the usage filter
  document.getElementById('usage-filter').value = usageTag;

  // Clear other filters
  document.getElementById('risk-filter').value = 'all';
  document.getElementById('status-filter').value = 'all';
  document.getElementById('search-input').value = '';

  // Apply filters
  filterExtensions();
}

// ============================================================================
// BROWSER SECURITY AUDIT (Phase 4)
// ============================================================================

/**
 * Check if automated checks permission is granted (R2: Always check actual Chrome state)
 */
async function checkAutomatedChecksPermission() {
  try {
    const hasPermission = await chrome.permissions.contains({ permissions: ['privacy'] });
    return hasPermission;
  } catch (error) {
    console.error('Failed to check privacy permission:', error);
    return false;
  }
}

/**
 * Request privacy permission for automated checks (R8: Show loading state)
 */
async function requestAutomatedChecksPermission() {
  const toggle = document.getElementById('automated-checks-toggle');
  const recheckBtn = document.getElementById('recheck-settings-btn');

  try {
    // Show loading state (R8)
    toggle.disabled = true;

    const granted = await chrome.permissions.request({ permissions: ['privacy'] });

    if (granted) {
      browserSecurityAudit.permissionGranted = true;
      await saveAutomatedChecksPreference(true);

      // Run audit and show results
      await runBrowserSecurityAudit();
      renderBrowserSecurityAudit();

      // Show automated checks section
      document.getElementById('automated-checks-section').style.display = 'block';
    } else {
      // User denied permission
      browserSecurityAudit.permissionGranted = false;
      toggle.checked = false;
      await saveAutomatedChecksPreference(false);
    }
  } catch (error) {
    console.error('Failed to request privacy permission:', error);
    browserSecurityAudit.permissionGranted = false;
    toggle.checked = false;
    await saveAutomatedChecksPreference(false);
  } finally {
    toggle.disabled = false;
  }
}

/**
 * Revoke privacy permission for automated checks
 */
async function revokeAutomatedChecksPermission() {
  try {
    await chrome.permissions.remove({ permissions: ['privacy'] });
    browserSecurityAudit.permissionGranted = false;
    browserSecurityAudit.automatedChecks = {};
    browserSecurityAudit.score = 0;

    await saveAutomatedChecksPreference(false);

    // Clear stored browser security audit data
    await chrome.storage.local.set({
      browserSecurityAudit: {
        automatedChecks: {},
        lastChecked: null
      }
    });

    // Hide automated checks section
    document.getElementById('automated-checks-section').style.display = 'none';

    // Update UI
    renderBrowserSecurityAudit();
    updateOverview(); // Update overview to reflect removed browser score

    // Notify service worker to update badge
    chrome.runtime.sendMessage({ type: 'UPDATE_ICON' });
  } catch (error) {
    console.error('Failed to revoke privacy permission:', error);
  }
}

/**
 * Load automated checks permission state on init (R2: Check actual permission, not saved preference)
 */
async function loadAutomatedChecksPreference() {
  try {
    // R2: Always check ACTUAL Chrome permission state, not just saved preference
    const hasPermission = await checkAutomatedChecksPermission();

    browserSecurityAudit.permissionGranted = hasPermission;
    document.getElementById('automated-checks-toggle').checked = hasPermission;

    if (hasPermission) {
      // Permission granted - show section and run audit
      document.getElementById('automated-checks-section').style.display = 'block';
      await runBrowserSecurityAudit();
    } else {
      // Permission not granted - hide section
      document.getElementById('automated-checks-section').style.display = 'none';
    }

    // Load manual check states
    await loadManualCheckStates();

    // Render UI
    renderBrowserSecurityAudit();
  } catch (error) {
    console.error('Failed to load automated checks preference:', error);
  }
}

/**
 * Save automated checks preference
 */
async function saveAutomatedChecksPreference(enabled) {
  try {
    await chrome.storage.local.set({ automatedChecksEnabled: enabled });
  } catch (error) {
    console.error('Failed to save automated checks preference:', error);
  }
}

/**
 * Run browser security audit using chrome.privacy API (R5: Error handling for each setting)
 */
async function runBrowserSecurityAudit() {
  if (!browserSecurityAudit.permissionGranted) {
    return;
  }

  const recheckBtn = document.getElementById('recheck-settings-btn');
  if (recheckBtn) {
    recheckBtn.disabled = true;
    recheckBtn.textContent = '⏳ Checking...';
  }

  browserSecurityAudit.automatedChecks = {};

  // Check each setting with individual error handling (R5)
  for (const [settingPath, config] of Object.entries(SECURITY_SETTINGS_CONFIG)) {
    const result = await getPrivacySetting(settingPath);

    if (result.error) {
      // R5: Show "Unable to check" status for failed readings
      browserSecurityAudit.automatedChecks[settingPath] = {
        value: null,
        error: result.error,
        config: config
      };
    } else {
      browserSecurityAudit.automatedChecks[settingPath] = {
        value: result.value,
        levelOfControl: result.levelOfControl,
        config: config
      };
    }
  }

  browserSecurityAudit.lastChecked = Date.now();

  // Calculate score
  calculateBrowserSecurityScore();

  // Save audit results to storage for service worker to access
  await chrome.storage.local.set({
    browserSecurityAudit: {
      automatedChecks: browserSecurityAudit.automatedChecks,
      lastChecked: browserSecurityAudit.lastChecked
    }
  });

  // Render results
  renderBrowserSecurityAudit();
  updateOverview(); // Update overview to reflect new browser security score

  // Notify service worker to update badge
  chrome.runtime.sendMessage({ type: 'UPDATE_ICON' });

  if (recheckBtn) {
    recheckBtn.disabled = false;
    recheckBtn.textContent = '🔄 Re-check';
  }
}

/**
 * Get a privacy setting value (R5: Graceful error handling)
 */
async function getPrivacySetting(settingPath) {
  try {
    const parts = settingPath.split('.');
    let setting = chrome.privacy;

    for (const part of parts) {
      setting = setting[part];
      if (!setting) {
        throw new Error(`Setting ${settingPath} not found`);
      }
    }

    const result = await setting.get({});
    return {
      value: result.value,
      levelOfControl: result.levelOfControl
    };
  } catch (error) {
    // R5: Return error info instead of crashing
    console.warn(`Could not read setting ${settingPath}:`, error.message);
    return {
      value: null,
      error: error.message
    };
  }
}

/**
 * Calculate browser security score from automated checks
 */
function calculateBrowserSecurityScore() {
  if (!browserSecurityAudit.permissionGranted) {
    browserSecurityAudit.score = 0;
    return;
  }

  let totalPoints = 0;
  let secureCount = 0;
  let warningCount = 0;
  let riskyCount = 0;

  for (const [settingPath, check] of Object.entries(browserSecurityAudit.automatedChecks)) {
    if (check.error) {
      // Skip settings that couldn't be checked
      continue;
    }

    const value = check.value;
    const config = check.config;
    const riskInfo = config.risk[value] || config.risk[String(value)];

    if (riskInfo) {
      totalPoints += riskInfo.points;

      if (riskInfo.level === 'secure') secureCount++;
      else if (riskInfo.level === 'warning') warningCount++;
      else if (riskInfo.level === 'risky') riskyCount++;
    }
  }

  // Score = 100 + totalPoints (where totalPoints are negative for risky settings)
  browserSecurityAudit.score = Math.max(0, Math.min(100, 100 + totalPoints));
  browserSecurityAudit.secureCount = secureCount;
  browserSecurityAudit.warningCount = warningCount;
  browserSecurityAudit.riskyCount = riskyCount;
}

/**
 * Render browser security audit UI
 */
function renderBrowserSecurityAudit() {
  renderAutomatedChecks();
  renderManualChecklist();
  updateBrowserSecurityScore();
}

/**
 * Render automated security checks results as table
 */
function renderAutomatedChecks() {
  const tbody = document.getElementById('automated-checks-body');
  const lastCheckedDisplay = document.getElementById('last-checked-display');
  const lastCheckedTime = document.getElementById('last-checked-time');

  if (!browserSecurityAudit.permissionGranted) {
    tbody.innerHTML = '<tr><td colspan="5" class="no-checks">Enable automated checks above to scan your browser settings.</td></tr>';
    lastCheckedDisplay.style.display = 'none';
    return;
  }

  if (Object.keys(browserSecurityAudit.automatedChecks).length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="no-checks">Click "Re-check" to scan your browser settings.</td></tr>';
    lastCheckedDisplay.style.display = 'none';
    return;
  }

  // Show last checked time
  if (browserSecurityAudit.lastChecked) {
    lastCheckedTime.textContent = new Date(browserSecurityAudit.lastChecked).toLocaleString();
    lastCheckedDisplay.style.display = 'inline-block';
  }

  // Create table data array for sorting
  const tableData = [];

  for (const [settingPath, check] of Object.entries(browserSecurityAudit.automatedChecks)) {
    const config = check.config;

    // R5: Handle errors gracefully
    if (check.error) {
      tableData.push({
        name: config.name,
        currentValue: null,
        recommendedValue: config.recommendedValue,
        status: 'error',
        config: config,
        check: check,
        error: check.error
      });
      continue;
    }

    const value = check.value;
    const riskInfo = config.risk[value] || config.risk[String(value)] || { level: 'warning', label: 'Unknown', points: 0 };
    const isRecommended = (value === config.recommendedValue) || (String(value) === String(config.recommendedValue));

    tableData.push({
      name: config.name,
      currentValue: value,
      recommendedValue: config.recommendedValue,
      status: riskInfo.level,
      isRecommended: isRecommended,
      config: config,
      check: check,
      riskInfo: riskInfo
    });
  }

  // Store for sorting
  window.automatedChecksData = tableData;

  // Render table rows
  tbody.innerHTML = tableData.map(item => {
    if (item.error) {
      return `
        <tr class="status-error">
          <td class="setting-name-cell">
            <div class="setting-name">${item.name}</div>
            <div class="setting-explanation">${item.config.explanation}</div>
          </td>
          <td colspan="2" class="error-cell">
            <span class="error-message">Unable to check: ${item.error}</span>
          </td>
          <td class="status-cell">
            <span class="status-badge error">Error</span>
          </td>
          <td class="details-cell">
            <details class="check-instructions">
              <summary>How to check manually</summary>
              <div class="instructions-content">
                <p>${item.config.howToFix}</p>
              </div>
            </details>
          </td>
        </tr>
      `;
    }

    const statusIcon = item.status === 'secure' ? '✓' : item.status === 'warning' ? '⚠' : '✗';

    return `
      <tr class="status-${item.status}">
        <td class="setting-name-cell">
          <div class="setting-name">${item.name}</div>
          <div class="setting-explanation">${item.config.explanation}</div>
        </td>
        <td class="current-value-cell">
          <span class="value-badge ${item.isRecommended ? 'good' : 'bad'}">${formatSettingValue(item.currentValue)}</span>
        </td>
        <td class="recommended-value-cell">
          <span class="value-text">${formatSettingValue(item.recommendedValue)}</span>
        </td>
        <td class="status-cell">
          <span class="status-badge ${item.status}">
            ${statusIcon} ${item.status === 'secure' ? 'Secure' : item.status === 'warning' ? 'Warning' : 'Risky'}
          </span>
        </td>
        <td class="details-cell">
          ${!item.isRecommended ? `
            <details class="check-instructions">
              <summary>How to fix</summary>
              <div class="instructions-content">
                <p>${item.config.howToFix}</p>
                ${item.check.levelOfControl && item.check.levelOfControl !== 'controllable_by_this_extension' ?
                  `<p class="control-note">⚠️ This setting is managed by ${item.check.levelOfControl.replace(/_/g, ' ')}</p>` : ''}
              </div>
            </details>
          ` : '<span class="ok-text">Configured correctly</span>'}
        </td>
      </tr>
    `;
  }).join('');
}

/**
 * Format a setting value for display
 */
function formatSettingValue(value) {
  if (typeof value === 'boolean') {
    return value ? 'Enabled' : 'Disabled';
  }
  if (value === 'default') {
    return 'Default';
  }
  if (value === 'default_public_interface_only') {
    return 'Public Interface Only';
  }
  if (value === 'disable_non_proxied_udp') {
    return 'Disable Non-Proxied UDP';
  }
  return String(value);
}

/**
 * Sort automated checks table
 */
let automatedChecksSort = { column: 'status', direction: 'asc' };

function sortAutomatedChecksTable(column) {
  if (!window.automatedChecksData) return;

  const data = [...window.automatedChecksData];

  // Toggle direction if same column
  if (automatedChecksSort.column === column) {
    automatedChecksSort.direction = automatedChecksSort.direction === 'asc' ? 'desc' : 'asc';
  } else {
    automatedChecksSort.column = column;
    automatedChecksSort.direction = column === 'status' ? 'asc' : 'asc';
  }

  // Sort the data
  data.sort((a, b) => {
    let aVal, bVal;

    switch (column) {
      case 'name':
        aVal = a.name.toLowerCase();
        bVal = b.name.toLowerCase();
        break;
      case 'current':
        aVal = formatSettingValue(a.currentValue).toLowerCase();
        bVal = formatSettingValue(b.currentValue).toLowerCase();
        break;
      case 'status':
        const statusOrder = { error: 4, risky: 3, warning: 2, secure: 1 };
        aVal = statusOrder[a.status] || 0;
        bVal = statusOrder[b.status] || 0;
        break;
      default:
        return 0;
    }

    if (aVal < bVal) return automatedChecksSort.direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return automatedChecksSort.direction === 'asc' ? 1 : -1;
    return 0;
  });

  // Update sort icons
  document.querySelectorAll('#automated-checks-table th.sortable').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    th.classList.remove('sorted-asc', 'sorted-desc');
    icon.textContent = '';

    if (th.dataset.sort === column) {
      th.classList.add(`sorted-${automatedChecksSort.direction}`);
      icon.textContent = automatedChecksSort.direction === 'asc' ? '▲' : '▼';
    }
  });

  // Re-render table
  const tbody = document.getElementById('automated-checks-body');
  tbody.innerHTML = data.map(item => {
    if (item.error) {
      return `
        <tr class="status-error">
          <td class="setting-name-cell">
            <div class="setting-name">${item.name}</div>
            <div class="setting-explanation">${item.config.explanation}</div>
          </td>
          <td colspan="2" class="error-cell">
            <span class="error-message">Unable to check: ${item.error}</span>
          </td>
          <td class="status-cell">
            <span class="status-badge error">Error</span>
          </td>
          <td class="details-cell">
            <details class="check-instructions">
              <summary>How to check manually</summary>
              <div class="instructions-content">
                <p>${item.config.howToFix}</p>
              </div>
            </details>
          </td>
        </tr>
      `;
    }

    const statusIcon = item.status === 'secure' ? '✓' : item.status === 'warning' ? '⚠' : '✗';

    return `
      <tr class="status-${item.status}">
        <td class="setting-name-cell">
          <div class="setting-name">${item.name}</div>
          <div class="setting-explanation">${item.config.explanation}</div>
        </td>
        <td class="current-value-cell">
          <span class="value-badge ${item.isRecommended ? 'good' : 'bad'}">${formatSettingValue(item.currentValue)}</span>
        </td>
        <td class="recommended-value-cell">
          <span class="value-text">${formatSettingValue(item.recommendedValue)}</span>
        </td>
        <td class="status-cell">
          <span class="status-badge ${item.status}">
            ${statusIcon} ${item.status === 'secure' ? 'Secure' : item.status === 'warning' ? 'Warning' : 'Risky'}
          </span>
        </td>
        <td class="details-cell">
          ${!item.isRecommended ? `
            <details class="check-instructions">
              <summary>How to fix</summary>
              <div class="instructions-content">
                <p>${item.config.howToFix}</p>
                ${item.check.levelOfControl && item.check.levelOfControl !== 'controllable_by_this_extension' ?
                  `<p class="control-note">⚠️ This setting is managed by ${item.check.levelOfControl.replace(/_/g, ' ')}</p>` : ''}
              </div>
            </details>
          ` : '<span class="ok-text">Configured correctly</span>'}
        </td>
      </tr>
    `;
  }).join('');
}

/**
 * Render manual verification checklist as table (R3: Show verification timestamps)
 */
function renderManualChecklist() {
  const tbody = document.getElementById('manual-checklist-body');

  // Create table data array for sorting
  const tableData = MANUAL_SECURITY_CHECKS.map(check => {
    const checkState = browserSecurityAudit.manualChecks[check.id] || {};
    const isVerified = checkState.verified || false;
    const verifiedAt = checkState.verifiedAt || null;

    return {
      check: check,
      isVerified: isVerified,
      verifiedAt: verifiedAt || 0 // 0 for sorting unverified to bottom
    };
  });

  // Store for sorting
  window.manualChecklistData = tableData;

  // Render table rows
  tbody.innerHTML = tableData.map(item => {
    const { check, isVerified, verifiedAt } = item;

    return `
      <tr class="${isVerified ? 'verified' : 'unverified'}">
        <td class="checkbox-cell">
          <input type="checkbox"
                 id="manual-${check.id}"
                 data-check-id="${check.id}"
                 ${isVerified ? 'checked' : ''}
                 aria-label="Mark ${check.name} as verified">
        </td>
        <td class="check-name-cell">
          <div class="check-name">${check.name}</div>
          <div class="check-explanation">${check.explanation}</div>
        </td>
        <td class="category-cell">
          <span class="check-category category-${check.category.toLowerCase()}">${check.category}</span>
        </td>
        <td class="verified-cell">
          ${isVerified && verifiedAt ? getTimeAgo(verifiedAt) : '<span class="unverified-text">Not verified</span>'}
        </td>
        <td class="instructions-cell">
          <details class="check-instructions">
            <summary>View Instructions</summary>
            <div class="instructions-content">
              <p><strong>Where to find it:</strong><br>${check.howToCheck}</p>
              <p><strong>Recommended setting:</strong><br>${formatRecommendedValue(check.recommended)}</p>
              ${check.howToFix ? `<p><strong>How to enable:</strong><br>${check.howToFix}</p>` : ''}
            </div>
          </details>
        </td>
      </tr>
    `;
  }).join('');

  // Add event listeners for checkboxes
  tbody.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
    checkbox.addEventListener('change', handleManualCheckChange);
  });
}

/**
 * Format recommended value for manual checks
 */
function formatRecommendedValue(value) {
  if (typeof value === 'boolean') {
    return value ? 'Enabled' : 'Disabled';
  }
  return String(value);
}

/**
 * Sort manual checklist table
 */
let manualChecklistSort = { column: 'category', direction: 'asc' };

function sortManualChecklistTable(column) {
  if (!window.manualChecklistData) return;

  const data = [...window.manualChecklistData];

  // Toggle direction if same column
  if (manualChecklistSort.column === column) {
    manualChecklistSort.direction = manualChecklistSort.direction === 'asc' ? 'desc' : 'asc';
  } else {
    manualChecklistSort.column = column;
    manualChecklistSort.direction = column === 'verified' ? 'desc' : 'asc';
  }

  // Sort the data
  data.sort((a, b) => {
    let aVal, bVal;

    switch (column) {
      case 'name':
        aVal = a.check.name.toLowerCase();
        bVal = b.check.name.toLowerCase();
        break;
      case 'category':
        const categoryOrder = { Critical: 3, Important: 2, Privacy: 1 };
        aVal = categoryOrder[a.check.category] || 0;
        bVal = categoryOrder[b.check.category] || 0;
        break;
      case 'verified':
        aVal = a.verifiedAt;
        bVal = b.verifiedAt;
        break;
      default:
        return 0;
    }

    if (aVal < bVal) return manualChecklistSort.direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return manualChecklistSort.direction === 'asc' ? 1 : -1;
    return 0;
  });

  // Update sort icons
  document.querySelectorAll('#manual-checklist-table th.sortable').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    th.classList.remove('sorted-asc', 'sorted-desc');
    icon.textContent = '';

    if (th.dataset.sort === column) {
      th.classList.add(`sorted-${manualChecklistSort.direction}`);
      icon.textContent = manualChecklistSort.direction === 'asc' ? '▲' : '▼';
    }
  });

  // Re-render table
  const tbody = document.getElementById('manual-checklist-body');
  tbody.innerHTML = data.map(item => {
    const { check, isVerified, verifiedAt } = item;

    return `
      <tr class="${isVerified ? 'verified' : 'unverified'}">
        <td class="checkbox-cell">
          <input type="checkbox"
                 id="manual-${check.id}"
                 data-check-id="${check.id}"
                 ${isVerified ? 'checked' : ''}
                 aria-label="Mark ${check.name} as verified">
        </td>
        <td class="check-name-cell">
          <div class="check-name">${check.name}</div>
          <div class="check-explanation">${check.explanation}</div>
        </td>
        <td class="category-cell">
          <span class="check-category category-${check.category.toLowerCase()}">${check.category}</span>
        </td>
        <td class="verified-cell">
          ${isVerified && verifiedAt ? getTimeAgo(verifiedAt) : '<span class="unverified-text">Not verified</span>'}
        </td>
        <td class="instructions-cell">
          <details class="check-instructions">
            <summary>View Instructions</summary>
            <div class="instructions-content">
              <p><strong>Where to find it:</strong><br>${check.howToCheck}</p>
              <p><strong>Recommended setting:</strong><br>${formatRecommendedValue(check.recommended)}</p>
              ${check.howToFix ? `<p><strong>How to enable:</strong><br>${check.howToFix}</p>` : ''}
            </div>
          </details>
        </td>
      </tr>
    `;
  }).join('');

  // Re-attach event listeners for checkboxes
  tbody.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
    checkbox.addEventListener('change', handleManualCheckChange);
  });
}

/**
 * Get relative time string (R3: "Last verified: X ago")
 */
function getTimeAgo(timestamp) {
  const now = Date.now();
  const diff = now - timestamp;

  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return 'just now';
  if (minutes === 1) return '1 minute ago';
  if (minutes < 60) return `${minutes} minutes ago`;
  if (hours === 1) return '1 hour ago';
  if (hours < 24) return `${hours} hours ago`;
  if (days === 1) return '1 day ago';
  if (days < 7) return `${days} days ago`;

  return new Date(timestamp).toLocaleDateString();
}

/**
 * Handle manual check checkbox change (R3: Store verification timestamp)
 */
async function handleManualCheckChange(e) {
  const checkId = e.target.dataset.checkId;
  const isChecked = e.target.checked;

  if (isChecked) {
    browserSecurityAudit.manualChecks[checkId] = {
      verified: true,
      verifiedAt: Date.now() // R3: Store timestamp when verified
    };
  } else {
    delete browserSecurityAudit.manualChecks[checkId];
  }

  await saveManualCheckStates();
  renderManualChecklist(); // Re-render to show/hide timestamp
}

/**
 * Save manual check states to storage (R3: With timestamps)
 */
async function saveManualCheckStates() {
  try {
    await chrome.storage.local.set({
      manualSecurityChecks: browserSecurityAudit.manualChecks
    });
  } catch (error) {
    console.error('Failed to save manual check states:', error);
  }
}

/**
 * Load manual check states from storage (R3: With timestamps)
 */
async function loadManualCheckStates() {
  try {
    const result = await chrome.storage.local.get(['manualSecurityChecks']);
    browserSecurityAudit.manualChecks = result.manualSecurityChecks || {};
  } catch (error) {
    console.error('Failed to load manual check states:', error);
    browserSecurityAudit.manualChecks = {};
  }
}

/**
 * Update browser security score display
 */
function updateBrowserSecurityScore() {
  const scoreValue = document.getElementById('browser-security-score');
  const scoreDescription = document.getElementById('browser-score-description');
  const secureCount = document.getElementById('secure-settings-count');
  const warningCount = document.getElementById('warning-settings-count');
  const riskyCount = document.getElementById('risky-settings-count');

  if (!browserSecurityAudit.permissionGranted || Object.keys(browserSecurityAudit.automatedChecks).length === 0) {
    scoreValue.textContent = '--';
    scoreDescription.textContent = 'Enable automated checks for score';
    secureCount.textContent = '0';
    warningCount.textContent = '0';
    riskyCount.textContent = '0';
    return;
  }

  scoreValue.textContent = Math.round(browserSecurityAudit.score);

  // Score description
  const score = browserSecurityAudit.score;
  if (score >= 90) {
    scoreDescription.textContent = 'Excellent security configuration';
  } else if (score >= 75) {
    scoreDescription.textContent = 'Good security, minor improvements needed';
  } else if (score >= 60) {
    scoreDescription.textContent = 'Moderate security, several issues to address';
  } else if (score >= 40) {
    scoreDescription.textContent = 'Poor security, many risky settings detected';
  } else {
    scoreDescription.textContent = 'Critical security risks detected';
  }

  // Breakdown counts
  secureCount.textContent = browserSecurityAudit.secureCount || 0;
  warningCount.textContent = browserSecurityAudit.warningCount || 0;
  riskyCount.textContent = browserSecurityAudit.riskyCount || 0;
}
