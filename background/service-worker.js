// Background service worker for Extension Security Auditor
// Manifest V3 requires service workers instead of background pages

/**
 * Extension installation handler
 */
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('Extension Security Auditor installed');
    // Could open onboarding page here in future
  } else if (details.reason === 'update') {
    console.log('Extension Security Auditor updated to version', chrome.runtime.getManifest().version);
  }
});

/**
 * Listen for extension install/uninstall events
 * This allows us to detect changes to the user's extensions
 */
chrome.management.onInstalled.addListener((info) => {
  console.log('New extension installed:', info.name);
  // Future: Could trigger notification about new extension
});

chrome.management.onUninstalled.addListener((id) => {
  console.log('Extension uninstalled:', id);
  // Future: Could update stored data
});

chrome.management.onEnabled.addListener((info) => {
  console.log('Extension enabled:', info.name);
});

chrome.management.onDisabled.addListener((info) => {
  console.log('Extension disabled:', info.name);
});

/**
 * Message handler for communication between popup/dashboard and service worker
 * Future: Used for background scanning, notifications, etc.
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

  // Future message types can be added here
});

console.log('Extension Security Auditor service worker loaded');
