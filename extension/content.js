/**
 * PhishGuard Content Script
 * Shows a warning banner on dangerous pages
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_RESULT') {
        // Remove existing banner if any
        const existing = document.getElementById('phishguard-banner');
        if (existing) existing.remove();

        // Only show banner for average and bad
        if (message.risk === 'good') return;

        const banner = document.createElement('div');
        banner.id = 'phishguard-banner';

        const isDanger = message.risk === 'bad';

        banner.innerHTML = `
      <div style="
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
        background: ${isDanger ? 'linear-gradient(135deg, #d32f2f, #b71c1c)' : 'linear-gradient(135deg, #f57c00, #e65100)'};
        color: white; padding: 12px 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px; display: flex; align-items: center; justify-content: space-between;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        animation: phishguard-slide 0.3s ease-out;
      ">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="font-size: 20px;">${isDanger ? '🚨' : '⚠️'}</span>
          <div>
            <strong>PhishGuard ${isDanger ? 'DANGER' : 'Warning'}:</strong>
            This site has a threat score of <strong>${message.score}/100</strong>.
            ${isDanger ? 'Do NOT enter any personal information!' : 'Proceed with caution.'}
          </div>
        </div>
        <button onclick="this.parentElement.parentElement.remove()" style="
          background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.4);
          color: white; padding: 6px 14px; border-radius: 6px; cursor: pointer;
          font-size: 13px; font-weight: 500;
        ">Dismiss</button>
      </div>
      <style>
        @keyframes phishguard-slide {
          from { transform: translateY(-100%); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
      </style>
    `;

        document.documentElement.prepend(banner);
    }
});
