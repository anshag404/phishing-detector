/**
 * PhishGuard Content Script
 * 1. Shows warning banners on dangerous pages (from URL scan)
 * 2. Scans email content on Gmail, Outlook, and Yahoo Mail
 */

// ---- URL Scan Result Banner ----
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_RESULT') {
    const existing = document.getElementById('phishguard-banner');
    if (existing) existing.remove();

    // Only show banner for medium and above
    if (message.risk === 'safe' || message.risk === 'low') return;

    const banner = document.createElement('div');
    banner.id = 'phishguard-banner';
    
    const colors = {
      medium:   { bg: 'linear-gradient(135deg, #f9a825, #f57f17)', icon: '⚠️', label: 'Caution', msg: 'Proceed with caution — verify before entering data.' },
      high:     { bg: 'linear-gradient(135deg, #ff6d00, #e65100)', icon: '🔶', label: 'HIGH RISK', msg: 'This site has strong phishing indicators. Do NOT enter personal info!' },
      critical: { bg: 'linear-gradient(135deg, #d32f2f, #b71c1c)', icon: '🚨', label: 'CRITICAL THREAT', msg: 'CONFIRMED phishing/malware site! Leave immediately!' }
    };
    const c = colors[message.risk] || colors.medium;

    banner.innerHTML = `
      <div style="
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
        background: ${c.bg};
        color: white; padding: 12px 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px; display: flex; align-items: center; justify-content: space-between;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        animation: phishguard-slide 0.3s ease-out;
      ">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="font-size: 20px;">${c.icon}</span>
          <div>
            <strong>PhishGuard ${c.label}:</strong>
            This site has a threat score of <strong>${message.score}/100</strong>.
            ${c.msg}
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

  // Email scan result
  if (message.type === 'EMAIL_SCAN_RESULT') {
    showEmailWarning(message);
  }
});

// ===============================================================
// EMAIL SCANNING — Detects when user opens emails in webmail
// ===============================================================

const hostname = window.location.hostname;
const isGmail = hostname === 'mail.google.com';
const isOutlook = hostname === 'outlook.live.com' || hostname === 'outlook.office.com' || hostname === 'outlook.office365.com';
const isYahoo = hostname === 'mail.yahoo.com';

// Only run email scanning on webmail sites
if (isGmail || isOutlook || isYahoo) {
  console.log('🛡️ PhishGuard: Email scanning active on', hostname);
  startEmailScanning();
}

function startEmailScanning() {
  // Track already-scanned emails to avoid repeats
  const scannedEmails = new Set();
  let lastScannedContent = '';

  // Use MutationObserver to detect when emails are opened
  const observer = new MutationObserver(() => {
    const emailContent = extractEmailContent();
    if (emailContent && emailContent.length > 30 && emailContent !== lastScannedContent) {
      // Debounce: only scan if content is stable
      lastScannedContent = emailContent;
      setTimeout(() => {
        if (lastScannedContent === emailContent && !scannedEmails.has(hashString(emailContent))) {
          scannedEmails.add(hashString(emailContent));
          scanEmailContent(emailContent);
        }
      }, 800);
    }
  });

  // Start observing with a delay to let the page load
  setTimeout(() => {
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: false,
      attributes: false
    });
  }, 2000);
}

function extractEmailContent() {
  let content = '';
  let subject = '';
  let sender = '';

  if (isGmail) {
    // Gmail: email body is in elements with class 'a3s' or 'ii gt'
    const emailBody = document.querySelector('.a3s.aiL') || document.querySelector('.a3s') || document.querySelector('.ii.gt');
    if (emailBody) content = emailBody.innerText || '';

    // Subject line
    const subjectEl = document.querySelector('h2.hP') || document.querySelector('[data-thread-perm-id] h2');
    if (subjectEl) subject = subjectEl.innerText || '';

    // Sender
    const senderEl = document.querySelector('.gD') || document.querySelector('[email]');
    if (senderEl) sender = senderEl.getAttribute('email') || senderEl.innerText || '';
  }

  else if (isOutlook) {
    // Outlook: email body in reading pane
    const emailBody = document.querySelector('[aria-label="Message body"]') ||
      document.querySelector('.XbIp4') ||
      document.querySelector('[role="document"]');
    if (emailBody) content = emailBody.innerText || '';

    // Subject
    const subjectEl = document.querySelector('[aria-label*="Subject"]') ||
      document.querySelector('.lDdSm');
    if (subjectEl) subject = subjectEl.innerText || '';
  }

  else if (isYahoo) {
    // Yahoo Mail: email body
    const emailBody = document.querySelector('.msg-body') ||
      document.querySelector('[data-test-id="message-view-body-content"]');
    if (emailBody) content = emailBody.innerText || '';

    // Subject
    const subjectEl = document.querySelector('[data-test-id="message-group-subject-text"]');
    if (subjectEl) subject = subjectEl.innerText || '';
  }

  // Combine subject and content for analysis
  const fullContent = [subject, sender, content].filter(Boolean).join(' | ');
  return fullContent.trim();
}

function scanEmailContent(content) {
  // Send to background script for scanning
  chrome.runtime.sendMessage({
    type: 'SCAN_EMAIL',
    content: content,
    source: isGmail ? 'Gmail' : isOutlook ? 'Outlook' : 'Yahoo Mail'
  }, (response) => {
    if (response && (response.risk === 'medium' || response.risk === 'high' || response.risk === 'critical')) {
      showEmailWarning(response);
    }
  });
}

function showEmailWarning(result) {
  const existing = document.getElementById('phishguard-email-warning');
  if (existing) existing.remove();

  const isCritical = result.risk === 'critical';
  const isHigh = result.risk === 'high';
  const isDanger = isCritical || isHigh;
  const borderColor = isCritical ? '#ff1744' : isHigh ? '#ff9800' : '#ffc107';
  const bgGrad = isCritical ? 'linear-gradient(135deg, #1a0000, #2d0000)' : isHigh ? 'linear-gradient(135deg, #1a0f00, #2d1a00)' : 'linear-gradient(135deg, #1a1200, #2d1f00)';
  const levelLabel = isCritical ? 'Phishing Email Detected!' : isHigh ? 'High-Risk Email' : 'Suspicious Email';
  const levelIcon = isCritical ? '🚨' : isHigh ? '🔶' : '⚠️';

  const warning = document.createElement('div');
  warning.id = 'phishguard-email-warning';

  warning.innerHTML = `
    <div style="
      position: fixed; bottom: 20px; right: 20px; z-index: 2147483647;
      width: 380px; max-width: calc(100vw - 40px);
      background: ${bgGrad};
      border: 2px solid ${borderColor};
      border-radius: 16px;
      padding: 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: white;
      box-shadow: 0 10px 40px rgba(0,0,0,0.5);
      animation: phishguard-popup 0.4s ease-out;
    ">
      <style>
        @keyframes phishguard-popup {
          from { transform: translateY(40px) scale(0.95); opacity: 0; }
          to { transform: translateY(0) scale(1); opacity: 1; }
        }
      </style>

      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
        <span style="font-size: 28px;">${levelIcon}</span>
        <div>
          <div style="font-size: 16px; font-weight: 700; color: ${borderColor};">
            ${levelLabel}
          </div>
          <div style="font-size: 11px; color: #999;">🛡️ PhishGuard Email Scanner</div>
        </div>
        <button onclick="this.closest('#phishguard-email-warning').remove()" style="
          margin-left: auto; background: none; border: none; color: #888;
          font-size: 20px; cursor: pointer; padding: 4px;
        ">✕</button>
      </div>

      <div style="
        background: rgba(255,255,255,0.05); border-radius: 10px; padding: 12px;
        margin-bottom: 12px; text-align: center;
      ">
        <div style="font-size: 36px; font-weight: 800; color: ${borderColor};">
          ${result.score}<span style="font-size: 16px; color: #888;">/100</span>
        </div>
        <div style="font-size: 12px; color: #aaa; text-transform: uppercase; letter-spacing: 1px;">
          Threat Score
        </div>
      </div>

      <div style="margin-bottom: 12px;">
        ${(result.factors || []).slice(0, 4).map(f => `
          <div style="
            display: flex; align-items: center; gap: 8px;
            padding: 6px 0; font-size: 12px; color: #ddd;
            border-bottom: 1px solid rgba(255,255,255,0.05);
          ">
            <span style="
              width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
              background: ${f.severity === 'critical' ? '#ff1744' : f.severity === 'high' ? '#ff9800' : f.severity === 'medium' ? '#ffc107' : '#2196f3'};
            "></span>
            <span style="flex:1;">${f.name}</span>
            <span style="color: #888; font-size: 11px;">+${f.points}</span>
          </div>
        `).join('')}
      </div>

      <div style="
        background: rgba(255,255,255,0.05); border-radius: 8px; padding: 10px;
        font-size: 12px; color: #ccc; line-height: 1.5;
      ">
        ${isDanger
      ? '🚫 <strong>Do NOT click any links</strong> or download attachments in this email. Do not reply with personal information.'
      : '⚠️ <strong>Be cautious</strong> with this email. Verify the sender before clicking links or sharing information.'
    }
      </div>
    </div>
  `;

  document.documentElement.appendChild(warning);

  // Auto-dismiss after 15 seconds for medium, stay for high/critical
  if (!isDanger) {
    setTimeout(() => {
      const el = document.getElementById('phishguard-email-warning');
      if (el) el.style.transition = 'opacity 0.5s', el.style.opacity = '0',
        setTimeout(() => el.remove(), 500);
    }, 15000);
  }
}

// Simple hash to track scanned emails
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < Math.min(str.length, 500); i++) {
    const chr = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0;
  }
  return hash.toString();
}
