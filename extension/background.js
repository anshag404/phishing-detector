/**
 * PhishGuard Background Service Worker
 * Scans every URL the user navigates to and shows notifications for threats
 */

// ---- Phishing Scanner Engine (same logic as server) ----
const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.buzz', '.rest'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly'];
const PHISHING_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'netflix', 'support', 'helpdesk', 'wallet', 'crypto', 'password', 'credential'
];
const SAFE_DOMAINS = [
    'google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com', 'wikipedia.org',
    'stackoverflow.com', 'reddit.com', 'netflix.com', 'instagram.com',
    'whatsapp.com', 'discord.com', 'slack.com', 'zoom.us', 'figma.com',
    'notion.so', 'trello.com', 'atlassian.com', 'gitlab.com', 'bitbucket.org',
    'mozilla.org', 'firefox.com', 'opera.com', 'brave.com', 'duckduckgo.com',
    'bing.com', 'yahoo.com', 'outlook.com', 'live.com', 'office.com',
    'dropbox.com', 'drive.google.com', 'docs.google.com', 'gmail.com',
    'chrome.google.com', 'extensions.google.com', 'web.whatsapp.com'
];

function scanURL(url) {
    const factors = [];
    let score = 0;

    try {
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'http://' + url;
        }
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        const fullUrl = url.toLowerCase();

        // Skip browser internal pages
        if (hostname === '' || hostname === 'localhost' || hostname.startsWith('127.') ||
            url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
            url.startsWith('edge://') || url.startsWith('about:') || url.startsWith('file:')) {
            return { score: 0, factors: [{ name: 'Internal Page', severity: 'safe', points: 0, description: 'Browser internal page.' }], type: 'url' };
        }

        // Check safe domains
        const isSafe = SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
        if (isSafe) {
            factors.push({ name: 'Known Safe Domain', severity: 'safe', points: -20, description: 'Recognized legitimate website.' });
            score -= 20;
        }

        // IP-based URL
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
            factors.push({ name: 'IP-Based URL', severity: 'high', points: 25, description: 'Uses an IP address instead of domain name.' });
            score += 25;
        }

        // No HTTPS
        if (parsed.protocol === 'http:') {
            factors.push({ name: 'No SSL Certificate', severity: 'medium', points: 15, description: 'No HTTPS encryption.' });
            score += 15;
        }

        // Suspicious TLD
        const tld = '.' + hostname.split('.').pop();
        if (SUSPICIOUS_TLDS.includes(tld)) {
            factors.push({ name: 'Suspicious TLD', severity: 'medium', points: 15, description: `Uses "${tld}" often linked to phishing.` });
            score += 15;
        }

        // URL shorteners
        if (URL_SHORTENERS.some(s => hostname.includes(s))) {
            factors.push({ name: 'URL Shortener', severity: 'medium', points: 15, description: 'Shorteners can hide true destinations.' });
            score += 15;
        }

        // Excessive subdomains
        const subdomainCount = hostname.split('.').length - 2;
        if (subdomainCount > 2) {
            factors.push({ name: 'Excessive Subdomains', severity: 'medium', points: 12, description: `Has ${subdomainCount} subdomains.` });
            score += 12;
        }

        // Phishing keywords
        const foundKeywords = PHISHING_URL_KEYWORDS.filter(kw => fullUrl.includes(kw));
        if (foundKeywords.length > 0 && !isSafe) {
            const pts = Math.min(foundKeywords.length * 5, 20);
            factors.push({ name: 'Suspicious Keywords', severity: foundKeywords.length > 2 ? 'high' : 'medium', points: pts, description: `Contains: ${foundKeywords.join(', ')}` });
            score += pts;
        }

        // Typosquatting
        const typoPatterns = [
            { pattern: /paypa[l1]/i, brand: 'PayPal' },
            { pattern: /amaz[o0]n/i, brand: 'Amazon' },
            { pattern: /g[o0]{2}g[l1]e/i, brand: 'Google' },
            { pattern: /faceb[o0]{2}k/i, brand: 'Facebook' },
            { pattern: /app[l1]e/i, brand: 'Apple' },
            { pattern: /micr[o0]s[o0]ft/i, brand: 'Microsoft' },
            { pattern: /netf[l1]ix/i, brand: 'Netflix' }
        ];
        for (const { pattern, brand } of typoPatterns) {
            if (pattern.test(hostname) && !isSafe) {
                factors.push({ name: 'Typosquatting', severity: 'high', points: 25, description: `May impersonate ${brand}.` });
                score += 25;
                break;
            }
        }

        // Special characters
        if (/[@!#$%^&*()]/.test(fullUrl)) {
            factors.push({ name: 'Special Characters', severity: 'low', points: 8, description: 'URL contains unusual characters.' });
            score += 8;
        }

        // Long URL
        if (fullUrl.length > 100) {
            factors.push({ name: 'Long URL', severity: 'low', points: 8, description: 'Unusually long URL.' });
            score += 8;
        }

    } catch (e) {
        factors.push({ name: 'Malformed URL', severity: 'high', points: 30, description: 'URL cannot be parsed.' });
        score += 30;
    }

    score = Math.max(0, Math.min(100, score));
    return { score, factors, type: 'url' };
}

function getRiskLevel(score) {
    if (score <= 20) return 'good';
    if (score <= 50) return 'average';
    return 'bad';
}

// ---- Scan History (stored in chrome.storage) ----
async function saveScanResult(url, result) {
    const data = await chrome.storage.local.get('scanHistory');
    const history = data.scanHistory || [];
    history.unshift({
        url, score: result.score, risk: getRiskLevel(result.score),
        factors: result.factors, timestamp: new Date().toISOString()
    });
    // Keep last 100 entries
    await chrome.storage.local.set({ scanHistory: history.slice(0, 100) });
}

// ---- Badge Color & Text ----
function updateBadge(tabId, score) {
    const risk = getRiskLevel(score);
    let color, text;
    if (risk === 'good') {
        color = '#00e676'; text = '✓';
    } else if (risk === 'average') {
        color = '#ffc107'; text = '⚠';
    } else {
        color = '#ff1744'; text = '⛔';
    }
    chrome.action.setBadgeBackgroundColor({ color, tabId });
    chrome.action.setBadgeText({ text, tabId });
}

// ---- Notifications ----
function showThreatNotification(url, score, risk) {
    const hostname = new URL(url).hostname;
    let message, iconPath;
    if (risk === 'bad') {
        message = `🚨 DANGER! "${hostname}" scored ${score}/100 threat level. This site shows strong phishing indicators. Do NOT enter any personal information!`;
    } else {
        message = `⚠️ CAUTION: "${hostname}" scored ${score}/100 threat level. Some suspicious indicators detected. Proceed with care.`;
    }

    chrome.notifications.create('phishguard-' + Date.now(), {
        type: 'basic',
        iconUrl: 'icons/icon128.svg',
        title: risk === 'bad' ? '🛡️ PhishGuard — DANGER!' : '🛡️ PhishGuard — Warning',
        message: message,
        priority: risk === 'bad' ? 2 : 1,
        requireInteraction: risk === 'bad'
    });
}

// ---- Main: Listen for tab navigation ----
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Skip non-http URLs
        if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) return;

        const result = scanURL(tab.url);
        const risk = getRiskLevel(result.score);

        // Update badge
        updateBadge(tabId, result.score);

        // Save to history
        saveScanResult(tab.url, result);

        // Store current scan for popup
        chrome.storage.local.set({
            ['currentScan_' + tabId]: {
                url: tab.url, score: result.score, risk, factors: result.factors
            }
        });

        // Show notification for average and bad
        if (risk === 'average' || risk === 'bad') {
            showThreatNotification(tab.url, result.score, risk);
        }

        // Send result to content script
        chrome.tabs.sendMessage(tabId, {
            type: 'SCAN_RESULT', score: result.score, risk, factors: result.factors
        }).catch(() => { });
    }
});

// Listen for messages from popup and content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_CURRENT_SCAN') {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            if (tabs[0]) {
                const data = await chrome.storage.local.get('currentScan_' + tabs[0].id);
                sendResponse(data['currentScan_' + tabs[0].id] || null);
            } else {
                sendResponse(null);
            }
        });
        return true;
    }
    if (message.type === 'GET_HISTORY') {
        chrome.storage.local.get('scanHistory', (data) => {
            sendResponse(data.scanHistory || []);
        });
        return true;
    }

    // ---- EMAIL SCANNING ----
    if (message.type === 'SCAN_EMAIL') {
        const result = scanEmailContent(message.content);
        const risk = getRiskLevel(result.score);

        // Save to history
        const data = chrome.storage.local.get('scanHistory');
        data.then(d => {
            const history = d.scanHistory || [];
            history.unshift({
                url: `📧 Email (${message.source})`,
                score: result.score, risk,
                factors: result.factors,
                timestamp: new Date().toISOString()
            });
            chrome.storage.local.set({ scanHistory: history.slice(0, 100) });
        });

        // Show notification for threats
        if (risk === 'average' || risk === 'bad') {
            showEmailNotification(result.score, risk, message.source);
        }

        sendResponse({ score: result.score, risk, factors: result.factors });
        return true;
    }
});

// ===============================================================
// EMAIL PHISHING SCANNER ENGINE
// ===============================================================

const EMAIL_URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'suspended', 'unauthorized', 'verify your',
    'click here', 'act now', 'limited time', 'expire', 'locked',
    'unusual activity', 'confirm your identity', 'security alert',
    'your account', 'has been compromised', 'reset your password',
    'winning', 'congratulations', 'selected', 'prize', 'lottery'
];

const EMAIL_THREAT_KEYWORDS = [
    'will be closed', 'will be suspended', 'legal action', 'law enforcement',
    'criminal', 'terminate', 'compromised', 'hacked', 'breached', 'stolen'
];

const EMAIL_CTA_KEYWORDS = [
    'click here', 'click below', 'click the link', 'follow the link',
    'tap here', 'open this', 'verify now', 'confirm now', 'act immediately'
];

const PERSONAL_INFO_KEYWORDS = [
    'social security', 'ssn', 'credit card', 'bank account',
    'routing number', 'pin number', 'date of birth', "mother's maiden"
];

function scanEmailContent(content) {
    const factors = [];
    let score = 0;
    const lower = content.toLowerCase();

    // 1. Urgency keywords
    const foundUrgency = EMAIL_URGENCY_KEYWORDS.filter(kw => lower.includes(kw));
    if (foundUrgency.length > 0) {
        const pts = Math.min(foundUrgency.length * 8, 45);
        factors.push({
            name: 'Urgency Language',
            severity: foundUrgency.length > 2 ? 'high' : 'medium',
            points: pts,
            description: `Contains: "${foundUrgency.slice(0, 4).join('", "')}"`
        });
        score += pts;
    }

    // 2. Threat language
    const foundThreats = EMAIL_THREAT_KEYWORDS.filter(kw => lower.includes(kw));
    if (foundThreats.length > 0) {
        const pts = Math.min(foundThreats.length * 15, 25);
        factors.push({
            name: 'Threatening Language',
            severity: 'high',
            points: pts,
            description: `Contains: "${foundThreats.join('", "')}"`
        });
        score += pts;
    }

    // 3. Call-to-action manipulation
    const foundCTA = EMAIL_CTA_KEYWORDS.filter(kw => lower.includes(kw));
    if (foundCTA.length > 0) {
        factors.push({
            name: 'Manipulative Call-to-Action',
            severity: 'high',
            points: 15,
            description: 'Uses direct calls to action like "click here"'
        });
        score += 15;
    }

    // 4. Personal info requests
    const foundPersonal = PERSONAL_INFO_KEYWORDS.filter(kw => lower.includes(kw));
    if (foundPersonal.length > 0) {
        factors.push({
            name: 'Personal Info Request',
            severity: 'high',
            points: 25,
            description: 'Requests sensitive personal information'
        });
        score += 25;
    }

    // 5. Suspicious links in email
    const urlMatches = content.match(/https?:\/\/[^\s<>"]+/gi) || [];
    if (urlMatches.length > 0) {
        let suspiciousUrls = 0;
        urlMatches.forEach(url => {
            const urlResult = scanURL(url);
            if (urlResult.score > 20) suspiciousUrls++;
        });
        if (suspiciousUrls > 0) {
            factors.push({
                name: 'Suspicious Links',
                severity: 'high',
                points: 20,
                description: `Contains ${suspiciousUrls} suspicious link(s)`
            });
            score += 20;
        }
    }

    // 6. Generic greetings
    const genericGreetings = ['dear customer', 'dear user', 'dear sir/madam', 'dear account holder', 'valued customer'];
    if (genericGreetings.some(g => lower.includes(g))) {
        factors.push({
            name: 'Generic Greeting',
            severity: 'low',
            points: 10,
            description: 'Uses generic greeting instead of your name'
        });
        score += 10;
    }

    // 7. Attachment mentions
    const attachmentWords = ['attachment', 'attached', 'download', '.exe', '.zip', '.scr', '.bat'];
    if (attachmentWords.some(w => lower.includes(w))) {
        factors.push({
            name: 'Suspicious Attachments',
            severity: 'medium',
            points: 12,
            description: 'References file attachments or downloads'
        });
        score += 12;
    }

    if (factors.length === 0) {
        factors.push({
            name: 'No Threats Found',
            severity: 'safe',
            points: 0,
            description: 'No phishing indicators detected'
        });
    }

    score = Math.max(0, Math.min(100, score));
    return { score, factors, type: 'email' };
}

function showEmailNotification(score, risk, source) {
    const message = risk === 'bad'
        ? `🚨 PHISHING EMAIL DETECTED in ${source}! Threat score: ${score}/100. Do NOT click any links or download attachments!`
        : `⚠️ Suspicious email detected in ${source}. Threat score: ${score}/100. Verify the sender before taking any action.`;

    chrome.notifications.create('phishguard-email-' + Date.now(), {
        type: 'basic',
        iconUrl: 'icons/icon128.svg',
        title: risk === 'bad' ? '🛡️ PhishGuard — PHISHING EMAIL!' : '🛡️ PhishGuard — Suspicious Email',
        message: message,
        priority: 2,
        requireInteraction: risk === 'bad'
    });
}

console.log('🛡️ PhishGuard Extension loaded — URL + Email scanning active');

