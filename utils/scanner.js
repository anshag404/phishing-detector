/**
 * Phishing Detection Scanner Engine
 * Uses heuristic rules to analyze URLs, emails, and websites
 * Returns a 0-100 threat score with detailed breakdown
 */

// Known suspicious TLDs
const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.buzz', '.rest'];

// Known URL shortener domains
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly'];

// Phishing keywords commonly found in URLs
const PHISHING_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'netflix', 'support', 'helpdesk', 'wallet', 'crypto', 'password', 'credential'
];

// Urgency keywords in emails
const EMAIL_URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'suspended', 'unauthorized', 'verify your',
    'click here', 'act now', 'limited time', 'expire', 'locked',
    'unusual activity', 'confirm your identity', 'security alert',
    'your account', 'has been compromised', 'reset your password',
    'winning', 'congratulations', 'selected', 'prize', 'lottery'
];

// Known safe domains
const SAFE_DOMAINS = [
    'google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com', 'wikipedia.org',
    'stackoverflow.com', 'reddit.com', 'netflix.com', 'instagram.com'
];

// PhishTank integration
const { checkPhishTank } = require('./phishtank');

/**
 * Analyze a URL for phishing indicators
 */
function scanURL(url) {
    const factors = [];
    let score = 0;

    try {
        // Normalize URL
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'http://' + url;
        }
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        const fullUrl = url.toLowerCase();

        // 0. Check Threat Intelligence database (highest priority — confirmed threat)
        const phishTankMatch = checkPhishTank(url);
        if (phishTankMatch) {
            factors.push({ name: 'Threat Intelligence Match', severity: 'critical', points: 75, description: `This URL is listed in verified threat databases as a known phishing/malware site (${phishTankMatch.matchType} match: ${phishTankMatch.target}). This is a confirmed threat, not a heuristic guess.` });
            score += 75;
        }

        // Check if it's a known safe domain
        const isSafe = SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
        if (isSafe && !phishTankMatch) {
            factors.push({ name: 'Known Safe Domain', severity: 'safe', points: -30, description: 'This domain is recognized as a legitimate, well-known website with established trust.' });
            score -= 30;
        }

        // 1. Check for IP-based URL (very strong indicator — legit sites almost never do this)
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipPattern.test(hostname)) {
            factors.push({ name: 'IP-Based URL', severity: 'high', points: 30, description: 'URL uses a raw IP address instead of a domain name. Legitimate websites almost never do this — it is a strong phishing/malware indicator.' });
            score += 30;
        }

        // 2. Check for HTTP (no SSL) — weak signal; many phishing sites now use HTTPS via Let's Encrypt
        if (parsed.protocol === 'http:') {
            factors.push({ name: 'No HTTPS Encryption', severity: 'low', points: 5, description: 'Website does not use HTTPS. Note: many phishing sites DO use HTTPS, so this alone is a weak indicator.' });
            score += 5;
        }

        // 3. Check for suspicious TLDs — moderate signal
        const tld = '.' + hostname.split('.').pop();
        if (SUSPICIOUS_TLDS.includes(tld)) {
            factors.push({ name: 'High-Risk Domain Extension', severity: 'medium', points: 10, description: `The domain uses "${tld}" which has a disproportionately high rate of abuse in phishing and malware campaigns.` });
            score += 10;
        }

        // 4. Check for URL shorteners — moderate signal (legit use exists)
        if (URL_SHORTENERS.some(s => hostname.includes(s))) {
            factors.push({ name: 'URL Shortener Detected', severity: 'medium', points: 10, description: 'URL shorteners mask the true destination. While used legitimately, they are also heavily abused in phishing campaigns.' });
            score += 10;
        }

        // 5. Check for excessive subdomains — strong signal when combined with others
        const subdomainCount = hostname.split('.').length - 2;
        if (subdomainCount > 2) {
            factors.push({ name: 'Excessive Subdomains', severity: 'medium', points: 15, description: `URL has ${subdomainCount} subdomains (e.g. secure.login.banking.evil.com). This is a common phishing technique to make URLs look legitimate.` });
            score += 15;
        }

        // 6. Check for phishing keywords in URL — weak signal alone (many legit URLs have "login")
        const foundKeywords = PHISHING_URL_KEYWORDS.filter(kw => fullUrl.includes(kw));
        if (foundKeywords.length > 0 && !isSafe) {
            const pts = Math.min(foundKeywords.length * 3, 15);
            factors.push({ name: 'Suspicious Keywords in URL', severity: foundKeywords.length > 3 ? 'medium' : 'low', points: pts, description: `URL contains trigger words: ${foundKeywords.join(', ')}. Alone this is a weak signal, but combined with other factors it increases suspicion.` });
            score += pts;
        }

        // 7. Check for typosquatting (character substitution) — one of the strongest indicators
        const typoPatterns = [
            { pattern: /paypa[l1]/i, brand: 'PayPal' },
            { pattern: /amaz[o0]n/i, brand: 'Amazon' },
            { pattern: /g[o0]{2}g[l1]e/i, brand: 'Google' },
            { pattern: /faceb[o0]{2}k/i, brand: 'Facebook' },
            { pattern: /app[l1]e/i, brand: 'Apple' },
            { pattern: /micr[o0]s[o0]ft/i, brand: 'Microsoft' },
            { pattern: /netf[l1]ix/i, brand: 'Netflix' },
            { pattern: /[1l]inkedin/i, brand: 'LinkedIn' },
            { pattern: /dropb[o0]x/i, brand: 'Dropbox' },
            { pattern: /wh[a4]ts[a4]pp/i, brand: 'WhatsApp' }
        ];

        for (const { pattern, brand } of typoPatterns) {
            if (pattern.test(hostname) && !isSafe) {
                factors.push({ name: 'Brand Impersonation (Typosquatting)', severity: 'high', points: 35, description: `Domain impersonates ${brand} using character substitution (e.g. "l" → "1", "o" → "0"). This is a classic and highly effective phishing technique.` });
                score += 35;
                break;
            }
        }

        // 8. Check for @ symbol in URL (credential spoofing: user@evil.com/fake-site)
        if (fullUrl.includes('@') && !fullUrl.startsWith('mailto:')) {
            factors.push({ name: 'URL Credential Spoofing', severity: 'high', points: 20, description: 'URL contains an "@" symbol, which can trick browsers into ignoring everything before it. This is a known phishing technique.' });
            score += 20;
        }

        // 9. Check URL length — weak signal
        if (fullUrl.length > 150) {
            factors.push({ name: 'Unusually Long URL', severity: 'low', points: 5, description: 'Extremely long URLs can hide malicious parameters in plain sight.' });
            score += 5;
        }

        // 10. Check for data: or javascript: in URL
        if (fullUrl.startsWith('data:') || fullUrl.startsWith('javascript:')) {
            factors.push({ name: 'Code Injection URL', severity: 'critical', points: 40, description: 'URL uses data: or javascript: protocol, which can execute arbitrary code. This is extremely dangerous.' });
            score += 40;
        }

    } catch (e) {
        factors.push({ name: 'Malformed URL', severity: 'high', points: 30, description: 'The URL is malformed and cannot be properly parsed, which is highly suspicious.' });
        score += 30;
    }

    score = Math.max(0, Math.min(100, score));
    return { score, factors, type: 'url' };
}

/**
 * Analyze email content for phishing indicators
 */
function scanEmail(content) {
    const factors = [];
    let score = 0;
    const lowerContent = content.toLowerCase();

    // 1. Check urgency keywords
    const foundUrgency = EMAIL_URGENCY_KEYWORDS.filter(kw => lowerContent.includes(kw));
    if (foundUrgency.length > 0) {
        const pts = Math.min(foundUrgency.length * 8, 45);
        factors.push({ name: 'Urgency Language Detected', severity: foundUrgency.length > 2 ? 'high' : 'medium', points: pts, description: `Email contains urgency phrases: "${foundUrgency.slice(0, 5).join('", "')}". Phishing emails often create a false sense of urgency.` });
        score += pts;
    }

    // 2. Check for suspicious links in content
    const urlPattern = /https?:\/\/[^\s<>"]+/gi;
    const urls = lowerContent.match(urlPattern) || [];
    if (urls.length > 0) {
        let suspiciousUrls = 0;
        urls.forEach(url => {
            const result = scanURL(url);
            if (result.score > 30) suspiciousUrls++;
        });
        if (suspiciousUrls > 0) {
            factors.push({ name: 'Suspicious Links Found', severity: 'high', points: 20, description: `Email contains ${suspiciousUrls} suspicious link(s) that show signs of phishing.` });
            score += 20;
        }
    }

    // 3. Check for attachment mentions
    const attachmentKeywords = ['attachment', 'attached', 'download', 'open the file', 'see attached', '.exe', '.zip', '.scr', '.bat'];
    const foundAttachments = attachmentKeywords.filter(kw => lowerContent.includes(kw));
    if (foundAttachments.length > 0) {
        factors.push({ name: 'Suspicious Attachment References', severity: 'medium', points: 15, description: 'Email references file attachments which could contain malware or phishing content.' });
        score += 15;
    }

    // 4. Check for requests for personal info
    const personalInfoKeywords = ['social security', 'ssn', 'credit card', 'bank account', 'routing number', 'pin number', 'date of birth', 'mother\'s maiden'];
    const foundPersonal = personalInfoKeywords.filter(kw => lowerContent.includes(kw));
    if (foundPersonal.length > 0) {
        factors.push({ name: 'Personal Information Request', severity: 'high', points: 25, description: 'Email requests sensitive personal information. Legitimate organizations rarely request such details via email.' });
        score += 25;
    }

    // 5. Check for poor grammar indicators
    const grammarIssues = ['kindly', 'dear customer', 'dear user', 'dear sir/madam', 'esteemed', 'beneficiary'];
    const foundGrammar = grammarIssues.filter(kw => lowerContent.includes(kw));
    if (foundGrammar.length > 0) {
        factors.push({ name: 'Generic/Unusual Greeting', severity: 'low', points: 10, description: 'Email uses generic or overly formal language commonly seen in phishing attempts.' });
        score += 10;
    }

    // 6. Check for threat language
    const threatKeywords = ['will be closed', 'will be suspended', 'legal action', 'law enforcement', 'criminal', 'terminate', 'compromised', 'hacked', 'breached', 'stolen'];
    const foundThreats = threatKeywords.filter(kw => lowerContent.includes(kw));
    if (foundThreats.length > 0) {
        const tpts = Math.min(foundThreats.length * 15, 25);
        factors.push({ name: 'Threatening Language', severity: 'high', points: tpts, description: `Email contains alarming phrases: "${foundThreats.join('", "')}". This language is used to pressure victims into hasty action.` });
        score += tpts;
    }

    // 6b. Check for call-to-action manipulation
    const ctaKeywords = ['click here', 'click below', 'click the link', 'follow the link', 'tap here', 'open this', 'verify now', 'confirm now', 'act immediately'];
    const foundCTA = ctaKeywords.filter(kw => lowerContent.includes(kw));
    if (foundCTA.length > 0) {
        factors.push({ name: 'Manipulative Call-to-Action', severity: 'high', points: 15, description: 'Email uses direct calls to action like "click here" to pressure you into interacting with potentially malicious content.' });
        score += 15;
    }

    // 7. Short content with link
    if (lowerContent.length < 200 && urls.length > 0) {
        factors.push({ name: 'Minimal Content with Link', severity: 'medium', points: 10, description: 'Email has very little text but includes a link — phishing emails are often brief to avoid detection.' });
        score += 10;
    }

    if (factors.length === 0) {
        factors.push({ name: 'No Obvious Threats', severity: 'safe', points: 0, description: 'No obvious phishing indicators were detected in this email content.' });
    }

    score = Math.max(0, Math.min(100, score));
    return { score, factors, type: 'email' };
}

/**
 * Analyze a website/domain
 */
function scanWebsite(domain) {
    // Normalize
    domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

    const factors = [];
    let score = 0;

    // Check if it's a known safe domain
    if (SAFE_DOMAINS.includes(domain)) {
        factors.push({ name: 'Verified Safe Domain', severity: 'safe', points: -30, description: 'This is a well-known, trusted website.' });
        score -= 30;
    }

    // Run URL scan on the domain
    const urlResult = scanURL('https://' + domain);
    factors.push(...urlResult.factors);
    score += urlResult.score;

    // Additional domain-specific checks
    // 1. Domain age simulation (based on TLD and complexity)
    const parts = domain.split('.');
    if (parts.length > 3) {
        factors.push({ name: 'Complex Domain Structure', severity: 'medium', points: 10, description: 'Domain has an unusually complex structure with multiple levels, common in phishing sites.' });
        score += 10;
    }

    // 2. Check for hyphens in domain
    const dashCount = (domain.match(/-/g) || []).length;
    if (dashCount > 2) {
        factors.push({ name: 'Excessive Hyphens', severity: 'medium', points: 10, description: 'Domain contains multiple hyphens, which is unusual for legitimate websites.' });
        score += 10;
    }

    // 3. Check for numbers in domain name
    const mainDomain = parts[parts.length - 2] || '';
    if (/\d{3,}/.test(mainDomain)) {
        factors.push({ name: 'Numbers in Domain Name', severity: 'low', points: 8, description: 'Domain name contains multiple consecutive numbers, which can indicate an auto-generated phishing domain.' });
        score += 8;
    }

    score = Math.max(0, Math.min(100, score));
    return { score, factors, type: 'website' };
}

/**
 * Get risk level based on score
 */
function getRiskLevel(score) {
    if (score <= 10) return 'safe';       // Clean — no indicators
    if (score <= 25) return 'low';        // 1-2 weak signals — probably fine
    if (score <= 50) return 'medium';     // Strong heuristic — be careful
    if (score <= 75) return 'high';       // Multiple strong signals — likely threat
    return 'critical';                    // Confirmed threat — do NOT interact
}

/**
 * Generate safety recommendations based on scan results
 */
function getRecommendations(score, factors, type) {
    const riskLevel = getRiskLevel(score);
    const recommendations = [];

    if (riskLevel === 'good') {
        recommendations.push({
            title: 'Stay Vigilant',
            priority: 'optional',
            description: 'While this appears safe, always remain cautious. Bookmark trusted sites and verify URLs before entering credentials.',
            icon: '✅'
        });
        return recommendations;
    }

    // Critical recommendations for bad score
    if (riskLevel === 'bad') {
        recommendations.push({
            title: 'Do NOT Enter Any Personal Information',
            priority: 'critical',
            description: 'This target shows strong phishing indicators. Never enter passwords, credit card numbers, or personal data on suspicious sites.',
            icon: '🚫'
        });
        recommendations.push({
            title: 'Change Your Passwords Immediately',
            priority: 'critical',
            description: 'If you have already interacted with this target, change your passwords on all related accounts right away. Use a password manager to generate strong, unique passwords.',
            icon: '🔑'
        });
        recommendations.push({
            title: 'Enable Two-Factor Authentication (2FA)',
            priority: 'critical',
            description: 'Enable 2FA on all your important accounts (email, banking, social media). This adds an extra layer of security even if your password is compromised.',
            icon: '🔐'
        });
        recommendations.push({
            title: 'Report This Phishing Attempt',
            priority: 'critical',
            description: 'Report this to: Google Safe Browsing (safebrowsing.google.com), PhishTank (phishtank.org), or your IT security team. You can also forward phishing emails to reportphishing@apwg.org.',
            icon: '🚨'
        });
    }

    // Recommendations for both average and bad
    recommendations.push({
        title: 'Update Your Browser & Enable Phishing Protection',
        priority: 'recommended',
        description: 'Ensure your browser is up to date. Enable built-in phishing protection: Chrome (Safe Browsing), Firefox (Deceptive Content Protection), Edge (SmartScreen).',
        icon: '🌐'
    });
    recommendations.push({
        title: 'Install Anti-Phishing Browser Extension',
        priority: 'recommended',
        description: 'Install a trusted anti-phishing extension such as uBlock Origin, Netcraft Extension, or Bitdefender TrafficLight to get real-time phishing warnings.',
        icon: '🧩'
    });
    recommendations.push({
        title: 'Enable Email Spam Filters',
        priority: 'recommended',
        description: 'Enable advanced spam filtering. For organizations, implement DMARC, SPF, and DKIM email authentication to prevent email spoofing.',
        icon: '📧'
    });
    recommendations.push({
        title: 'Block Suspicious Domains at DNS Level',
        priority: 'recommended',
        description: 'Use a secure DNS provider like Cloudflare (1.1.1.2) or Quad9 (9.9.9.9) that blocks known malicious domains automatically.',
        icon: '🛡️'
    });

    // Type-specific recommendations
    if (type === 'email') {
        recommendations.push({
            title: 'Verify Sender Identity',
            priority: 'recommended',
            description: 'Check the actual sender email address (not just the display name). Contact the supposed sender through official channels to verify the email is legitimate.',
            icon: '🔍'
        });
        recommendations.push({
            title: 'Never Download Unexpected Attachments',
            priority: 'recommended',
            description: 'Do not open attachments from unknown or unexpected emails. Scan any downloaded files with antivirus software before opening.',
            icon: '📎'
        });
    }

    if (type === 'url' || type === 'website') {
        recommendations.push({
            title: 'Verify the Website SSL Certificate',
            priority: 'recommended',
            description: 'Click the padlock icon in your browser address bar to check if the SSL certificate is valid and issued to the expected organization.',
            icon: '🔒'
        });
    }

    // System hardening for bad
    if (riskLevel === 'bad') {
        recommendations.push({
            title: 'Run a Full System Antivirus Scan',
            priority: 'critical',
            description: 'Run a complete system scan with updated antivirus software. If you interacted with the phishing content, malware may have been installed.',
            icon: '🖥️'
        });
        recommendations.push({
            title: 'Disable Macros in Office Applications',
            priority: 'recommended',
            description: 'Disable macros in Microsoft Office (File > Options > Trust Center). Phishing attacks often use malicious macros in documents.',
            icon: '📄'
        });
        recommendations.push({
            title: 'Update Your Operating System',
            priority: 'recommended',
            description: 'Ensure your OS has the latest security patches installed. Phishing attacks often exploit known vulnerabilities in outdated systems.',
            icon: '⬆️'
        });
        recommendations.push({
            title: 'Monitor Your Financial Accounts',
            priority: 'critical',
            description: 'Check your bank and credit card statements for unauthorized transactions. Consider placing a fraud alert on your credit reports.',
            icon: '💳'
        });
    }

    return recommendations;
}

module.exports = {
    scanURL,
    scanEmail,
    scanWebsite,
    getRiskLevel,
    getRecommendations
};
