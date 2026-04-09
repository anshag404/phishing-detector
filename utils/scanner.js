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

        // 0. Check PhishTank database (highest priority)
        const phishTankMatch = checkPhishTank(url);
        if (phishTankMatch) {
            factors.push({ name: 'PhishTank Verified Threat', severity: 'high', points: 40, description: `This URL is listed in the PhishTank database as a verified phishing site (${phishTankMatch.matchType} match: ${phishTankMatch.target}).` });
            score += 40;
        }

        // Check if it's a known safe domain
        const isSafe = SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
        if (isSafe && !phishTankMatch) {
            factors.push({ name: 'Known Safe Domain', severity: 'safe', points: -20, description: 'This domain is recognized as a legitimate, well-known website.' });
            score -= 20;
        }

        // 1. Check for IP-based URL
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipPattern.test(hostname)) {
            factors.push({ name: 'IP-Based URL', severity: 'high', points: 25, description: 'URL uses an IP address instead of a domain name, commonly used in phishing attacks.' });
            score += 25;
        }

        // 2. Check for HTTP (no SSL)
        if (parsed.protocol === 'http:') {
            factors.push({ name: 'No SSL Certificate', severity: 'medium', points: 15, description: 'Website does not use HTTPS encryption. Legitimate sites typically use SSL certificates.' });
            score += 15;
        }

        // 3. Check for suspicious TLDs
        const tld = '.' + hostname.split('.').pop();
        if (SUSPICIOUS_TLDS.includes(tld)) {
            factors.push({ name: 'Suspicious Domain Extension', severity: 'medium', points: 15, description: `The domain uses "${tld}" which is frequently associated with phishing and spam websites.` });
            score += 15;
        }

        // 4. Check for URL shorteners
        if (URL_SHORTENERS.some(s => hostname.includes(s))) {
            factors.push({ name: 'URL Shortener Detected', severity: 'medium', points: 15, description: 'URL shorteners can hide the true destination of a link, commonly used in phishing.' });
            score += 15;
        }

        // 5. Check for excessive subdomains
        const subdomainCount = hostname.split('.').length - 2;
        if (subdomainCount > 2) {
            factors.push({ name: 'Excessive Subdomains', severity: 'medium', points: 12, description: `URL has ${subdomainCount} subdomains. Phishing sites often use many subdomains to appear legitimate.` });
            score += 12;
        }

        // 6. Check for phishing keywords in URL
        const foundKeywords = PHISHING_URL_KEYWORDS.filter(kw => fullUrl.includes(kw));
        if (foundKeywords.length > 0) {
            const pts = Math.min(foundKeywords.length * 5, 20);
            factors.push({ name: 'Suspicious Keywords in URL', severity: foundKeywords.length > 2 ? 'high' : 'medium', points: pts, description: `URL contains suspicious keywords: ${foundKeywords.join(', ')}. These are commonly used in phishing URLs.` });
            score += pts;
        }

        // 7. Check for typosquatting (character substitution)
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
            if (pattern.test(hostname) && !SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d))) {
                factors.push({ name: 'Possible Typosquatting', severity: 'high', points: 25, description: `Domain appears to impersonate ${brand} using slight character variations — a classic phishing technique.` });
                score += 25;
                break;
            }
        }

        // 8. Check for special characters in URL
        const specialChars = (fullUrl.match(/[@!#$%^&*()]/g) || []).length;
        if (specialChars > 0) {
            factors.push({ name: 'Special Characters in URL', severity: 'low', points: 8, description: 'URL contains unusual special characters that may be used to obfuscate the true destination.' });
            score += 8;
        }

        // 9. Check URL length
        if (fullUrl.length > 100) {
            factors.push({ name: 'Unusually Long URL', severity: 'low', points: 8, description: 'Very long URLs can be used to hide suspicious parameters and redirect targets.' });
            score += 8;
        }

        // 10. Check for double slashes in path
        if (parsed.pathname.includes('//')) {
            factors.push({ name: 'Double Slashes in Path', severity: 'low', points: 5, description: 'URL path contains double slashes which may indicate a redirect or obfuscation attempt.' });
            score += 5;
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
    if (score <= 20) return 'good';
    if (score <= 50) return 'average';
    return 'bad';
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
