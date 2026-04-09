# 🛡️ PhishGuard — Real-Time Phishing Detection System

A full-stack cybersecurity platform and Chrome extension that detects phishing threats in real-time using heuristic analysis and live threat intelligence from **95,000+** verified sources.

![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.x-000000?logo=express&logoColor=white)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension_MV3-4285F4?logo=googlechrome&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## ✨ Features

### 🌐 Web Application
- **URL Scanner** — Paste any URL to get a 0–100 threat score with detailed breakdown
- **Email Scanner** — Analyze email content for phishing indicators (urgency language, suspicious links, personal info requests)
- **Website Scanner** — Full website analysis with multiple heuristic checks
- **Bulk Scanner** — Scan multiple URLs at once
- **Threat Report** — Animated gauge, factor-by-factor breakdown, and tailored safety recommendations
- **User Authentication** — Email/password, Google OAuth, GitHub OAuth

### 🧩 Chrome Extension
- **Background Scanning** — Automatically scans every page you visit
- **Email Monitoring** — Reads and scans emails in Gmail, Outlook, and Yahoo Mail in real-time
- **Popup Dashboard** — Click the extension icon to see the current site's threat score
- **Warning Banners** — Red/yellow banners injected at the top of dangerous pages
- **Desktop Notifications** — Instant alerts for phishing threats
- **Scan History** — Tracks your last 100 scanned sites

### 📡 Threat Intelligence Pipeline
- **4 live threat feeds** aggregated into a unified database:

| Feed | Type | Entries |
|------|------|---------|
| [PhishTank](https://phishtank.org) | Verified phishing URLs | ~56,000 |
| [OpenPhish](https://openphish.com) | Community phishing feed | ~300 |
| [URLhaus Recent](https://urlhaus.abuse.ch) | Malware distribution URLs | ~30,000 |
| [URLhaus Online](https://urlhaus.abuse.ch) | Currently online threats | ~13,000 |

- **Hardened ingestion** — Handles HTTP 403/429/503, Cloudflare blocks, gzip compression, multi-step redirects
- **Defanged URL support** — Automatically converts `hxxp://`, `[.]`, `[dot]` back to real URLs
- **Smart caching** — 4-hour local cache to minimize API calls
- **False positive prevention** — Hosting platforms (Google, GitHub, Wix, Vercel, etc.) excluded from bare-domain matching

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org) v18 or later
- [Git](https://git-scm.com)

### Installation

```bash
# Clone the repository
git clone https://github.com/anshag404/phishing-detector.git
cd phishing-detector

# Install dependencies
npm install

# Create environment file
cp .env.example .env
# Edit .env with your OAuth credentials (optional)

# Start the server
node server.js
```

Open **http://localhost:3000** in your browser.

### Chrome Extension Setup

1. Open `chrome://extensions/` in Chrome
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. The 🛡️ shield icon appears in your toolbar — you're protected!

---

## 🏗️ Project Structure

```
phishing-detector/
├── server.js                 # Express server entry point
├── database.js               # JSON file database (users, scans)
├── routes/
│   ├── auth.js               # Authentication (email, Google, GitHub OAuth)
│   └── scan.js               # Scan API endpoints
├── utils/
│   ├── scanner.js            # Heuristic phishing detection engine
│   └── phishtank.js          # Multi-feed threat intelligence aggregator
├── middleware/
│   └── auth.js               # Session authentication middleware
├── public/
│   ├── index.html            # Landing page with auth forms
│   ├── dashboard.html        # Scan dashboard
│   ├── report.html           # Threat analysis report
│   ├── css/style.css         # Cybersecurity-themed dark UI
│   └── js/
│       ├── auth.js           # Frontend auth logic
│       ├── dashboard.js      # Dashboard functionality
│       └── report.js         # Report visualization
├── extension/
│   ├── manifest.json         # Chrome Extension Manifest V3
│   ├── background.js         # Service worker (URL + email scanning)
│   ├── content.js            # Page injection (banners, email reading)
│   ├── popup.html/css/js     # Extension popup UI
│   └── icons/                # Extension icons
└── test-phishtank.js         # Pipeline integration tests
```

---

## 🔍 Detection Engine

The scanner uses a **multi-layered approach**:

### Layer 1: Threat Database Lookup (+75 points)
Checks URLs against 95,000+ verified phishing/malware entries from live threat feeds. A match here is a **confirmed threat**, not a heuristic guess.

### Layer 2: Heuristic Analysis (0–50 points)
| Check | Points | Severity | Real-World Rationale |
|-------|--------|----------|---------------------|
| Brand Impersonation (Typosquatting) | +35 | High | Strongest heuristic — `paypa1.com` impersonating PayPal |
| IP-based URL | +30 | High | Legit sites never use raw IPs (`192.168.1.1/login`) |
| URL Credential Spoofing (`@`) | +20 | High | `http://google.com@evil.com` tricks browsers |
| Excessive subdomains | +15 | Medium | `secure.login.banking.evil.com` |
| High-risk TLD | +10 | Medium | `.tk`, `.xyz`, `.top` — disproportionate abuse rates |
| URL shortener | +10 | Medium | `bit.ly` hides true destination |
| Suspicious keywords | +3–15 | Low | "login", "verify" — weak alone, strong combined |
| No HTTPS | +5 | Low | Weak — phishing sites use Let's Encrypt too |
| Long URL (150+ chars) | +5 | Low | Can hide malicious params |
| Code injection URL | +40 | Critical | `javascript:` or `data:` protocol |
| Known safe domain | -30 | Safe | Google, GitHub, Microsoft, etc. |

### Layer 3: Email Content Analysis
| Check | Points | Description |
|-------|--------|-------------|
| Urgency language | +8–45 | "act now", "suspended", "verify" |
| Threatening language | +15–25 | "legal action", "compromised" |
| Call-to-action | +15 | "click here", "verify now" |
| Personal info request | +25 | SSN, credit card, bank account |
| Suspicious links | +20 | Links that fail URL analysis |
| Generic greeting | +10 | "Dear customer" instead of name |
| Attachment mentions | +12 | `.exe`, `.zip`, download links |

### Risk Levels
| Score | Level | What It Means |
|-------|-------|---------------|
| 0–15 | 🟢 **Safe** | No meaningful threat indicators detected |
| 16–40 | 🟡 **Suspicious** | Multiple weak signals or one strong heuristic signal — proceed with caution |
| 41–100 | 🔴 **Dangerous** | Confirmed threat intelligence match or multiple strong indicators — do not interact |

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory:

```env
PORT=3000
SESSION_SECRET=your-secret-key

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth (optional)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

---

## 🧪 Testing

```bash
# Run the threat feed pipeline test
node test-phishtank.js
```

This tests:
- ✅ Defanged URL normalization (5 test cases)
- ✅ All 4 threat feed connections
- ✅ Safe URL false-positive verification
- ✅ End-to-end detection of known threats

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Node.js, Express |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Database | JSON file storage |
| Auth | bcryptjs, express-session, OAuth 2.0 |
| Extension | Chrome Extension Manifest V3 |
| Threat Intel | PhishTank, OpenPhish, URLhaus |

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

**Ansh Agarwal** — [@anshag404](https://github.com/anshag404)

---
