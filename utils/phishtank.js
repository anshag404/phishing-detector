/**
 * PhishTank Integration Module
 * Fetches the PhishTank database and checks URLs against known phishing entries.
 * 
 * PhishTank provides a free JSON feed of verified phishing URLs.
 * API docs: https://phishtank.org/developer_info.php
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const CACHE_FILE = path.join(__dirname, '..', 'phishtank_cache.json');
const CACHE_MAX_AGE_MS = 6 * 60 * 60 * 1000; // 6 hours

// PhishTank download URL (JSON format, gzipped)
// Using the community feed — no API key required for the online CSV/JSON
const PHISHTANK_URL = 'http://data.phishtank.com/data/online-valid.json.gz';
// Fallback: uncompressed
const PHISHTANK_URL_FALLBACK = 'http://data.phishtank.com/data/online-valid.json';

let phishTankDB = new Set();
let lastFetchTime = 0;
let isFetching = false;

/**
 * Make an HTTP/HTTPS GET request with proper headers
 * Returns raw Buffer body (handles gzip decompression automatically)
 */
function fetchURL(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const options = {
      headers: {
        'User-Agent': 'PhishGuard/1.0 (Phishing Detection System; +https://github.com/anshag404/phishing-detector)',
        'Accept': 'application/json, application/gzip, */*'
      },
      timeout: 60000
    };

    console.log(`[PhishTank] Fetching: ${url.substring(0, 80)}...`);

    const req = client.get(url, options, (res) => {
      console.log(`[PhishTank] HTTP ${res.statusCode} | Content-Type: ${res.headers['content-type'] || 'unknown'}`);

      // Handle redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        console.log(`[PhishTank] Redirecting...`);
        return fetchURL(res.headers.location).then(resolve).catch(reject);
      }

      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode} from PhishTank`));
      }

      // Collect raw binary data
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        let rawBuffer = Buffer.concat(chunks);
        console.log(`[PhishTank] Downloaded ${rawBuffer.length} bytes`);

        // Check if it's gzip compressed (magic bytes: 1f 8b)
        if (rawBuffer.length > 2 && rawBuffer[0] === 0x1f && rawBuffer[1] === 0x8b) {
          console.log(`[PhishTank] Detected gzip data, decompressing...`);
          try {
            rawBuffer = zlib.gunzipSync(rawBuffer);
            console.log(`[PhishTank] Decompressed to ${rawBuffer.length} bytes`);
          } catch (err) {
            console.log(`[PhishTank] Gzip decompress failed: ${err.message}`);
            return reject(err);
          }
        }

        const body = rawBuffer.toString('utf8');
        console.log(`[PhishTank] Response: ${body.length} chars`);
        resolve({ statusCode: res.statusCode, body });
      });
      res.on('error', reject);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out after 60s'));
    });

    req.on('error', reject);
  });
}

/**
 * Parse PhishTank JSON data and extract active phishing URLs
 */
function parsePhishTankData(jsonString) {
  const urls = new Set();

  try {
    const data = JSON.parse(jsonString);

    if (!Array.isArray(data)) {
      console.log(`[PhishTank] ⚠️ Unexpected data format: ${typeof data}`);
      // May be wrapped in an object
      if (data && data.data && Array.isArray(data.data)) {
        console.log(`[PhishTank] Found data.data array`);
        return parsePhishTankEntries(data.data);
      }
      return urls;
    }

    return parsePhishTankEntries(data);
  } catch (err) {
    console.error(`[PhishTank] ❌ JSON parse error: ${err.message}`);
    console.log(`[PhishTank] First 200 chars of response: ${jsonString.substring(0, 200)}`);
    return urls;
  }
}

function parsePhishTankEntries(entries) {
  const urls = new Set();
  let validCount = 0;

  for (const entry of entries) {
    // PhishTank JSON format has 'url' field
    // It may also have 'phish_detail_url', 'verified', 'online'
    const phishUrl = entry.url || entry.phish_url || entry.URL;
    if (!phishUrl) continue;

    // Only include verified/online entries
    const isVerified = entry.verified === 'yes' || entry.verified === true || entry.verified === 'y';
    const isOnline = entry.online === 'yes' || entry.online === true || entry.online === 'y' || !entry.hasOwnProperty('online');

    if (isVerified || isOnline || !entry.hasOwnProperty('verified')) {
      try {
        let normalized = phishUrl.toLowerCase().trim();
        if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
          normalized = 'http://' + normalized;
        }
        const parsed = new URL(normalized);
        const hostname = parsed.hostname;
        const pathPart = parsed.pathname.replace(/\/+$/, '');

        // Always store full path for precise matching
        if (pathPart && pathPart !== '') {
          urls.add(hostname + pathPart);
        }

        // Only store bare hostname if it's NOT a well-known hosting platform
        // (phishing pages are often hosted on legitimate services)
        const hostingPlatforms = [
          'google.com', 'sites.google.com', 'docs.google.com', 'forms.gle',
          'wixstudio.com', 'wixsite.com', 'wix.com',
          'framer.app', 'webflow.io', 'squarespace.com',
          'github.io', 'netlify.app', 'vercel.app', 'herokuapp.com',
          'blogspot.com', 'wordpress.com', 'weebly.com',
          'firebase.app', 'firebaseapp.com',
          'azurewebsites.net', 'cloudfront.net', 'amazonaws.com'
        ];
        const isHostingPlatform = hostingPlatforms.some(h => hostname === h || hostname.endsWith('.' + h));

        if (!isHostingPlatform) {
          urls.add(hostname);
        }

        validCount++;
      } catch (e) {
        // Skip malformed URLs
      }
    }
  }

  console.log(`[PhishTank] ✅ Parsed ${validCount} active phishing entries from ${entries.length} total`);

  // Log first 3 URLs for verification
  const sample = [...urls].slice(0, 6);
  console.log(`[PhishTank] 🔍 Sample entries:`);
  sample.forEach((u, i) => console.log(`  ${i + 1}. ${u}`));

  return urls;
}

/**
 * Load from cache if fresh enough
 */
function loadCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const stat = fs.statSync(CACHE_FILE);
      const age = Date.now() - stat.mtimeMs;

      if (age < CACHE_MAX_AGE_MS) {
        const cached = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
        if (cached.urls && Array.isArray(cached.urls)) {
          console.log(`[PhishTank] 📦 Loaded ${cached.urls.length} entries from cache (${Math.round(age / 60000)}m old)`);
          return new Set(cached.urls);
        }
      } else {
        console.log(`[PhishTank] ⏰ Cache expired (${Math.round(age / 3600000)}h old)`);
      }
    }
  } catch (err) {
    console.log(`[PhishTank] Cache read error: ${err.message}`);
  }
  return null;
}

/**
 * Save to cache
 */
function saveCache(urlSet) {
  try {
    const data = { urls: [...urlSet], timestamp: Date.now(), count: urlSet.size };
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data), 'utf8');
    console.log(`[PhishTank] 💾 Cached ${urlSet.size} entries`);
  } catch (err) {
    console.log(`[PhishTank] Cache write error: ${err.message}`);
  }
}

/**
 * Fetch and load the PhishTank database
 */
async function loadPhishTankDB() {
  if (isFetching) {
    console.log(`[PhishTank] Already fetching, skipping...`);
    return;
  }

  // Try cache first
  const cached = loadCache();
  if (cached) {
    phishTankDB = cached;
    lastFetchTime = Date.now();
    return;
  }

  isFetching = true;
  console.log(`[PhishTank] 🔄 Fetching PhishTank database...`);

  try {
    // Try gzipped first
    let response;
    try {
      response = await fetchURL(PHISHTANK_URL);
    } catch (err) {
      console.log(`[PhishTank] Gzip fetch failed (${err.message}), trying uncompressed...`);
      response = await fetchURL(PHISHTANK_URL_FALLBACK);
    }

    if (response.body.length < 100) {
      console.log(`[PhishTank] ⚠️ Response too short (${response.body.length} chars). Possibly blocked.`);
      console.log(`[PhishTank] Body preview: ${response.body.substring(0, 200)}`);
      isFetching = false;
      return;
    }

    const urls = parsePhishTankData(response.body);

    if (urls.size > 0) {
      phishTankDB = urls;
      lastFetchTime = Date.now();
      saveCache(urls);
      console.log(`[PhishTank] ✅ Database loaded: ${urls.size} entries`);
    } else {
      console.log(`[PhishTank] ⚠️ 0 entries parsed — check data format`);
    }
  } catch (err) {
    console.error(`[PhishTank] ❌ Fetch failed: ${err.message}`);
  }

  isFetching = false;
}

/**
 * Check if a URL is in the PhishTank database
 * @returns {object|null} - Match info if found, null if clean
 */
function checkPhishTank(url) {
  if (phishTankDB.size === 0) return null;

  try {
    let normalized = url.toLowerCase().trim();
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'http://' + normalized;
    }
    const parsed = new URL(normalized);
    const hostname = parsed.hostname;
    const fullPath = hostname + parsed.pathname.replace(/\/+$/, '');

    // Check exact path match first, then hostname
    if (phishTankDB.has(fullPath)) {
      return { matched: true, matchType: 'exact_path', target: fullPath };
    }
    if (phishTankDB.has(hostname)) {
      return { matched: true, matchType: 'domain', target: hostname };
    }
  } catch (e) {
    // Invalid URL
  }

  return null;
}

/**
 * Get PhishTank DB stats
 */
function getPhishTankStats() {
  return {
    loaded: phishTankDB.size > 0,
    entries: phishTankDB.size,
    lastFetch: lastFetchTime ? new Date(lastFetchTime).toISOString() : 'never',
    cacheAge: lastFetchTime ? Math.round((Date.now() - lastFetchTime) / 60000) + ' minutes' : 'N/A'
  };
}

module.exports = {
  loadPhishTankDB,
  checkPhishTank,
  getPhishTankStats
};
