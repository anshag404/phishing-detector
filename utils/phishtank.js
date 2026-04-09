/**
 * Threat Feed Aggregator — Hardened Data Ingestion Pipeline
 * 
 * Pulls phishing URLs from multiple external threat feeds, normalizes them,
 * and feeds them into the detection engine. Handles:
 *   - Multiple feed formats (JSON, CSV, plain text, defanged URLs)
 *   - HTTP error handling (403, 429, Cloudflare blocks)
 *   - Gzip decompression (magic byte detection)
 *   - Defanged URL normalization (hxxp://, [.], etc.)
 *   - Payload inspection and verbose debug logging
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const CACHE_DIR = path.join(__dirname, '..', 'feed_cache');
const CACHE_MAX_AGE_MS = 4 * 60 * 60 * 1000; // 4 hours

// ================================================================
// FEED REGISTRY — all external threat intelligence sources
// ================================================================
const FEEDS = [
  {
    id: 'phishtank',
    name: 'PhishTank Verified Online',
    url: 'http://data.phishtank.com/data/online-valid.json.gz',
    fallbackUrl: 'http://data.phishtank.com/data/online-valid.json',
    format: 'json',
    jsonPath: null,        // root is array
    urlField: 'url',       // field name containing the URL
    filterFn: (entry) => true, // accept all (already filtered as "online-valid")
  },
  {
    id: 'openphish',
    name: 'OpenPhish Community Feed',
    url: 'https://openphish.com/feed.txt',
    format: 'text',        // one URL per line
  },
  {
    id: 'urlhaus_recent',
    name: 'URLhaus Recent URLs (abuse.ch)',
    url: 'https://urlhaus.abuse.ch/downloads/text_recent/',
    format: 'text',
  },
  {
    id: 'urlhaus_online',
    name: 'URLhaus Online URLs (abuse.ch)',
    url: 'https://urlhaus.abuse.ch/downloads/text_online/',
    format: 'text',
  },

];

// ================================================================
// GLOBAL THREAT DB
// ================================================================
let threatDB = new Set();
let feedStats = {};
let lastLoadTime = 0;
let isLoading = false;

// ================================================================
// HARDENED HTTP FETCHER
// ================================================================

/**
 * Fetch a URL with full error handling, redirect support, gzip detection.
 * Uses a realistic browser User-Agent to avoid bot blocks.
 */
function fetchFeed(url, feedName) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const options = {
      headers: {
        // Realistic browser User-Agent to bypass bot filters
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/json,text/plain,text/csv,*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',   // don't ask for gzip encoding (we handle file-level gzip ourselves)
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
      },
      timeout: 45000,
    };

    console.log(`[${feedName}] FETCH: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`);

    const req = client.get(url, options, (res) => {
      const status = res.statusCode;
      const contentType = res.headers['content-type'] || 'unknown';

      console.log(`[${feedName}] STATUS: ${status} | Content-Type: ${contentType}`);

      // ---- EXPLICIT STATUS CODE HANDLING ----
      if (status >= 300 && status < 400 && res.headers.location) {
        console.log(`[${feedName}] REDIRECT -> following...`);
        res.resume(); // drain response
        return fetchFeed(res.headers.location, feedName).then(resolve).catch(reject);
      }

      if (status === 403) {
        res.resume();
        return reject(new Error(`❌ 403 FORBIDDEN — ${feedName} is blocking our request. The server rejected our User-Agent or IP.`));
      }

      if (status === 429) {
        res.resume();
        return reject(new Error(`❌ 429 TOO MANY REQUESTS — ${feedName} rate-limited us. Try again later.`));
      }

      if (status === 503) {
        res.resume();
        return reject(new Error(`❌ 503 SERVICE UNAVAILABLE — ${feedName} may be behind Cloudflare or under maintenance.`));
      }

      if (status !== 200) {
        res.resume();
        return reject(new Error(`❌ HTTP ${status} — unexpected status from ${feedName}`));
      }

      // ---- COLLECT RAW BINARY DATA ----
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        let rawBuffer = Buffer.concat(chunks);
        console.log(`[${feedName}] DOWNLOADED: ${rawBuffer.length} bytes`);

        // ---- GZIP DETECTION BY MAGIC BYTES (0x1f 0x8b) ----
        if (rawBuffer.length > 2 && rawBuffer[0] === 0x1f && rawBuffer[1] === 0x8b) {
          console.log(`[${feedName}] GZIP detected (magic bytes), decompressing...`);
          try {
            rawBuffer = zlib.gunzipSync(rawBuffer);
            console.log(`[${feedName}] DECOMPRESSED: ${rawBuffer.length} bytes`);
          } catch (err) {
            return reject(new Error(`Gzip decompression failed: ${err.message}`));
          }
        }

        const body = rawBuffer.toString('utf8');

        // ---- RAW PAYLOAD INSPECTION (first 500 chars) ----
        console.log(`[${feedName}] PAYLOAD PREVIEW (first 500 chars):`);
        console.log(`---START---`);
        console.log(body.substring(0, 500));
        console.log(`---END---`);

        // ---- CHECK FOR CLOUDFLARE / CAPTCHA HTML BLOCK ----
        if (body.includes('Checking your browser') || body.includes('cf-browser-verification') || body.includes('Just a moment...')) {
          return reject(new Error(`❌ CLOUDFLARE BLOCK — ${feedName} returned a Cloudflare CAPTCHA page, not data.`));
        }

        if (body.includes('<html') && !body.includes('"url"') && body.length < 5000) {
          console.log(`[${feedName}] ⚠️ WARNING: Response looks like HTML, not data. Possible error page.`);
        }

        resolve({ body, contentType });
      });
      res.on('error', reject);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`❌ TIMEOUT — ${feedName} did not respond within 45 seconds.`));
    });

    req.on('error', (err) => {
      reject(new Error(`❌ NETWORK ERROR — ${feedName}: ${err.message}`));
    });
  });
}

// ================================================================
// URL DEFANGING / NORMALIZATION
// ================================================================

/**
 * Convert defanged URLs back to usable format and normalize.
 * Handles: hxxp://, hXXp://, [.], [dot], [:]
 */
function defangToUrl(raw) {
  let url = raw.trim();

  // Remove surrounding quotes, brackets, angle brackets
  url = url.replace(/^["'<\[]+|["'>\]]+$/g, '');

  // Defanged protocol: hxxp:// → http://, hxxps:// → https://
  url = url.replace(/^hxxps?:\/\//i, (match) => {
    return match.toLowerCase().replace('hxxps', 'https').replace('hxxp', 'http');
  });

  // Defanged dots: [.] or [dot] → .
  url = url.replace(/\[dot\]/gi, '.').replace(/\[\.\]/g, '.');

  // Defanged colon: [:] → :
  url = url.replace(/\[:\]/g, ':');

  // Defanged @: [@] → @
  url = url.replace(/\[@\]/g, '@');

  // Strip trailing whitespace, slashes
  url = url.replace(/\s+$/, '');

  // Ensure protocol
  if (url && !url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('//')) {
    url = 'http://' + url;
  }

  return url;
}

// ================================================================
// PARSERS (JSON, CSV, TEXT)
// ================================================================

const HOSTING_PLATFORMS = [
  'google.com', 'sites.google.com', 'docs.google.com', 'forms.gle',
  'wixstudio.com', 'wixsite.com', 'wix.com',
  'framer.app', 'webflow.io', 'squarespace.com',
  'github.com', 'github.io', 'netlify.app', 'vercel.app', 'herokuapp.com',
  'blogspot.com', 'wordpress.com', 'weebly.com',
  'firebase.app', 'firebaseapp.com',
  'azurewebsites.net', 'cloudfront.net', 'amazonaws.com'
];

/**
 * Extract hostname + path from a URL, add to the Set.
 * Returns true if a valid entry was added.
 */
function addUrlToSet(rawUrl, urlSet) {
  try {
    const cleaned = defangToUrl(rawUrl);
    if (!cleaned || cleaned.length < 8) return false;

    const parsed = new URL(cleaned);
    const hostname = parsed.hostname.toLowerCase();
    if (!hostname || hostname.length < 3) return false;

    const pathPart = parsed.pathname.replace(/\/+$/, '');

    // Store full path
    if (pathPart && pathPart !== '') {
      urlSet.add(hostname + pathPart);
    }

    // Store bare hostname only for non-platform domains
    const isHosting = HOSTING_PLATFORMS.some(h => hostname === h || hostname.endsWith('.' + h));
    if (!isHosting) {
      urlSet.add(hostname);
    }

    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Parse JSON feed
 */
function parseJSON(body, feed) {
  const urls = new Set();
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    console.log(`[${feed.name}] ❌ JSON PARSE ERROR: ${e.message}`);
    return urls;
  }

  let entries = parsed;
  if (feed.jsonPath) {
    entries = feed.jsonPath.split('.').reduce((o, k) => o && o[k], parsed);
  }
  if (!Array.isArray(entries)) {
    if (entries && entries.data && Array.isArray(entries.data)) entries = entries.data;
    else { console.log(`[${feed.name}] ⚠️ JSON is not an array`); return urls; }
  }

  let added = 0;
  for (const entry of entries) {
    if (feed.filterFn && !feed.filterFn(entry)) continue;
    const rawUrl = entry[feed.urlField || 'url'] || entry.phish_url || entry.URL || entry.link;
    if (rawUrl && addUrlToSet(rawUrl, urls)) added++;
  }

  console.log(`[${feed.name}] ✅ Parsed ${added} URLs from ${entries.length} JSON entries`);
  return urls;
}

/**
 * Parse plain text feed (one URL per line)
 */
function parseText(body, feed) {
  const urls = new Set();
  const lines = body.split('\n');
  let added = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    if (addUrlToSet(trimmed, urls)) added++;
  }

  console.log(`[${feed.name}] ✅ Parsed ${added} URLs from ${lines.length} lines`);
  return urls;
}

/**
 * Parse CSV feed
 */
function parseCSV(body, feed) {
  const urls = new Set();
  const lines = body.split('\n');
  let added = 0;
  const colIdx = feed.urlColumn || 0;
  const start = feed.skipHeader ? 1 : 0;

  for (let i = start; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;

    // Simple CSV split (handles quoted fields)
    const cols = line.match(/(".*?"|[^",]+)(?=\s*,|\s*$)/g);
    if (!cols || cols.length <= colIdx) continue;

    let rawUrl = cols[colIdx].replace(/^["']+|["']+$/g, '').trim();
    if (addUrlToSet(rawUrl, urls)) added++;
  }

  console.log(`[${feed.name}] ✅ Parsed ${added} URLs from ${lines.length - start} CSV rows`);
  return urls;
}

// ================================================================
// MAIN: LOAD ALL FEEDS
// ================================================================

async function loadAllFeeds() {
  if (isLoading) {
    console.log(`[ThreatFeeds] Already loading, skipping...`);
    return;
  }

  // Try cache first
  const cached = loadFeedCache();
  if (cached) {
    threatDB = cached;
    lastLoadTime = Date.now();
    return;
  }

  isLoading = true;
  console.log(`\n${'='.repeat(60)}`);
  console.log(`[ThreatFeeds] Loading ${FEEDS.length} threat intelligence feeds...`);
  console.log(`${'='.repeat(60)}\n`);

  const allUrls = new Set();

  for (const feed of FEEDS) {
    console.log(`\n--- ${feed.name} (${feed.id}) ---`);
    try {
      let response;
      try {
        response = await fetchFeed(feed.url, feed.name);
      } catch (err) {
        if (feed.fallbackUrl) {
          console.log(`[${feed.name}] Primary failed, trying fallback...`);
          response = await fetchFeed(feed.fallbackUrl, feed.name);
        } else {
          throw err;
        }
      }

      if (response.body.length < 50) {
        console.log(`[${feed.name}] ⚠️ Response too short (${response.body.length} bytes). Skipping.`);
        feedStats[feed.id] = { status: 'empty', count: 0 };
        continue;
      }

      // Parse based on format
      let urls;
      switch (feed.format) {
        case 'json':  urls = parseJSON(response.body, feed); break;
        case 'csv':   urls = parseCSV(response.body, feed); break;
        case 'text':
        default:      urls = parseText(response.body, feed); break;
      }

      // ---- PIPELINE VERIFICATION LOG ----
      const sample = [...urls].slice(0, 3);
      if (urls.size > 0) {
        console.log(`[${feed.name}] ✅ Successfully parsed ${urls.size} active URLs.`);
        console.log(`[${feed.name}] Sending first URL: ${sample[0]} to detection engine.`);
      } else {
        console.log(`[${feed.name}] ⚠️ 0 URLs parsed — check format/response above.`);
      }

      // Merge into global DB
      for (const u of urls) allUrls.add(u);

      feedStats[feed.id] = { status: 'ok', count: urls.size };
    } catch (err) {
      console.error(`[${feed.name}] ${err.message}`);
      feedStats[feed.id] = { status: 'error', error: err.message, count: 0 };
    }
  }

  if (allUrls.size > 0) {
    threatDB = allUrls;
    lastLoadTime = Date.now();
    saveFeedCache(allUrls);
    console.log(`\n${'='.repeat(60)}`);
    console.log(`[ThreatFeeds] ✅ TOTAL: ${allUrls.size} unique threat entries loaded from ${FEEDS.length} feeds`);
    console.log(`${'='.repeat(60)}\n`);
  } else {
    console.log(`[ThreatFeeds] ⚠️ WARNING: 0 total entries loaded across all feeds`);
  }

  isLoading = false;
}

// ================================================================
// CACHE
// ================================================================

function loadFeedCache() {
  try {
    if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
    const cacheFile = path.join(CACHE_DIR, 'threat_db.json');
    if (fs.existsSync(cacheFile)) {
      const age = Date.now() - fs.statSync(cacheFile).mtimeMs;
      if (age < CACHE_MAX_AGE_MS) {
        const data = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
        if (data.urls && Array.isArray(data.urls)) {
          console.log(`[ThreatFeeds] 📦 Loaded ${data.urls.length} entries from cache (${Math.round(age / 60000)}m old)`);
          feedStats = data.feedStats || {};
          return new Set(data.urls);
        }
      }
    }
  } catch (e) { /* cache miss */ }
  return null;
}

function saveFeedCache(urlSet) {
  try {
    if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
    const cacheFile = path.join(CACHE_DIR, 'threat_db.json');
    fs.writeFileSync(cacheFile, JSON.stringify({
      urls: [...urlSet], feedStats, timestamp: Date.now(), count: urlSet.size
    }), 'utf8');
    console.log(`[ThreatFeeds] 💾 Cached ${urlSet.size} entries`);
  } catch (e) {
    console.log(`[ThreatFeeds] Cache write error: ${e.message}`);
  }
}

// ================================================================
// LOOKUP
// ================================================================

function checkThreatDB(url) {
  if (threatDB.size === 0) return null;
  try {
    let normalized = defangToUrl(url).toLowerCase().trim();
    if (!normalized.startsWith('http')) normalized = 'http://' + normalized;
    const parsed = new URL(normalized);
    const hostname = parsed.hostname;
    const fullPath = hostname + parsed.pathname.replace(/\/+$/, '');

    if (threatDB.has(fullPath)) return { matched: true, matchType: 'exact_path', target: fullPath };
    if (threatDB.has(hostname)) return { matched: true, matchType: 'domain', target: hostname };
  } catch (e) { /* invalid URL */ }
  return null;
}

function getThreatDBStats() {
  return {
    loaded: threatDB.size > 0,
    entries: threatDB.size,
    feeds: feedStats,
    lastFetch: lastLoadTime ? new Date(lastLoadTime).toISOString() : 'never',
  };
}

// ================================================================
// BACKWARD COMPATIBILITY — keep old API working
// ================================================================

module.exports = {
  // New multi-feed API
  loadAllFeeds,
  checkThreatDB,
  getThreatDBStats,
  defangToUrl,
  // Legacy aliases (so scanner.js and server.js keep working)
  loadPhishTankDB: loadAllFeeds,
  checkPhishTank: checkThreatDB,
  getPhishTankStats: getThreatDBStats,
};
