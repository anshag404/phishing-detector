/**
 * Threat Feed Pipeline Test
 * Tests the full ingestion pipeline: fetch → decompress → parse → normalize → detect
 * 
 * Run: node test-phishtank.js
 */

const { loadAllFeeds, checkThreatDB, getThreatDBStats, defangToUrl } = require('./utils/phishtank');

// Defanged URL test cases
const DEFANG_TESTS = [
  { input: 'hxxp://evil[.]example[.]com/login',    expected: 'http://evil.example.com/login' },
  { input: 'hxxps://phish[dot]site[.]tk/verify',   expected: 'https://phish.site.tk/verify' },
  { input: 'hXXp://192[.]168[.]1[.]100/steal',     expected: 'http://192.168.1.100/steal' },
  { input: '  "http://sketchy.xyz"  ',              expected: 'http://sketchy.xyz' },
  { input: 'malware[.]bad[.]com',                   expected: 'http://malware.bad.com' },
];

// Safe URLs (should NOT match)
const SAFE_URLS = ['https://google.com', 'https://github.com', 'https://microsoft.com'];

async function runTest() {
  console.log('='.repeat(60));
  console.log('  PhishGuard — Threat Feed Pipeline Test');
  console.log('='.repeat(60));
  console.log('');

  // STEP 1: Test defanging logic
  console.log('STEP 1: Defanged URL Normalization');
  console.log('-'.repeat(40));
  let defangPass = 0;
  for (const t of DEFANG_TESTS) {
    const result = defangToUrl(t.input);
    const pass = result === t.expected;
    if (pass) defangPass++;
    console.log(`${pass ? 'PASS' : 'FAIL'}: "${t.input}" -> "${result}"${pass ? '' : ` (expected: "${t.expected}")`}`);
  }
  console.log(`Defang tests: ${defangPass}/${DEFANG_TESTS.length} passed\n`);

  // STEP 2: Load all feeds (this exercises the full pipeline)
  console.log('STEP 2: Loading all threat feeds...');
  console.log('-'.repeat(40));
  await loadAllFeeds();

  // STEP 3: Print stats
  const stats = getThreatDBStats();
  console.log('\nSTEP 3: Feed Stats Summary');
  console.log('-'.repeat(40));
  console.log(`Total Entries: ${stats.entries}`);
  console.log(`Loaded: ${stats.loaded}`);
  console.log(`Last Fetch: ${stats.lastFetch}`);
  console.log('');
  console.log('Per-feed breakdown:');
  for (const [feedId, info] of Object.entries(stats.feeds)) {
    const icon = info.status === 'ok' ? 'OK' : (info.status === 'error' ? 'ERR' : 'EMPTY');
    console.log(`  [${icon}] ${feedId}: ${info.count} entries${info.error ? ` (${info.error.substring(0, 60)})` : ''}`);
  }
  console.log('');

  // STEP 4: Test safe URLs (should NOT match)
  console.log('STEP 4: Safe URL Verification (should NOT match DB)');
  console.log('-'.repeat(40));
  for (const url of SAFE_URLS) {
    const match = checkThreatDB(url);
    console.log(`${match ? 'FAIL (false positive!)' : 'PASS'}: ${url} -> ${match ? 'MATCHED' : 'clean'}`);
  }
  console.log('');

  // STEP 5: Test detection against DB entries
  if (stats.loaded) {
    console.log('STEP 5: Testing 5 threat DB entries through scanner...');
    console.log('-'.repeat(40));
    const { scanURL, getRiskLevel } = require('./utils/scanner');
    // Load a few entries from the cache
    const cacheFile = require('path').join(__dirname, 'feed_cache', 'threat_db.json');
    if (require('fs').existsSync(cacheFile)) {
      const cache = JSON.parse(require('fs').readFileSync(cacheFile, 'utf8'));
      // Filter to non-path entries (bare hostnames) for cleaner test
      const hostnames = cache.urls.filter(u => !u.includes('/')).slice(0, 5);
      let detected = 0;
      for (const host of hostnames) {
        const url = 'http://' + host;
        const result = scanURL(url);
        const risk = getRiskLevel(result.score);
        const hasThreatFactor = result.factors.some(f => f.name.includes('Verified Threat') || f.name.includes('PhishTank'));
        if (risk !== 'good') detected++;
        console.log(`${risk !== 'good' ? 'DETECTED' : 'MISSED'}: ${url} -> Score: ${result.score} | Risk: ${risk.toUpperCase()} | ThreatDB: ${hasThreatFactor ? 'YES' : 'no'}`);
      }
      console.log(`\nDetection rate: ${detected}/${hostnames.length} flagged as threats`);
    }
  } else {
    console.log('STEP 5 SKIPPED: No feeds loaded\n');
  }

  console.log('');
  console.log('='.repeat(60));
  console.log('Test complete!');
  console.log('='.repeat(60));
}

runTest().catch(err => {
  console.error('Test crashed:', err);
  process.exit(1);
});
