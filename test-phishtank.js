/**
 * PhishTank Integration Test Script
 * Tests fetching, parsing, and scanning against the PhishTank database.
 * 
 * Run: node test-phishtank.js
 */

const { loadPhishTankDB, checkPhishTank, getPhishTankStats } = require('./utils/phishtank');
const { scanURL, getRiskLevel } = require('./utils/scanner');

// Known phishing test URLs (some may be down, but they should still match DB)
const TEST_URLS = [
  'http://paypal-secure-login.tk/verify',
  'http://account-verify.xyz/signin',
  'http://192.168.1.100/bankofamerica/login',
  'https://google.com',  // should be SAFE
  'https://github.com',  // should be SAFE
];

async function runTest() {
  console.log('='.repeat(60));
  console.log('🛡️  PhishGuard — PhishTank Integration Test');
  console.log('='.repeat(60));
  console.log('');

  // Step 1: Load PhishTank database
  console.log('STEP 1: Loading PhishTank database...');
  console.log('-'.repeat(40));
  await loadPhishTankDB();

  const stats = getPhishTankStats();
  console.log('');
  console.log('📊 PhishTank DB Stats:');
  console.log(`   Loaded:     ${stats.loaded}`);
  console.log(`   Entries:    ${stats.entries}`);
  console.log(`   Last Fetch: ${stats.lastFetch}`);
  console.log(`   Cache Age:  ${stats.cacheAge}`);
  console.log('');

  // Step 2: Test hardcoded URLs
  console.log('STEP 2: Testing hardcoded URLs with scanner...');
  console.log('-'.repeat(40));
  
  for (const url of TEST_URLS) {
    const result = scanURL(url);
    const risk = getRiskLevel(result.score);
    const phishTankMatch = checkPhishTank(url);
    const icon = risk === 'good' ? '✅' : risk === 'average' ? '⚠️' : '🔴';
    
    console.log(`\n${icon} ${url}`);
    console.log(`   Score: ${result.score}/100 | Risk: ${risk.toUpperCase()}`);
    console.log(`   PhishTank Match: ${phishTankMatch ? `YES (${phishTankMatch.matchType})` : 'No'}`);
    console.log(`   Factors: ${result.factors.map(f => f.name).join(', ')}`);
  }

  // Step 3: If PhishTank DB loaded, test first 5 entries from the DB itself
  if (stats.loaded && stats.entries > 0) {
    console.log('');
    console.log('STEP 3: Testing first 5 PhishTank DB entries through scanner...');
    console.log('-'.repeat(40));

    // We need to read a few entries from the cache to test
    const fs = require('fs');
    const path = require('path');
    const cacheFile = path.join(__dirname, 'phishtank_cache.json');
    
    if (fs.existsSync(cacheFile)) {
      const cache = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      // The cache urls are hostnames — let's test a few
      const sampleUrls = cache.urls.slice(0, 5).map(u => 'http://' + u);
      
      let detected = 0;
      for (const url of sampleUrls) {
        const result = scanURL(url);
        const risk = getRiskLevel(result.score);
        if (risk !== 'good') detected++;
        
        const icon = risk === 'good' ? '✅' : risk === 'average' ? '⚠️' : '🔴';
        console.log(`${icon} ${url} → Score: ${result.score} | Risk: ${risk.toUpperCase()}`);
      }

      console.log('');
      console.log(`📈 Detection Results: ${detected}/${sampleUrls.length} flagged as threats`);
    }
  } else {
    console.log('');
    console.log('⚠️ STEP 3 SKIPPED: PhishTank DB not loaded — check network/logs above');
  }

  console.log('');
  console.log('='.repeat(60));
  console.log('Test complete!');
  console.log('='.repeat(60));
}

runTest().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
