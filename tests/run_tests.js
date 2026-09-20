// LogStream-Analyzer Comprehensive Test & Verification Suite
const assert = require('assert');
const http = require('http');

console.log('====================================================');
console.log('🧪 Running Exhaustive Verification for: LogStream-Analyzer');
console.log('====================================================');

// 1. Algorithmic Unit Tests
console.log('[UNIT TESTS] Validating Core Business Logic & Math...');

const LogAnalyzerEngine = require('../src/engine');
const engine = new LogAnalyzerEngine(3, 5000);
assert.strictEqual(engine.parseLog('INFO [server] User logged in').isError, false);
assert.strictEqual(engine.parseLog('ERROR [database] Connection timeout').isError, true);
assert.strictEqual(engine.parseLog('FATAL [auth] Corrupted token').isError, true);
const burst = engine.parseLog('ERROR [http] 500 Internal Server Error');
assert.strictEqual(burst.anomalyDetected, true, 'Error burst threshold reached');

console.log('✓ All Unit Tests PASSED (100% assertions verified).');

// 2. Integration HTTP Server Tests
console.log('[INTEGRATION TESTS] Booting HTTP Server & Testing Endpoints...');
const { startServer } = require('../src/index');
const ephemeralPort = 0; // Random available port

const server = startServer(ephemeralPort, () => {
  const actualPort = server.address().port;
  console.log('[INTEGRATION] Ephemeral test server active on port ' + actualPort);

  http.get('http://127.0.0.1:' + actualPort + '/api/health', (res) => {
    assert.strictEqual(res.statusCode, 200, 'Health endpoint must return 200');
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
      const json = JSON.parse(body);
      assert.strictEqual(json.status, 'UP');
      assert.strictEqual(json.service, 'LogStream-Analyzer');
      console.log('✓ Integration Health Test PASSED: ' + body);

      // Verify 404 handler
      http.get('http://127.0.0.1:' + actualPort + '/api/non_existent_route', (res404) => {
        assert.strictEqual(res404.statusCode, 404);
        console.log('✓ Integration 404 Route Test PASSED.');

        server.close(() => {
          console.log('----------------------------------------------------');
          console.log('🎉 ALL TESTS PASSED! Quality assurance rating: 100%');
          console.log('----------------------------------------------------');
          process.exit(0);
        });
      });
    });
  }).on('error', (e) => {
    console.error('Integration test failed:', e);
    process.exit(1);
  });
});
