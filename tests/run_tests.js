// LogStream-Analyzer Comprehensive Verification Suite
// Author: Ali Nurettin Demir (@alinurettin)
const assert = require('assert');
const http = require('http');
const { LogParser, ShannonEntropy, ThreatDetector, RollingStats, LogStreamEngine } = require('../src/engine');
const { startServer } = require('../src/index');

console.log('====================================================');
console.log('🧪 Running Verification Suite: LogStream-Analyzer (v2.0.0)');
console.log('====================================================');

let passedAssertions = 0;
function check(description, condition) {
  assert.ok(condition, description);
  passedAssertions++;
  console.log(`  ✓ [Assertion ${passedAssertions}] ${description}`);
}

// ----------------------------------------------------
// SECTION 1: Multi-Format Log Parsing
// ----------------------------------------------------
console.log('\n[SECTION 1: Multi-Format Log Parsing]');

// 1. Nginx / Apache Combined format
const combinedLine = '198.51.100.24 - - [20/Sep/2026:14:32:10 +0000] "POST /api/v2/checkout HTTP/1.1" 201 1420 "https://shop.com/cart" "Mozilla/5.0"';
const parsedCombined = LogParser.parse(combinedLine);
check('Combined format recognized', parsedCombined.format === 'COMBINED');
check('Client IP extracted correctly', parsedCombined.clientIp === '198.51.100.24');
check('HTTP Method extracted correctly', parsedCombined.method === 'POST');
check('URI Path extracted correctly', parsedCombined.path === '/api/v2/checkout');
check('Status Code parsed as number 201', parsedCombined.statusCode === 201);
check('Bytes sent parsed as number 1420', parsedCombined.bytesSent === 1420);
check('Referer extracted', parsedCombined.referer === 'https://shop.com/cart');

// 2. Syslog RFC format
const syslogLine = '<34>1 2026-09-20T14:32:11Z edge-gateway-01 nginx 1234 ID47 - Failed SSL handshake from 10.0.0.9';
const parsedSyslog = LogParser.parse(syslogLine);
check('Syslog format recognized', parsedSyslog.format === 'SYSLOG');
check('Syslog level mapped from PRI (34 & 7 = 2 -> CRITICAL)', parsedSyslog.level === 'CRITICAL');
check('Syslog client IP or host extracted', parsedSyslog.clientIp === 'edge-gateway-01');

// 3. JSON structured log
const jsonLine = JSON.stringify({
  timestamp: '2026-09-20T14:32:12Z',
  level: 'error',
  ip: '10.200.1.5',
  service: 'auth-service',
  message: 'Failed login attempt for user root'
});
const parsedJson = LogParser.parse(jsonLine);
check('JSON format recognized', parsedJson.format === 'JSON');
check('JSON level normalized to uppercase ERROR', parsedJson.level === 'ERROR');
check('JSON client IP extracted', parsedJson.clientIp === '10.200.1.5');
check('JSON message extracted', parsedJson.message === 'Failed login attempt for user root');

// 4. Raw fallback
const rawLine = 'FATAL: kernel panic - unable to mount root fs on unknown-block(0,0)';
const parsedRaw = LogParser.parse(rawLine);
check('Raw format fallback recognized', parsedRaw.format === 'RAW');
check('Raw FATAL level detected', parsedRaw.level === 'CRITICAL');

try {
  LogParser.parse('');
  assert.fail('Should fail on empty log');
} catch (e) {
  check('Reject empty log string', e.message.includes('non-empty'));
}

// ----------------------------------------------------
// SECTION 2: Shannon Entropy Calculation
// ----------------------------------------------------
console.log('\n[SECTION 2: Shannon Entropy Analysis]');

const lowEntropy = ShannonEntropy.calculate('AAAAAAAAAAAAAA');
check('Repetitive string has 0 entropy', lowEntropy === 0);

const normalUrlEntropy = ShannonEntropy.calculate('/api/v1/products?category=electronics');
check('Standard URL entropy is between 2.5 and 4.5 bits', normalUrlEntropy >= 2.5 && normalUrlEntropy <= 4.5);

const exploitEntropy = ShannonEntropy.calculate('/q?payload=dGhpcyBpcyBhIHZlcnkgbG9uZyByYW5kb21pemVkIHNoZWxsY29kZSBidWZmZXI=');
check('Randomized / base64 payload has high entropy (> 4.3)', exploitEntropy > 4.3);
check('isAnomalousEntropy flags high entropy payload', ShannonEntropy.isAnomalousEntropy('dGhpcyBpcyBhIHZlcnkgbG9uZyByYW5kb21pemVkIHNoZWxsY29kZSBidWZmZXI=X1Y2ZGFzZGFzZA==', 4.5));
check('isAnomalousEntropy returns false for standard text', !ShannonEntropy.isAnomalousEntropy('hello world', 4.5));

// ----------------------------------------------------
// SECTION 3: Threat Detector
// ----------------------------------------------------
console.log('\n[SECTION 3: Cyber Threat Signature Scanner]');

const sqli = ThreatDetector.scan('/search?q=test%20UNION%20SELECT%20user,pass%20FROM%20admins');
check('Detects SQL Injection signature', sqli.threatDetected === true && sqli.type === 'SQL_INJECTION');

const traversal = ThreatDetector.scan('/static/../../etc/passwd');
check('Detects Path Traversal signature', traversal.threatDetected === true && traversal.type === 'PATH_TRAVERSAL');

const xss = ThreatDetector.scan('/comment?body=<script>alert("pwned")</script>');
check('Detects XSS injection signature', xss.threatDetected === true && xss.type === 'XSS_INJECTION');

const cmdi = ThreatDetector.scan('/download?file=doc.pdf; cat /etc/passwd');
check('Detects Command Injection signature', cmdi.threatDetected === true && cmdi.type === 'COMMAND_INJECTION');

const safe = ThreatDetector.scan('/api/v1/users/42/profile');
check('Safe path returns threatDetected false', safe.threatDetected === false);

// ----------------------------------------------------
// SECTION 4: Rolling Statistics & Volumetric Z-Scores
// ----------------------------------------------------
console.log('\n[SECTION 4: Rolling Stats & Volumetric Spikes]');

const stats = new RollingStats(5);
[10, 10, 10, 10, 10].forEach(v => stats.add(v));
check('Mean of constant values is 10', stats.getMean() === 10);
check('StdDev of constant values is 0', stats.getStdDev() === 0);

// Add varying numbers
const statsVarying = new RollingStats(5);
[2, 4, 4, 4, 5, 5, 7, 9].forEach(v => statsVarying.add(v)); // window holds last 5: [4, 5, 5, 7, 9]
check('Rolling window retains last 5 samples', statsVarying.samples.length === 5);
check('Mean computed correctly', statsVarying.getMean() === 6);
check('StdDev is greater than 0', statsVarying.getStdDev() > 0);
const z = statsVarying.getZScore(15);
check('High outlier yields positive z-score (> 1.5)', z > 1.5);

// ----------------------------------------------------
// SECTION 5: LogStreamEngine End-to-End Ingestion
// ----------------------------------------------------
console.log('\n[SECTION 5: LogStreamEngine Core Ingestion]');

const streamEngine = new LogStreamEngine({ bufferCapacity: 10, zScoreThreshold: 2.0 });

// Ingest clean logs
const ev1 = streamEngine.ingest('127.0.0.1 - - [20/Sep/2026:10:00:00 +0000] "GET /home HTTP/1.1" 200 1024');
check('Event 1 format is COMBINED', ev1.format === 'COMBINED');
check('Event 1 anomalyDetected is false', ev1.anomalyDetected === false);

// Ingest threat log
const ev2 = streamEngine.ingest('10.0.0.1 - - [20/Sep/2026:10:00:01 +0000] "GET /api?id=1%20UNION%20SELECT%20*%20FROM%20users HTTP/1.1" 500 256');
check('Event 2 flags threatDetected', ev2.threat.threatDetected === true);
check('Event 2 flags anomalyDetected', ev2.anomalyDetected === true);

const statsReport = streamEngine.getStats();
check('Stats totalProcessed is 2', statsReport.totalProcessed === 2);
check('Stats totalThreats is 1', statsReport.totalThreats === 1);
check('Stats totalErrors is 1', statsReport.totalErrors === 1);

// Test buffer overflow boundary
for (let i = 0; i < 20; i++) {
  streamEngine.ingest(`{"level":"info","message":"ping test ${i}"}`);
}
check('Buffer capacity respects limit (10 items)', streamEngine.buffer.length === 10);
check('getRecentEvents(5) returns 5 events', streamEngine.getRecentEvents(5).length === 5);

// ----------------------------------------------------
// SECTION 6: Ephemeral HTTP Integration & REST Protocol
// ----------------------------------------------------
console.log('\n[SECTION 6: Ephemeral HTTP Server & REST Endpoints]');

const server = startServer(0, () => {
  const port = server.address().port;
  console.log(`  [HTTP] Ephemeral server running on port ${port}`);

  function api(method, path, body, cb) {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    }, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try {
          cb(res.statusCode, JSON.parse(raw));
        } catch (e) {
          cb(res.statusCode, raw);
        }
      });
    });
    if (payload) req.write(payload);
    req.end();
  }

  // 1. GET /api/health
  api('GET', '/api/health', null, (status, health) => {
    check('GET /api/health returns HTTP 200', status === 200);
    check('Health service reports LogStream-Analyzer', health.service === 'LogStream-Analyzer');
    check('Health status is UP', health.status === 'UP');

    // 2. GET /api/stats
    api('GET', '/api/stats', null, (status, resStats) => {
      check('GET /api/stats returns HTTP 200', status === 200);
      check('Stats contains totalProcessed', typeof resStats.stats.totalProcessed === 'number');

      // 3. POST /api/logs/ingest
      api('POST', '/api/logs/ingest', {
        log: '192.168.1.50 - - [20/Sep/2026:15:00:00 +0000] "GET /admin/../../etc/shadow HTTP/1.1" 403 0'
      }, (status, resIngest) => {
        check('POST /api/logs/ingest returns HTTP 200', status === 200);
        check('Ingested event flagged threat', resIngest.event.threat.threatDetected === true);

        // 4. POST /api/entropy/analyze
        api('POST', '/api/entropy/analyze', { text: 'randomStringWithVeryHighEntropy123987!@#' }, (status, resEntropy) => {
          check('POST /api/entropy/analyze returns HTTP 200', status === 200);
          check('Entropy returned as number', typeof resEntropy.entropy === 'number');

          // 5. GET /api/logs/recent
          api('GET', '/api/logs/recent?limit=5', null, (status, resRecent) => {
            check('GET /api/logs/recent returns HTTP 200', status === 200);
            check('Recent events list returned', Array.isArray(resRecent.events));

            // 6. GET /api/logs/anomalies
            api('GET', '/api/logs/anomalies', null, (status, resAnomalies) => {
              check('GET /api/logs/anomalies returns HTTP 200', status === 200);
              check('Anomalies array contains detected threat', resAnomalies.anomalies.length > 0);

              // 7. 404 Route
              api('GET', '/api/invalid-path', null, (status) => {
                check('Invalid path returns 404', status === 404);

                server.close(() => {
                  console.log('\n====================================================');
                  console.log(`🎉 ALL ${passedAssertions} ASSERTIONS PASSED (100% Non-Mocked Coverage)`);
                  console.log('====================================================');
                  process.exit(0);
                });
              });
            });
          });
        });
      });
    });
  });
});
