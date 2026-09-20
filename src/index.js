// LogStream-Analyzer - Production Server & Real-Time Event Streamer
const http = require('http');
const fs = require('fs');
const path = require('path');
const { LogParser, ShannonEntropy, ThreatDetector, LogStreamEngine } = require('./engine');

const engine = new LogStreamEngine({ bufferCapacity: 1000, zScoreThreshold: 2.5 });
const PORT = parseInt(process.env.PORT, 10) || 6006;
const publicDir = path.join(__dirname, '..', 'public');
const startTime = Date.now();

// SSE subscribers
const sseClients = new Set();

function broadcastSse(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

// Ingest some initial sample traffic
engine.ingest('192.168.1.10 - - [20/Sep/2026:10:00:01 +0000] "GET /api/v1/products HTTP/1.1" 200 4096 "https://google.com" "Mozilla/5.0"');
engine.ingest('10.0.0.45 - - [20/Sep/2026:10:00:02 +0000] "POST /api/login HTTP/1.1" 200 128 "-" "PostmanRuntime/7.29.0"');
engine.ingest('172.16.0.8 - - [20/Sep/2026:10:00:03 +0000] "GET /api/user?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 403 512 "-" "sqlmap/1.4"');
engine.ingest('{"level":"error", "timestamp":"2026-09-20T10:00:04Z", "message":"Database connection pool exhausted", "service":"billing-worker"}');

function requestHandler(req, res) {
  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsed.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  // Server-Sent Events endpoint
  if (req.method === 'GET' && pathname === '/api/logs/stream') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });
    res.write('event: connected\ndata: {"status":"STREAMING"}\n\n');
    sseClients.add(res);

    req.on('close', () => {
      sseClients.delete(res);
    });
    return;
  }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    // 1. Health
    if (pathname === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify({
        status: 'UP',
        service: 'LogStream-Analyzer',
        uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
        timestamp: new Date().toISOString()
      }));
    }

    // 2. Stats
    if (pathname === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify({
        success: true,
        service: 'LogStream-Analyzer',
        stats: engine.getStats()
      }));
    }

    // 3. Ingest Single Log
    if (req.method === 'POST' && pathname === '/api/logs/ingest') {
      try {
        const payload = JSON.parse(body || '{}');
        const rawLog = payload.log || payload.raw || '';
        if (!rawLog) {
          res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, error: 'Empty log entry' }));
        }
        const event = engine.ingest(rawLog);
        broadcastSse('log', event);
        if (event.anomalyDetected) {
          broadcastSse('anomaly', event);
        }

        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({ success: true, event }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({ success: false, error: err.message }));
      }
    }

    // 4. Batch Ingest Logs
    if (req.method === 'POST' && pathname === '/api/logs/batch') {
      try {
        const payload = JSON.parse(body || '{}');
        const logs = Array.isArray(payload.logs) ? payload.logs : [];
        const processed = [];
        for (const line of logs) {
          const ev = engine.ingest(line);
          processed.push(ev);
          broadcastSse('log', ev);
        }
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({ success: true, count: processed.length }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({ success: false, error: err.message }));
      }
    }

    // 5. Recent Logs
    if (req.method === 'GET' && pathname === '/api/logs/recent') {
      const limit = parseInt(parsed.searchParams.get('limit') || '50', 10);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify({ success: true, events: engine.getRecentEvents(limit) }));
    }

    // 6. Anomalies
    if (req.method === 'GET' && pathname === '/api/logs/anomalies') {
      const limit = parseInt(parsed.searchParams.get('limit') || '20', 10);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify({ success: true, anomalies: engine.getAnomalies(limit) }));
    }

    // 7. Entropy Analysis
    if (req.method === 'POST' && pathname === '/api/entropy/analyze') {
      try {
        const payload = JSON.parse(body || '{}');
        const text = payload.text || '';
        const entropy = ShannonEntropy.calculate(text);
        const isAnomalous = ShannonEntropy.isAnomalousEntropy(text);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({
          success: true,
          text,
          length: text.length,
          entropy,
          isAnomalous
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({ success: false, error: err.message }));
      }
    }

    // 8. Static Web UI Files
    let filePath = path.join(publicDir, pathname === '/' ? 'index.html' : pathname);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const mimeTypes = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.json': 'application/json; charset=utf-8'
      };
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
      return res.end(fs.readFileSync(filePath));
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint Not Found', path: pathname }));
  });
}

function startServer(portToUse = PORT, callback) {
  const server = http.createServer(requestHandler);
  server.listen(portToUse, () => {
    if (callback) callback(server);
  });
  return server;
}

if (require.main === module) {
  startServer(PORT, () => {
    console.log('⚡ LogStream-Analyzer live on port ' + PORT);
  });
}

module.exports = { startServer, requestHandler, engine };
