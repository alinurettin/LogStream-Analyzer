// LogStream-Analyzer Client Application & SSE Stream Consumer
document.addEventListener('DOMContentLoaded', () => {
  const statTotal = document.getElementById('statTotal');
  const statThroughput = document.getElementById('statThroughput');
  const statErrorRate = document.getElementById('statErrorRate');
  const statErrorsCount = document.getElementById('statErrorsCount');
  const statThreats = document.getElementById('statThreats');
  const statAnomalies = document.getElementById('statAnomalies');
  const anomaliesBadge = document.getElementById('anomaliesBadge');

  const entropyInput = document.getElementById('entropyInput');
  const calcEntropyBtn = document.getElementById('calcEntropyBtn');
  const entropyVal = document.getElementById('entropyVal');
  const entropyStatus = document.getElementById('entropyStatus');
  const threatSignature = document.getElementById('threatSignature');

  const ingestForm = document.getElementById('ingestForm');
  const rawLogInput = document.getElementById('rawLogInput');
  const simulateBtn = document.getElementById('simulateBtn');
  const clearWaterfallBtn = document.getElementById('clearWaterfallBtn');

  const logTableBody = document.getElementById('logTableBody');
  const anomaliesList = document.getElementById('anomaliesList');

  // Presets mapping
  const presets = {
    combined: '192.168.1.100 - - [20/Sep/2026:12:00:00 +0000] "GET /api/v1/users HTTP/1.1" 200 1024 "-" "curl/7.81.0"',
    sqli: '10.0.4.12 - - [20/Sep/2026:12:00:01 +0000] "GET /items?category=books%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 403 256 "-" "sqlmap/1.4"',
    traversal: '172.16.50.3 - - [20/Sep/2026:12:00:02 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 0 "-" "Nikto/2.1"',
    json: '{"level":"error", "timestamp":"2026-09-20T12:00:03Z", "ip":"10.0.1.20", "service":"payment-gateway", "message":"Stripe API returned 502 Bad Gateway"}',
    syslog: '<34>1 2026-09-20T12:00:04Z edge-01 sshd 4567 - - Failed password for root from 185.220.101.5 port 55432 ssh2'
  };

  document.querySelectorAll('.btn-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-preset');
      if (presets[type]) rawLogInput.value = presets[type];
    });
  });

  // Load telemetry stats
  async function loadStats() {
    try {
      const res = await fetch('/api/stats');
      const data = await res.json();
      if (data.success && data.stats) {
        const s = data.stats;
        statTotal.textContent = s.totalProcessed.toLocaleString();
        statThroughput.textContent = `${s.throughputPerSec} logs / sec`;
        statErrorRate.textContent = `${s.errorRatePct}%`;
        statErrorsCount.textContent = `${s.totalErrors} total errors`;
        statThreats.textContent = s.totalThreats.toLocaleString();
        statAnomalies.textContent = s.totalAnomalies.toLocaleString();
        anomaliesBadge.textContent = `${s.totalAnomalies} Flagged`;
      }
    } catch (e) {
      console.error('Failed to load stats', e);
    }
  }

  // Render Log Row in Waterfall
  function appendLogRow(event) {
    if (logTableBody.children.length === 1 && logTableBody.children[0].querySelector('.text-center')) {
      logTableBody.innerHTML = '';
    }

    const tr = document.createElement('tr');
    if (event.anomalyDetected) {
      tr.style.background = 'rgba(239, 68, 68, 0.08)';
    }

    const flags = [];
    if (event.threat && event.threat.threatDetected) flags.push(`<span class="threat-tag">${event.threat.type}</span>`);
    if (event.isHighEntropy) flags.push('<span class="threat-tag" style="background:#7c3aed; color:#ddd6fe;">HIGH_ENTROPY</span>');
    if (event.isVolumetricSpike) flags.push('<span class="threat-tag" style="background:#ea580c; color:#fed7aa;">3σ_SPIKE</span>');

    tr.innerHTML = `
      <td><span class="format-badge">${event.format}</span></td>
      <td><span class="level-tag ${event.level}">${event.level}</span></td>
      <td><span style="font-family:monospace; color:#94a3b8;">${event.clientIp}</span></td>
      <td>
        <div style="font-family:monospace; color:#f8fafc; word-break:break-all;">${event.path || event.message}</div>
      </td>
      <td><span style="font-family:monospace; color:#38bdf8;">${event.entropy.toFixed(2)} b</span></td>
      <td>${flags.join(' ') || '<span style="color:#64748b;">Normal</span>'}</td>
    `;

    logTableBody.prepend(tr);
    if (logTableBody.children.length > 50) {
      logTableBody.removeChild(logTableBody.lastChild);
    }
  }

  // Render Anomaly Card
  function appendAnomalyCard(event) {
    if (anomaliesList.children.length === 1 && anomaliesList.children[0].classList.contains('empty-state')) {
      anomaliesList.innerHTML = '';
    }

    const card = document.createElement('div');
    card.className = 'anomaly-card';
    const threatTitle = event.threat && event.threat.threatDetected ? event.threat.type : (event.isHighEntropy ? 'ANOMALOUS_ENTROPY' : 'VOLUMETRIC_SPIKE');
    const timeStr = new Date(event.timestamp).toLocaleTimeString();

    card.innerHTML = `
      <div class="anomaly-header">
        <span class="anomaly-title">🚨 ${threatTitle}</span>
        <span class="anomaly-time">${timeStr}</span>
      </div>
      <div class="anomaly-desc">${event.path || event.message}</div>
      <div style="font-size:0.7rem; color:#94a3b8; display:flex; gap:0.5rem; margin-top:2px;">
        <span>IP: ${event.clientIp}</span>
        <span>Entropy: ${event.entropy.toFixed(2)} bits</span>
      </div>
    `;

    anomaliesList.prepend(card);
    if (anomaliesList.children.length > 20) {
      anomaliesList.removeChild(anomaliesList.lastChild);
    }
  }

  // Load Initial Recent Logs
  async function loadInitialLogs() {
    try {
      const res = await fetch('/api/logs/recent?limit=25');
      const data = await res.json();
      if (data.success && data.events) {
        logTableBody.innerHTML = '';
        data.events.reverse().forEach(ev => appendLogRow(ev));
      }
    } catch (e) {
      console.error(e);
    }
  }

  // Load Initial Anomalies
  async function loadInitialAnomalies() {
    try {
      const res = await fetch('/api/logs/anomalies?limit=10');
      const data = await res.json();
      if (data.success && data.anomalies) {
        if (data.anomalies.length > 0) anomaliesList.innerHTML = '';
        data.anomalies.reverse().forEach(ev => appendAnomalyCard(ev));
      }
    } catch (e) {
      console.error(e);
    }
  }

  // Analyze Entropy
  async function evaluateEntropy(text) {
    try {
      const res = await fetch('/api/entropy/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
      });
      const data = await res.json();
      if (data.success) {
        entropyVal.textContent = `${data.entropy.toFixed(3)} bits/char`;
        entropyStatus.innerHTML = data.isAnomalous
          ? '<span style="color:#ef4444; font-weight:bold;">🚨 Anomalous High Entropy</span>'
          : '<span style="color:#10b981;">✓ Standard Entropy Range</span>';

        let threat = 'None Detected';
        if (/union\s+select|drop\s+table/i.test(text)) threat = 'SQL Injection';
        else if (/\.\.\//.test(text)) threat = 'Path Traversal';
        else if (/<script/i.test(text)) threat = 'Cross-Site Scripting (XSS)';
        threatSignature.textContent = threat;
      }
    } catch (e) {
      console.error(e);
    }
  }

  // Ingest Form Submit
  ingestForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const raw = rawLogInput.value.trim();
    if (!raw) return;

    try {
      const res = await fetch('/api/logs/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log: raw })
      });
      const data = await res.json();
      if (data.success) {
        appendLogRow(data.event);
        if (data.event.anomalyDetected) appendAnomalyCard(data.event);
        await loadStats();
      } else {
        alert('Ingest error: ' + data.error);
      }
    } catch (err) {
      alert('Network error: ' + err.message);
    }
  });

  // Traffic Flood Simulation
  simulateBtn.addEventListener('click', async () => {
    const burst = [
      '192.168.1.50 - - [20/Sep/2026:12:01:00 +0000] "GET /api/v1/feed HTTP/1.1" 200 4096 "-" "App/2.0"',
      '192.168.1.51 - - [20/Sep/2026:12:01:01 +0000] "GET /api/v1/search?q=test HTTP/1.1" 200 1024 "-" "App/2.0"',
      '10.99.1.5 - - [20/Sep/2026:12:01:02 +0000] "GET /admin?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 403 0 "-" "sqlmap/1.4"',
      '{"level":"warn", "timestamp":"2026-09-20T12:01:03Z", "ip":"10.0.5.99", "message":"High memory watermark exceeded (88%)"}',
      '172.16.8.9 - - [20/Sep/2026:12:01:04 +0000] "POST /upload?path=../../etc/passwd HTTP/1.1" 403 128 "-" "Nikto/2.1"',
      '192.168.1.52 - - [20/Sep/2026:12:01:05 +0000] "GET /health HTTP/1.1" 200 64 "-" "Kubelet/1.28"',
      '{"level":"error", "timestamp":"2026-09-20T12:01:06Z", "ip":"10.0.2.14", "message":"Redis connection timed out after 5000ms"}',
      '185.220.100.1 - - [20/Sep/2026:12:01:07 +0000] "GET /login?redirect=javascript:alert(1) HTTP/1.1" 400 512 "-" "Scanner/1.0"'
    ];

    try {
      const res = await fetch('/api/logs/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logs: burst })
      });
      const data = await res.json();
      if (data.success) {
        await loadInitialLogs();
        await loadInitialAnomalies();
        await loadStats();
      }
    } catch (e) {
      console.error(e);
    }
  });

  calcEntropyBtn.addEventListener('click', () => {
    evaluateEntropy(entropyInput.value.trim());
  });

  clearWaterfallBtn.addEventListener('click', () => {
    logTableBody.innerHTML = '<tr><td colspan="6" class="text-center">Awaiting log stream events...</td></tr>';
  });

  // Setup Server-Sent Events (SSE) stream
  function setupSse() {
    const eventSource = new EventSource('/api/logs/stream');
    eventSource.addEventListener('log', (e) => {
      try {
        const ev = JSON.parse(e.data);
        appendLogRow(ev);
        loadStats();
      } catch (err) {
        console.error(err);
      }
    });

    eventSource.addEventListener('anomaly', (e) => {
      try {
        const ev = JSON.parse(e.data);
        appendAnomalyCard(ev);
      } catch (err) {
        console.error(err);
      }
    });

    eventSource.onerror = () => {
      // Reconnect handled automatically by browser
    };
  }

  // Init
  evaluateEntropy(entropyInput.value.trim());
  loadStats();
  loadInitialLogs();
  loadInitialAnomalies();
  setupSse();
  setInterval(loadStats, 5000);
});
