/**
 * LogStream-Analyzer - Real-Time Streaming Telemetry & Threat Analysis Engine
 * Author: Ali Nurettin Demir (@alinurettin)
 * 
 * Features:
 * - Multi-Format Log Parser (Nginx/Apache Combined, Syslog RFC 5424, JSON Structured, Raw)
 * - Shannon Entropy Calculation for Attack & Anomaly Scoring (H(X) = -sum(P(x) * log2(P(x))))
 * - Rolling Z-Score Anomaly Detector with Welford's Online Variance
 * - Threat Signature Matching (SQLi, XSS, Path Traversal, SSRF)
 * - Ring Buffer Event Store & Live Stream Telemetry
 */

class LogParser {
  // Regex for Apache/Nginx Combined Log Format
  static COMBINED_REGEX = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)?(?:")\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?/;

  // Regex for Syslog RFC 5424 / RFC 3164
  static SYSLOG_REGEX = /^<(\d+)>(\d?)\s*(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?\s+(.*)$/;

  static parse(raw) {
    if (!raw || typeof raw !== 'string') {
      throw new Error('Log line must be a non-empty string');
    }

    const trimmed = raw.trim();

    // 1. Check if JSON structured log
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const json = JSON.parse(trimmed);
        const level = (json.level || json.severity || 'INFO').toUpperCase();
        return {
          format: 'JSON',
          timestamp: json.timestamp || new Date().toISOString(),
          level,
          clientIp: json.ip || json.client_ip || '127.0.0.1',
          method: json.method || null,
          path: json.path || json.url || null,
          statusCode: json.statusCode || json.status || null,
          message: json.message || json.msg || JSON.stringify(json),
          raw: trimmed
        };
      } catch (e) {
        // Fallback to text parsing if JSON parsing fails
      }
    }

    // 2. Check Apache / Nginx Combined format
    const matchCombined = trimmed.match(this.COMBINED_REGEX);
    if (matchCombined) {
      const statusCode = parseInt(matchCombined[5], 10);
      let level = 'INFO';
      if (statusCode >= 500) level = 'ERROR';
      else if (statusCode >= 400) level = 'WARN';

      return {
        format: 'COMBINED',
        timestamp: matchCombined[2],
        level,
        clientIp: matchCombined[1],
        method: matchCombined[3],
        path: matchCombined[4],
        statusCode,
        bytesSent: matchCombined[6] === '-' ? 0 : parseInt(matchCombined[6], 10),
        referer: matchCombined[7] || null,
        userAgent: matchCombined[8] || null,
        message: `${matchCombined[3]} ${matchCombined[4]} -> ${statusCode}`,
        raw: trimmed
      };
    }

    // 3. Check Syslog RFC format
    const matchSyslog = trimmed.match(this.SYSLOG_REGEX);
    if (matchSyslog) {
      const pri = parseInt(matchSyslog[1], 10);
      const severity = pri & 0x07; // 0=Emergency, 1=Alert, 2=Crit, 3=Error, 4=Warn, 5=Notice, 6=Info, 7=Debug
      const severityMap = ['EMERGENCY', 'ALERT', 'CRITICAL', 'ERROR', 'WARN', 'NOTICE', 'INFO', 'DEBUG'];
      const level = severityMap[severity] || 'INFO';

      return {
        format: 'SYSLOG',
        timestamp: matchSyslog[3],
        level,
        clientIp: matchSyslog[4] || 'localhost',
        app: matchSyslog[5] || 'system',
        message: matchSyslog[8] || matchSyslog[7] || '',
        raw: trimmed
      };
    }

    // 4. Freeform text fallback
    let detectedLevel = 'INFO';
    if (/\b(FATAL|CRITICAL|EMERG)\b/i.test(trimmed)) detectedLevel = 'CRITICAL';
    else if (/\b(ERROR|FAIL|EXCEPTION|ERR)\b/i.test(trimmed)) detectedLevel = 'ERROR';
    else if (/\b(WARN|WARNING)\b/i.test(trimmed)) detectedLevel = 'WARN';
    else if (/\b(DEBUG|TRACE)\b/i.test(trimmed)) detectedLevel = 'DEBUG';

    return {
      format: 'RAW',
      timestamp: new Date().toISOString(),
      level: detectedLevel,
      clientIp: '127.0.0.1',
      message: trimmed,
      raw: trimmed
    };
  }
}

class ShannonEntropy {
  /**
   * Calculates Shannon Entropy H(X) = -sum(P(x) * log2(P(x)))
   * Returns float bits per character.
   */
  static calculate(input) {
    if (!input || typeof input !== 'string' || input.length === 0) return 0;

    const length = input.length;
    const frequencies = new Map();

    for (let i = 0; i < length; i++) {
      const char = input[i];
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    let entropy = 0;
    for (const count of frequencies.values()) {
      const p = count / length;
      entropy -= p * Math.log2(p);
    }

    return Number(entropy.toFixed(4));
  }

  /**
   * Evaluates if string has anomalously high entropy (typical for base64 shellcode / encrypted exploits)
   */
  static isAnomalousEntropy(input, threshold = 4.5) {
    if (!input || input.length < 16) return false;
    return this.calculate(input) >= threshold;
  }
}

class ThreatDetector {
  static SIGNATURES = [
    { type: 'SQL_INJECTION', regex: /(\bUNION\b\s+\bSELECT\b|'\s*OR\s*'1'\s*=\s*'1|;\s*DROP\s+TABLE|--\s*$)/i },
    { type: 'PATH_TRAVERSAL', regex: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/)/i },
    { type: 'XSS_INJECTION', regex: /(<script\b[^>]*>|javascript:\s*|onload\s*=\s*|alert\s*\(|document\.cookie)/i },
    { type: 'COMMAND_INJECTION', regex: /(;\s*cat\s+\/etc\/passwd|\|\s*nc\s+-[lve]|`id`|\$\(whoami\))/i }
  ];

  static scan(text) {
    if (!text || typeof text !== 'string') return null;

    let target = text;
    try {
      target = decodeURIComponent(text);
    } catch (e) {
      // keep raw text if decoding fails
    }

    for (const sig of this.SIGNATURES) {
      if (sig.regex.test(text) || sig.regex.test(target)) {
        return {
          threatDetected: true,
          type: sig.type,
          matchedPattern: sig.regex.toString()
        };
      }
    }

    return { threatDetected: false };
  }
}

class RollingStats {
  constructor(windowSize = 60) {
    this.windowSize = windowSize;
    this.samples = [];
  }

  add(value) {
    this.samples.push(value);
    if (this.samples.length > this.windowSize) {
      this.samples.shift();
    }
  }

  getMean() {
    if (this.samples.length === 0) return 0;
    const sum = this.samples.reduce((acc, v) => acc + v, 0);
    return sum / this.samples.length;
  }

  getStdDev() {
    if (this.samples.length < 2) return 0;
    const mean = this.getMean();
    const variance = this.samples.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / (this.samples.length - 1);
    return Math.sqrt(variance);
  }

  getZScore(value) {
    const stdDev = this.getStdDev();
    if (stdDev === 0) return 0;
    return (value - this.getMean()) / stdDev;
  }
}

class LogStreamEngine {
  constructor(options = {}) {
    this.bufferCapacity = options.bufferCapacity || 500;
    this.zScoreThreshold = options.zScoreThreshold || 3.0; // 3 sigma
    this.buffer = [];
    this.rollingErrorRate = new RollingStats(30);

    this.metrics = {
      totalProcessed: 0,
      totalErrors: 0,
      totalWarnings: 0,
      totalThreats: 0,
      totalAnomalies: 0,
      startTime: Date.now()
    };
  }

  ingest(rawLog) {
    const parsed = LogParser.parse(rawLog);
    const entropy = ShannonEntropy.calculate(parsed.path || parsed.message);
    const threat = ThreatDetector.scan(parsed.path || parsed.message);

    const isError = ['ERROR', 'CRITICAL', 'FATAL'].includes(parsed.level) || (parsed.statusCode >= 500);
    const isWarn = parsed.level === 'WARN' || (parsed.statusCode >= 400 && parsed.statusCode < 500);

    this.metrics.totalProcessed++;
    if (isError) this.metrics.totalErrors++;
    if (isWarn) this.metrics.totalWarnings++;
    if (threat && threat.threatDetected) this.metrics.totalThreats++;

    // Update rolling error rate
    this.rollingErrorRate.add(isError ? 1 : 0);
    const currentErrorZ = this.rollingErrorRate.getZScore(isError ? 1 : 0);
    const isVolumetricSpike = currentErrorZ >= this.zScoreThreshold;

    const isHighEntropy = ShannonEntropy.isAnomalousEntropy(parsed.path || parsed.message, 4.6);
    const anomalyDetected = isVolumetricSpike || isHighEntropy || (threat && threat.threatDetected);

    if (anomalyDetected) this.metrics.totalAnomalies++;

    const enrichedEvent = {
      id: this.metrics.totalProcessed,
      timestamp: Date.now(),
      format: parsed.format,
      level: parsed.level,
      clientIp: parsed.clientIp,
      method: parsed.method || null,
      path: parsed.path || null,
      statusCode: parsed.statusCode || null,
      message: parsed.message,
      entropy,
      isHighEntropy,
      threat: threat || { threatDetected: false },
      anomalyDetected,
      isVolumetricSpike,
      zScore: Number(currentErrorZ.toFixed(2))
    };

    this.buffer.push(enrichedEvent);
    if (this.buffer.length > this.bufferCapacity) {
      this.buffer.shift();
    }

    return enrichedEvent;
  }

  getRecentEvents(limit = 50) {
    return this.buffer.slice(-limit);
  }

  getAnomalies(limit = 20) {
    return this.buffer.filter(e => e.anomalyDetected).slice(-limit);
  }

  getStats() {
    const uptimeSec = Math.max(1, Math.floor((Date.now() - this.metrics.startTime) / 1000));
    const throughputPerSec = Number((this.metrics.totalProcessed / uptimeSec).toFixed(2));
    const errorRatePct = this.metrics.totalProcessed > 0
      ? Number(((this.metrics.totalErrors / this.metrics.totalProcessed) * 100).toFixed(2))
      : 0;

    return {
      totalProcessed: this.metrics.totalProcessed,
      totalErrors: this.metrics.totalErrors,
      totalWarnings: this.metrics.totalWarnings,
      totalThreats: this.metrics.totalThreats,
      totalAnomalies: this.metrics.totalAnomalies,
      errorRatePct,
      throughputPerSec,
      bufferSize: this.buffer.length,
      uptimeSeconds: uptimeSec
    };
  }
}

module.exports = {
  LogParser,
  ShannonEntropy,
  ThreatDetector,
  RollingStats,
  LogStreamEngine
};