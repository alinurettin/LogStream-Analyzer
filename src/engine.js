class LogAnalyzerEngine {
  constructor(burstThreshold = 3, windowMs = 5000) {
    this.burstThreshold = burstThreshold;
    this.windowMs = windowMs;
    this.errorTimestamps = [];
  }
  parseLog(rawLog) {
    const isError = /ERROR|FATAL|Exception|500/i.test(rawLog);
    const timestamp = Date.now();
    let anomalyDetected = false;
    if (isError) {
      this.errorTimestamps.push(timestamp);
      this.cleanup();
      if (this.errorTimestamps.length >= this.burstThreshold) {
        anomalyDetected = true;
      }
    }
    return {
      timestamp,
      isError,
      anomalyDetected,
      recentErrorCount: this.errorTimestamps.length
    };
  }
  cleanup() {
    const cutoff = Date.now() - this.windowMs;
    this.errorTimestamps = this.errorTimestamps.filter(t => t > cutoff);
  }
}
module.exports = LogAnalyzerEngine;