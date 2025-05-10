const fs = require('fs');
const path = require('path');

class Logger {
  constructor(logLevel = 1, logFile = null) {
    this.logLevel = logLevel; // 0: No output, 1: Status log, 2: Debug log
    this.logFile = logFile;

    if (this.logFile) {
      // Ensure log file directory exists
      const dir = path.dirname(this.logFile);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }
  }

  // Format the time for log headers
  _getCurrentTime() {
    const now = new Date();
    return now.toISOString(); // Outputs ISO format timestamp
  }

  // Base log method
  _log(level, message) {
    if (this.logLevel >= level) {
      const time = this._getCurrentTime();
      const logMessage = `[${time}] ${message}`;

      if (this.logFile) {
        fs.appendFileSync(this.logFile, logMessage + '\n'); // Write to file
        console.log(logMessage); 
      } else {
        console.log(logMessage); 
      }
    }
  }

  // Public methods for different log levels
  status(message) {
    this._log(1, `STATUS: ${message}`);
  }

  debug(message) {
    //this._log(2, `DEBUG: ${message}`);
    //console.log(message); 
  }

  error(message) {
    this._log(1, `ERROR: ${message}`); // Errors can be logged at level 1
  }

  setLogLevel(level) {
    this.logLevel = level;
  }
}

module.exports = Logger;
