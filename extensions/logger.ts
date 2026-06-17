/**
 * Logger utility for pi-secret-sentinel
 * Provides structured logging with consistent formatting and level control.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

let currentLevel: LogLevel = "info";

/**
 * Set the minimum log level.
 */
export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

/**
 * Format a log message with the package prefix.
 */
function formatMessage(level: LogLevel, message: string): string {
  return `[pi-secret-sentinel] [${level.toUpperCase()}] ${message}`;
}

/**
 * Log a debug message.
 */
export function logDebug(message: string): void {
  if (LOG_LEVELS[currentLevel] <= LOG_LEVELS.debug) {
    console.debug(formatMessage("debug", message));
  }
}

/**
 * Log an info message.
 */
export function logInfo(message: string): void {
  if (LOG_LEVELS[currentLevel] <= LOG_LEVELS.info) {
    console.log(formatMessage("info", message));
  }
}

/**
 * Log a warning message.
 */
export function logWarn(message: string): void {
  if (LOG_LEVELS[currentLevel] <= LOG_LEVELS.warn) {
    console.warn(formatMessage("warn", message));
  }
}

/**
 * Log an error message.
 */
export function logError(message: string): void {
  if (LOG_LEVELS[currentLevel] <= LOG_LEVELS.error) {
    console.error(formatMessage("error", message));
  }
}
