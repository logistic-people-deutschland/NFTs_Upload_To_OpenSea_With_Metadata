/**
 * WebSecurity SaaS - Logging Utility
 * Strukturiertes Logging mit Winston für alle Services
 */

import winston from 'winston';
import path from 'path';

// Log-Level Definitionen
export type LogLevel = 'error' | 'warn' | 'info' | 'debug';

// Logger-Konfiguration Interface
interface LoggerConfig {
  level: LogLevel;
  format: 'json' | 'simple';
  file?: string;
  console: boolean;
}

// Standard-Konfiguration
const defaultConfig: LoggerConfig = {
  level: (process.env.LOG_LEVEL as LogLevel) || 'info',
  format: (process.env.LOG_FORMAT as 'json' | 'simple') || 'json',
  file: process.env.LOG_FILE,
  console: true
};

// Custom Log-Format für strukturierte Logs
const customFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS'
  }),
  winston.format.errors({ stack: true }),
  winston.format.metadata({
    fillExcept: ['message', 'level', 'timestamp', 'label']
  })
);

// JSON-Format für Produktion
const jsonFormat = winston.format.combine(
  customFormat,
  winston.format.json()
);

// Einfaches Format für Entwicklung
const simpleFormat = winston.format.combine(
  customFormat,
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, metadata, stack }) => {
    let log = `${timestamp} [${level}]: ${message}`;
    
    // Metadata hinzufügen wenn vorhanden
    if (Object.keys(metadata).length > 0) {
      log += ` ${JSON.stringify(metadata)}`;
    }
    
    // Stack Trace hinzufügen bei Fehlern
    if (stack) {
      log += `\n${stack}`;
    }
    
    return log;
  })
);

// Logger-Instanz erstellen
function createLogger(config: LoggerConfig = defaultConfig): winston.Logger {
  const transports: winston.transport[] = [];
  
  // Console Transport
  if (config.console) {
    transports.push(
      new winston.transports.Console({
        level: config.level,
        format: config.format === 'json' ? jsonFormat : simpleFormat
      })
    );
  }
  
  // File Transport
  if (config.file) {
    // Stelle sicher, dass das Log-Verzeichnis existiert
    const logDir = path.dirname(config.file);
    
    transports.push(
      new winston.transports.File({
        filename: config.file,
        level: config.level,
        format: jsonFormat,
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5,
        tailable: true
      })
    );
    
    // Separater Transport für Fehler
    transports.push(
      new winston.transports.File({
        filename: config.file.replace('.log', '.error.log'),
        level: 'error',
        format: jsonFormat,
        maxsize: 10 * 1024 * 1024,
        maxFiles: 5,
        tailable: true
      })
    );
  }
  
  return winston.createLogger({
    level: config.level,
    transports,
    // Verhindere Absturz bei unbehandelten Exceptions
    exitOnError: false,
    // Behandle unbehandelte Exceptions und Rejections
    exceptionHandlers: config.file ? [
      new winston.transports.File({
        filename: config.file.replace('.log', '.exceptions.log'),
        format: jsonFormat
      })
    ] : [],
    rejectionHandlers: config.file ? [
      new winston.transports.File({
        filename: config.file.replace('.log', '.rejections.log'),
        format: jsonFormat
      })
    ] : []
  });
}

// Haupt-Logger-Instanz
export const logger = createLogger();

// Logger-Klasse für Service-spezifische Logger
export class ServiceLogger {
  private logger: winston.Logger;
  private serviceName: string;
  
  constructor(serviceName: string, config?: Partial<LoggerConfig>) {
    this.serviceName = serviceName;
    this.logger = createLogger({ ...defaultConfig, ...config });
  }
  
  private formatMessage(message: string, metadata?: Record<string, any>): [string, Record<string, any>] {
    const enrichedMetadata = {
      service: this.serviceName,
      timestamp: new Date().toISOString(),
      ...metadata
    };
    
    return [message, enrichedMetadata];
  }
  
  error(message: string, error?: Error, metadata?: Record<string, any>): void {
    const [msg, meta] = this.formatMessage(message, {
      ...metadata,
      error: error ? {
        name: error.name,
        message: error.message,
        stack: error.stack
      } : undefined
    });
    
    this.logger.error(msg, meta);
  }
  
  warn(message: string, metadata?: Record<string, any>): void {
    const [msg, meta] = this.formatMessage(message, metadata);
    this.logger.warn(msg, meta);
  }
  
  info(message: string, metadata?: Record<string, any>): void {
    const [msg, meta] = this.formatMessage(message, metadata);
    this.logger.info(msg, meta);
  }
  
  debug(message: string, metadata?: Record<string, any>): void {
    const [msg, meta] = this.formatMessage(message, metadata);
    this.logger.debug(msg, meta);
  }
  
  // Spezielle Methoden für Scan-Events
  scanStarted(scanId: string, targetUrl: string, metadata?: Record<string, any>): void {
    this.info('Scan started', {
      scanId,
      targetUrl,
      event: 'scan_started',
      ...metadata
    });
  }
  
  scanProgress(scanId: string, step: string, progress: number, metadata?: Record<string, any>): void {
    this.info('Scan progress', {
      scanId,
      currentStep: step,
      progress,
      event: 'scan_progress',
      ...metadata
    });
  }
  
  scanCompleted(scanId: string, duration: number, findingsCount: number, metadata?: Record<string, any>): void {
    this.info('Scan completed', {
      scanId,
      duration,
      findingsCount,
      event: 'scan_completed',
      ...metadata
    });
  }
  
  scanFailed(scanId: string, error: Error, metadata?: Record<string, any>): void {
    this.error('Scan failed', error, {
      scanId,
      event: 'scan_failed',
      ...metadata
    });
  }
  
  // Performance-Logging
  performanceLog(operation: string, duration: number, metadata?: Record<string, any>): void {
    this.info('Performance metric', {
      operation,
      duration,
      event: 'performance',
      ...metadata
    });
  }
  
  // Security-Event-Logging
  securityEvent(eventType: string, severity: 'low' | 'medium' | 'high' | 'critical', details: Record<string, any>): void {
    this.warn('Security event detected', {
      eventType,
      severity,
      event: 'security_event',
      ...details
    });
  }
}

// Vordefinierte Service-Logger
export const chromeLogger = new ServiceLogger('ChromeDevTools');
export const genkitLogger = new ServiceLogger('GenkitAnalysis');
export const orchestratorLogger = new ServiceLogger('ScanOrchestrator');
export const apiLogger = new ServiceLogger('API');

// Utility-Funktionen
export function createServiceLogger(serviceName: string, config?: Partial<LoggerConfig>): ServiceLogger {
  return new ServiceLogger(serviceName, config);
}

// Performance-Messung Decorator
export function logPerformance(target: any, propertyName: string, descriptor: PropertyDescriptor) {
  const method = descriptor.value;
  
  descriptor.value = async function (...args: any[]) {
    const start = Date.now();
    const serviceName = target.constructor.name;
    const logger = new ServiceLogger(serviceName);
    
    try {
      const result = await method.apply(this, args);
      const duration = Date.now() - start;
      
      logger.performanceLog(`${propertyName}`, duration, {
        args: args.length,
        success: true
      });
      
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      
      logger.performanceLog(`${propertyName}`, duration, {
        args: args.length,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      throw error;
    }
  };
  
  return descriptor;
}

// Graceful Shutdown für Logger
export function shutdownLogger(): Promise<void> {
  return new Promise((resolve) => {
    logger.end(() => {
      resolve();
    });
  });
}

export default logger;

