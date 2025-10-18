/**
 * WebSecurity SaaS - Konfigurationsmanagement
 * Zentrale Konfiguration für alle Services und Umgebungen
 */

import dotenv from 'dotenv';
import path from 'path';
import { ServiceConfig, BrowserConfig, AIConfig, ScanProfile } from '../types';

// Environment-Variablen laden
dotenv.config();

// Basis-Konfiguration Interface
interface AppConfig extends ServiceConfig {
  app: {
    name: string;
    version: string;
    environment: 'development' | 'staging' | 'production';
    port: number;
    debug: boolean;
  };
  security: {
    rateLimitWindowMs: number;
    rateLimitMaxRequests: number;
    maxScanTimeout: number;
    allowedOrigins: string[];
  };
}

// Hilfsfunktion für Environment-Variablen mit Fallback
function getEnvVar(key: string, defaultValue: string): string;
function getEnvVar(key: string, defaultValue: number): number;
function getEnvVar(key: string, defaultValue: boolean): boolean;
function getEnvVar(key: string, defaultValue: string[]): string[];
function getEnvVar(key: string, defaultValue: any): any {
  const value = process.env[key];
  
  if (value === undefined) {
    return defaultValue;
  }
  
  // Boolean-Konvertierung
  if (typeof defaultValue === 'boolean') {
    return value.toLowerCase() === 'true';
  }
  
  // Number-Konvertierung
  if (typeof defaultValue === 'number') {
    const parsed = parseInt(value, 10);
    return isNaN(parsed) ? defaultValue : parsed;
  }
  
  // Array-Konvertierung (komma-separiert)
  if (Array.isArray(defaultValue)) {
    return value.split(',').map(item => item.trim());
  }
  
  return value;
}

// Browser-Konfiguration
const browserConfig: BrowserConfig = {
  headless: getEnvVar('CHROME_HEADLESS', true),
  viewport: {
    width: getEnvVar('CHROME_VIEWPORT_WIDTH', 1920),
    height: getEnvVar('CHROME_VIEWPORT_HEIGHT', 1080)
  },
  timeout: getEnvVar('CHROME_TIMEOUT', 30000),
  executablePath: process.env.CHROME_EXECUTABLE_PATH,
  args: [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-accelerated-2d-canvas',
    '--no-first-run',
    '--no-zygote',
    '--disable-gpu',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding'
  ]
};

// AI-Konfiguration (Google Genkit)
const aiConfig: AIConfig = {
  model: getEnvVar('GENKIT_MODEL', 'gemini-1.5-pro'),
  temperature: parseFloat(getEnvVar('AI_TEMPERATURE', '0.3')),
  maxTokens: getEnvVar('AI_MAX_TOKENS', 4096),
  confidenceThreshold: parseFloat(getEnvVar('AI_CONFIDENCE_THRESHOLD', '0.7')),
  enablePatternRecognition: getEnvVar('AI_ENABLE_PATTERN_RECOGNITION', true),
  enableRiskScoring: getEnvVar('AI_ENABLE_RISK_SCORING', true)
};

// Haupt-Konfiguration
export const config: AppConfig = {
  app: {
    name: 'WebSecurity SaaS',
    version: '1.0.0',
    environment: (process.env.NODE_ENV as any) || 'development',
    port: getEnvVar('PORT', 3000),
    debug: getEnvVar('DEBUG', false)
  },
  
  chrome: browserConfig,
  
  genkit: aiConfig,
  
  scan: {
    maxConcurrentScans: getEnvVar('MAX_CONCURRENT_SCANS', 5),
    defaultTimeout: getEnvVar('SCAN_TIMEOUT', 60000),
    retryAttempts: getEnvVar('AI_MAX_RETRIES', 3),
    retryDelay: 1000
  },
  
  logging: {
    level: getEnvVar('LOG_LEVEL', 'info'),
    format: getEnvVar('LOG_FORMAT', 'json'),
    file: process.env.LOG_FILE
  },
  
  security: {
    rateLimitWindowMs: getEnvVar('RATE_LIMIT_WINDOW_MS', 900000), // 15 Minuten
    rateLimitMaxRequests: getEnvVar('RATE_LIMIT_MAX_REQUESTS', 100),
    maxScanTimeout: 300000, // 5 Minuten Maximum
    allowedOrigins: getEnvVar('ALLOWED_ORIGINS', ['http://localhost:3000'])
  }
};

// Scan-Profile laden
export const scanProfiles: Record<string, ScanProfile> = {
  quick: {
    name: 'Quick Scan',
    description: 'Schnelle Basis-Sicherheitsprüfung',
    enabledChecks: ['security_headers', 'cookies', 'ssl'],
    maxDepth: 1,
    followRedirects: true,
    checkSubdomains: false
  },
  
  standard: {
    name: 'Standard Scan',
    description: 'Umfassende Sicherheitsprüfung',
    enabledChecks: ['xss', 'csrf', 'security_headers', 'cookies', 'mixed_content', 'ssl'],
    maxDepth: 2,
    followRedirects: true,
    checkSubdomains: false
  },
  
  comprehensive: {
    name: 'Comprehensive Scan',
    description: 'Vollständige Sicherheitsanalyse mit AI-Unterstützung',
    enabledChecks: ['xss', 'csrf', 'security_headers', 'cookies', 'mixed_content', 'ssl', 'javascript_vulnerabilities'],
    maxDepth: 3,
    followRedirects: true,
    checkSubdomains: true
  },
  
  compliance: {
    name: 'Compliance Scan',
    description: 'OWASP und GDPR Compliance-Prüfung',
    enabledChecks: ['security_headers', 'cookies', 'ssl', 'csrf'],
    maxDepth: 2,
    followRedirects: true,
    checkSubdomains: false
  }
};

// Google Cloud / Genkit spezifische Konfiguration
export const genkitConfig = {
  projectId: getEnvVar('GENKIT_PROJECT_ID', ''),
  region: getEnvVar('GENKIT_REGION', 'us-central1'),
  apiKey: process.env.GENKIT_API_KEY,
  
  // Model-spezifische Einstellungen
  models: {
    'gemini-1.5-pro': {
      maxTokens: 8192,
      temperature: 0.3,
      topP: 0.8,
      topK: 40
    },
    'gemini-1.5-flash': {
      maxTokens: 4096,
      temperature: 0.2,
      topP: 0.9,
      topK: 32
    }
  },
  
  // Prompt-Templates
  prompts: {
    securityAnalysis: `
      Analysiere die folgenden Websicherheits-Scan-Ergebnisse und bewerte:
      1. Schweregrad der gefundenen Schwachstellen
      2. Potenzielle Auswirkungen auf die Sicherheit
      3. Priorität der Behebung
      4. Konkrete Empfehlungen zur Verbesserung
      
      Scan-Ergebnisse: {scanResults}
      
      Antworte im JSON-Format mit strukturierten Insights und Empfehlungen.
    `,
    
    riskScoring: `
      Berechne einen Risiko-Score (0-100) basierend auf den folgenden Sicherheitsbefunden:
      {findings}
      
      Berücksichtige dabei:
      - OWASP Top 10 Kategorien
      - Schweregrad der einzelnen Befunde
      - Kombinierte Auswirkungen mehrerer Schwachstellen
      - Branchenstandards und Best Practices
    `,
    
    patternRecognition: `
      Erkenne Sicherheitsmuster und Anomalien in den folgenden Daten:
      {pageData}
      
      Suche nach:
      - Ungewöhnlichen Konfigurationen
      - Bekannten Angriffsvektoren
      - Sicherheits-Anti-Patterns
      - Compliance-Verstößen
    `
  }
};

// Validierung der Konfiguration
export function validateConfig(): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Genkit API Key prüfen
  if (!genkitConfig.apiKey) {
    errors.push('GENKIT_API_KEY ist nicht gesetzt');
  }
  
  // Chrome Executable prüfen (nur in Produktion)
  if (config.app.environment === 'production' && !config.chrome.executablePath) {
    errors.push('CHROME_EXECUTABLE_PATH ist in Produktion erforderlich');
  }
  
  // Timeout-Werte validieren
  if (config.scan.defaultTimeout > config.security.maxScanTimeout) {
    errors.push('SCAN_TIMEOUT darf nicht größer als maxScanTimeout sein');
  }
  
  // AI-Konfiguration validieren
  if (config.genkit.temperature < 0 || config.genkit.temperature > 1) {
    errors.push('AI_TEMPERATURE muss zwischen 0 und 1 liegen');
  }
  
  if (config.genkit.confidenceThreshold < 0 || config.genkit.confidenceThreshold > 1) {
    errors.push('AI_CONFIDENCE_THRESHOLD muss zwischen 0 und 1 liegen');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

// Konfiguration für verschiedene Umgebungen
export function getEnvironmentConfig(): Partial<AppConfig> {
  switch (config.app.environment) {
    case 'development':
      return {
        logging: {
          level: 'debug',
          format: 'simple'
        },
        chrome: {
          ...config.chrome,
          headless: false // Browser sichtbar in Entwicklung
        }
      };
      
    case 'staging':
      return {
        logging: {
          level: 'info',
          format: 'json'
        },
        scan: {
          ...config.scan,
          maxConcurrentScans: 3 // Weniger parallele Scans in Staging
        }
      };
      
    case 'production':
      return {
        logging: {
          level: 'warn',
          format: 'json',
          file: '/var/log/websecurity/app.log'
        },
        chrome: {
          ...config.chrome,
          headless: true,
          args: [
            ...config.chrome.args || [],
            '--disable-logging',
            '--disable-extensions'
          ]
        }
      };
      
    default:
      return {};
  }
}

// Merged Konfiguration mit umgebungsspezifischen Overrides
export const finalConfig: AppConfig = {
  ...config,
  ...getEnvironmentConfig()
};

// Export der wichtigsten Konfigurationen
export { browserConfig, aiConfig, genkitConfig };
export default finalConfig;

