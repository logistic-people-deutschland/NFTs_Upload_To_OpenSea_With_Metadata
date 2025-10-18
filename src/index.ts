/**
 * WebSecurity SaaS - Main Entry Point
 * Haupteinstiegspunkt für die Anwendung
 */

export { ChromeDevToolsService } from './services/ChromeDevToolsService';
export { GenkitAnalysisService } from './services/GenkitAnalysisService';
export { ScanOrchestrator } from './services/ScanOrchestrator';

export * from './types';
export { config, scanProfiles, validateConfig } from './config';
export { logger, ServiceLogger, createServiceLogger } from './utils/Logger';

// Hauptfunktion für programmatische Nutzung
export async function createWebSecurityScanner() {
  const { ScanOrchestrator } = await import('./services/ScanOrchestrator');
  return new ScanOrchestrator();
}

// Version und Metadaten
export const VERSION = '1.0.0';
export const NAME = 'WebSecurity SaaS PoC';

// Default Export für einfache Nutzung
export default {
  createWebSecurityScanner,
  VERSION,
  NAME
};

