/**
 * Tests für ChromeDevToolsService
 */

import { ChromeDevToolsService } from '../../src/services/ChromeDevToolsService';
import { BrowserConfig } from '../../src/types';

describe('ChromeDevToolsService', () => {
  let service: ChromeDevToolsService;
  
  const mockBrowserConfig: BrowserConfig = {
    headless: true,
    viewport: { width: 1920, height: 1080 },
    timeout: 30000,
    args: ['--no-sandbox']
  };
  
  beforeEach(() => {
    service = new ChromeDevToolsService(mockBrowserConfig);
  });
  
  afterEach(async () => {
    await service.cleanup();
  });
  
  describe('launchBrowser', () => {
    it('sollte Browser erfolgreich starten', async () => {
      await expect(service.launchBrowser()).resolves.not.toThrow();
    });
  });
  
  describe('scanWebsite', () => {
    it('sollte Website-Scan durchführen', async () => {
      const testUrl = 'https://example.com';
      
      const result = await service.scanWebsite(testUrl);
      
      expect(result).toBeDefined();
      expect(result.pageInfo).toBeDefined();
      expect(result.pageInfo.url).toBe(testUrl);
      expect(result.securityHeaders).toBeDefined();
      expect(result.cookies).toBeDefined();
      expect(result.xssFindings).toBeDefined();
      expect(result.csrfAnalysis).toBeDefined();
      expect(result.mixedContent).toBeDefined();
      expect(result.sslAnalysis).toBeDefined();
      expect(result.jsLibraries).toBeDefined();
      expect(result.screenshots).toBeDefined();
      expect(result.networkLogs).toBeDefined();
    });
    
    it('sollte Fehler bei ungültiger URL werfen', async () => {
      const invalidUrl = 'invalid-url';
      
      await expect(service.scanWebsite(invalidUrl)).rejects.toThrow();
    });
  });
  
  describe('Security Headers Analysis', () => {
    it('sollte fehlende Security Headers erkennen', async () => {
      await service.launchBrowser();
      
      // Private Methode über Reflection testen (nur für Demo)
      const result = await (service as any).analyzeSecurityHeaders();
      
      expect(result).toBeDefined();
      expect(result.present).toBeDefined();
      expect(result.missing).toBeDefined();
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });
  
  describe('Cookie Analysis', () => {
    it('sollte Cookie-Sicherheit analysieren', async () => {
      await service.launchBrowser();
      
      const result = await (service as any).analyzeCookies();
      
      expect(result).toBeDefined();
      expect(result.cookies).toBeDefined();
      expect(result.issues).toBeDefined();
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });
  
  describe('XSS Detection', () => {
    it('sollte XSS-Schwachstellen erkennen', async () => {
      await service.launchBrowser();
      
      const result = await (service as any).detectXSSVulnerabilities();
      
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });
  });
  
  describe('CSRF Analysis', () => {
    it('sollte CSRF-Schutz analysieren', async () => {
      await service.launchBrowser();
      
      const result = await (service as any).analyzeCSRFProtection();
      
      expect(result).toBeDefined();
      expect(result.hasProtection).toBeDefined();
      expect(result.protectionMethods).toBeDefined();
      expect(result.vulnerableForms).toBeDefined();
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });
  
  describe('Mixed Content Detection', () => {
    it('sollte Mixed Content erkennen', async () => {
      await service.launchBrowser();
      
      const result = await (service as any).detectMixedContent();
      
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });
  });
  
  describe('SSL Analysis', () => {
    it('sollte SSL-Konfiguration analysieren', async () => {
      const testUrl = 'https://example.com';
      
      const result = await (service as any).analyzeSSL(testUrl);
      
      expect(result).toBeDefined();
      expect(result.isSecure).toBeDefined();
      expect(result.certificate).toBeDefined();
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });
  
  describe('JavaScript Libraries Analysis', () => {
    it('sollte JavaScript-Bibliotheken analysieren', async () => {
      await service.launchBrowser();
      
      const result = await (service as any).analyzeJavaScriptLibraries();
      
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });
  });
  
  describe('Screenshots', () => {
    it('sollte Screenshots erstellen', async () => {
      await service.launchBrowser();
      
      const result = await (service as any).captureScreenshots();
      
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });
  });
  
  describe('Cleanup', () => {
    it('sollte Browser ordnungsgemäß schließen', async () => {
      await service.launchBrowser();
      await expect(service.cleanup()).resolves.not.toThrow();
    });
  });
});

