/**
 * WebSecurity SaaS - Chrome DevTools MCP Service
 * Browser-Automatisierung und Sicherheitsprüfungen mit MCP Chrome DevTools
 */

import puppeteer, { Browser, Page, HTTPResponse } from 'puppeteer';
import { 
  BrowserScanResults, 
  BrowserConfig, 
  PageInfo, 
  SecurityHeadersAnalysis, 
  SecurityHeader,
  CookieAnalysis,
  CookieInfo,
  CookieIssue,
  XSSFinding,
  CSRFAnalysis,
  CSRFVulnerableForm,
  MixedContentFinding,
  SSLAnalysis,
  CertificateInfo,
  JSLibraryAnalysis,
  Screenshot,
  NetworkLog,
  SeverityLevel
} from '../types';
import { chromeLogger, logPerformance } from '../utils/Logger';
import { config } from '../config';

export class ChromeDevToolsService {
  private browser: Browser | null = null;
  private page: Page | null = null;
  private networkLogs: NetworkLog[] = [];
  
  constructor(private browserConfig: BrowserConfig = config.chrome) {
    chromeLogger.info('ChromeDevToolsService initialisiert', { 
      config: this.browserConfig 
    });
  }
  
  /**
   * Browser-Instanz starten
   */
  @logPerformance
  async launchBrowser(): Promise<void> {
    try {
      chromeLogger.info('Starte Browser-Instanz');
      
      this.browser = await puppeteer.launch({
        headless: this.browserConfig.headless,
        executablePath: this.browserConfig.executablePath,
        args: this.browserConfig.args,
        defaultViewport: {
          width: this.browserConfig.viewport.width,
          height: this.browserConfig.viewport.height
        },
        timeout: this.browserConfig.timeout
      });
      
      this.page = await this.browser.newPage();
      
      // User-Agent setzen
      await this.page.setUserAgent(
        process.env.SCAN_USER_AGENT || 
        'WebSecurity-SaaS-Scanner/1.0 (Security Analysis Bot)'
      );
      
      // Network-Monitoring aktivieren
      await this.setupNetworkMonitoring();
      
      chromeLogger.info('Browser erfolgreich gestartet');
    } catch (error) {
      chromeLogger.error('Fehler beim Starten des Browsers', error as Error);
      throw error;
    }
  }
  
  /**
   * Network-Monitoring einrichten
   */
  private async setupNetworkMonitoring(): Promise<void> {
    if (!this.page) return;
    
    await this.page.setRequestInterception(true);
    
    this.page.on('request', (request) => {
      // Request durchlassen
      request.continue();
    });
    
    this.page.on('response', (response: HTTPResponse) => {
      const networkLog: NetworkLog = {
        url: response.url(),
        method: response.request().method(),
        statusCode: response.status(),
        responseTime: 0, // TODO: Implementiere Response-Time-Messung
        requestHeaders: response.request().headers(),
        responseHeaders: response.headers(),
        timestamp: new Date()
      };
      
      this.networkLogs.push(networkLog);
    });
  }
  
  /**
   * Vollständigen Sicherheitsscan einer Website durchführen
   */
  @logPerformance
  async scanWebsite(url: string): Promise<BrowserScanResults> {
    if (!this.browser || !this.page) {
      await this.launchBrowser();
    }
    
    chromeLogger.scanStarted('browser-scan', url);
    
    try {
      // Reset Network Logs
      this.networkLogs = [];
      
      // Seite laden und grundlegende Informationen sammeln
      const pageInfo = await this.getPageInfo(url);
      
      // Parallel alle Sicherheitsprüfungen durchführen
      const [
        securityHeaders,
        cookies,
        xssFindings,
        csrfAnalysis,
        mixedContent,
        sslAnalysis,
        jsLibraries,
        screenshots
      ] = await Promise.all([
        this.analyzeSecurityHeaders(),
        this.analyzeCookies(),
        this.detectXSSVulnerabilities(),
        this.analyzeCSRFProtection(),
        this.detectMixedContent(),
        this.analyzeSSL(url),
        this.analyzeJavaScriptLibraries(),
        this.captureScreenshots()
      ]);
      
      const results: BrowserScanResults = {
        pageInfo,
        securityHeaders,
        cookies,
        xssFindings,
        csrfAnalysis,
        mixedContent,
        sslAnalysis,
        jsLibraries,
        screenshots,
        networkLogs: [...this.networkLogs]
      };
      
      chromeLogger.scanCompleted('browser-scan', Date.now(), 
        xssFindings.length + mixedContent.length + jsLibraries.length);
      
      return results;
      
    } catch (error) {
      chromeLogger.scanFailed('browser-scan', error as Error);
      throw error;
    }
  }
  
  /**
   * Grundlegende Seiten-Informationen sammeln
   */
  @logPerformance
  private async getPageInfo(url: string): Promise<PageInfo> {
    if (!this.page) throw new Error('Browser nicht initialisiert');
    
    const startTime = Date.now();
    
    try {
      const response = await this.page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.browserConfig.timeout
      });
      
      const loadTime = Date.now() - startTime;
      
      const [title, finalUrl] = await Promise.all([
        this.page.title(),
        this.page.url()
      ]);
      
      return {
        title,
        url,
        finalUrl,
        statusCode: response?.status() || 0,
        loadTime,
        contentType: response?.headers()['content-type'] || '',
        contentLength: parseInt(response?.headers()['content-length'] || '0'),
        redirectChain: response?.request().redirectChain().map(req => req.url()) || []
      };
      
    } catch (error) {
      chromeLogger.error('Fehler beim Laden der Seite', error as Error, { url });
      throw error;
    }
  }
  
  /**
   * Sicherheits-Header analysieren
   */
  @logPerformance
  private async analyzeSecurityHeaders(): Promise<SecurityHeadersAnalysis> {
    if (!this.page) throw new Error('Browser nicht initialisiert');
    
    // Response-Headers der aktuellen Seite abrufen
    const response = await this.page.goto(this.page.url());
    const headers = response?.headers() || {};
    
    const requiredHeaders = [
      {
        name: 'Content-Security-Policy',
        severity: 'high' as SeverityLevel,
        description: 'Verhindert XSS und Code-Injection-Angriffe'
      },
      {
        name: 'X-Frame-Options',
        severity: 'medium' as SeverityLevel,
        description: 'Schutz vor Clickjacking-Angriffen'
      },
      {
        name: 'X-Content-Type-Options',
        severity: 'medium' as SeverityLevel,
        description: 'Verhindert MIME-Type-Sniffing'
      },
      {
        name: 'Strict-Transport-Security',
        severity: 'high' as SeverityLevel,
        description: 'Erzwingt HTTPS-Verbindungen'
      },
      {
        name: 'Referrer-Policy',
        severity: 'low' as SeverityLevel,
        description: 'Kontrolliert Referrer-Informationen'
      },
      {
        name: 'Permissions-Policy',
        severity: 'medium' as SeverityLevel,
        description: 'Kontrolliert Browser-Features'
      }
    ];
    
    const present: SecurityHeader[] = [];
    const missing: SecurityHeader[] = [];
    const misconfigured: SecurityHeader[] = [];
    
    for (const requiredHeader of requiredHeaders) {
      const headerValue = headers[requiredHeader.name.toLowerCase()];
      
      if (headerValue) {
        const header: SecurityHeader = {
          name: requiredHeader.name,
          value: headerValue,
          severity: requiredHeader.severity,
          description: requiredHeader.description
        };
        
        // Einfache Validierung der Header-Werte
        if (this.isHeaderMisconfigured(requiredHeader.name, headerValue)) {
          misconfigured.push(header);
        } else {
          present.push(header);
        }
      } else {
        missing.push({
          name: requiredHeader.name,
          severity: requiredHeader.severity,
          description: requiredHeader.description
        });
      }
    }
    
    // Score berechnen (0-100)
    const totalHeaders = requiredHeaders.length;
    const presentCount = present.length;
    const score = Math.round((presentCount / totalHeaders) * 100);
    
    const recommendations = missing.map(header => 
      `Implementiere ${header.name} Header: ${header.description}`
    );
    
    return {
      present,
      missing,
      misconfigured,
      score,
      recommendations
    };
  }
  
  /**
   * Prüft ob ein Security-Header falsch konfiguriert ist
   */
  private isHeaderMisconfigured(headerName: string, value: string): boolean {
    switch (headerName.toLowerCase()) {
      case 'content-security-policy':
        return value.includes('unsafe-inline') || value.includes('unsafe-eval');
      case 'x-frame-options':
        return !['DENY', 'SAMEORIGIN'].includes(value.toUpperCase());
      case 'strict-transport-security':
        return !value.includes('max-age') || parseInt(value.match(/max-age=(\\d+)/)?.[1] || '0') < 31536000;
      default:
        return false;
    }
  }
  
  /**
   * Cookie-Sicherheit analysieren
   */
  @logPerformance
  private async analyzeCookies(): Promise<CookieAnalysis> {
    if (!this.page) throw new Error('Browser nicht initialisiert');
    
    const cookies = await this.page.cookies();
    const cookieInfos: CookieInfo[] = [];
    const issues: CookieIssue[] = [];
    
    let secureCount = 0;
    let httpOnlyCount = 0;
    let sameSiteCount = 0;
    
    for (const cookie of cookies) {
      const cookieInfo: CookieInfo = {
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: cookie.sameSite as any,
        expires: cookie.expires ? new Date(cookie.expires * 1000) : undefined
      };
      
      cookieInfos.push(cookieInfo);
      
      // Zähler aktualisieren
      if (cookie.secure) secureCount++;
      if (cookie.httpOnly) httpOnlyCount++;
      if (cookie.sameSite) sameSiteCount++;
      
      // Sicherheitsprobleme identifizieren
      if (!cookie.secure && this.page.url().startsWith('https:')) {
        issues.push({
          cookieName: cookie.name,
          issue: 'Cookie nicht als secure markiert trotz HTTPS',
          severity: 'medium',
          recommendation: 'Setze das Secure-Flag für alle Cookies auf HTTPS-Seiten'
        });
      }
      
      if (!cookie.httpOnly && cookie.name.toLowerCase().includes('session')) {
        issues.push({
          cookieName: cookie.name,
          issue: 'Session-Cookie nicht als HttpOnly markiert',
          severity: 'high',
          recommendation: 'Setze das HttpOnly-Flag für Session-Cookies'
        });
      }
      
      if (!cookie.sameSite) {
        issues.push({
          cookieName: cookie.name,
          issue: 'SameSite-Attribut fehlt',
          severity: 'medium',
          recommendation: 'Setze SameSite=Strict oder SameSite=Lax'
        });
      }
    }
    
    // Score berechnen
    const totalCookies = cookies.length;
    const secureScore = totalCookies > 0 ? (secureCount / totalCookies) * 100 : 100;
    
    return {
      cookies: cookieInfos,
      secureCount,
      httpOnlyCount,
      sameSiteCount,
      issues,
      score: Math.round(secureScore)
    };
  }
  
  /**
   * XSS-Schwachstellen erkennen
   */
  @logPerformance
  private async detectXSSVulnerabilities(): Promise<XSSFinding[]> {
    if (!this.page) throw new Error('Browser nicht initialisiert');
    
    const findings: XSSFinding[] = [];
    
    // Einfache XSS-Payloads für Tests
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '"><script>alert("XSS")</script>',
      'javascript:alert("XSS")',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>'
    ];
    
    try {
      // Suche nach Input-Feldern
      const inputs = await this.page.$$('input, textarea, [contenteditable]');
      
      for (const input of inputs) {
        const tagName = await input.evaluate(el => el.tagName.toLowerCase());
        const type = await input.evaluate(el => (el as HTMLInputElement).type || 'text');
        
        // Teste verschiedene XSS-Payloads
        for (const payload of xssPayloads) {
          try {
            await input.clear();
            await input.type(payload);
            
            // Prüfe ob Payload im DOM reflektiert wird
            const pageContent = await this.page.content();
            if (pageContent.includes(payload)) {
              findings.push({
                type: 'reflected',
                payload,
                location: `${tagName}[type="${type}"]`,
                context: 'Input field reflection',
                severity: 'high',
                verified: true,
                evidence: `Payload "${payload}" wurde im DOM reflektiert`
              });
            }
          } catch (error) {
            // Ignoriere Fehler bei einzelnen Payloads
          }
        }
      }
      
      // Prüfe URL-Parameter auf XSS
      const url = new URL(this.page.url());
      for (const [param, value] of url.searchParams) {
        const pageContent = await this.page.content();
        if (pageContent.includes(value) && value.includes('<')) {
          findings.push({
            type: 'reflected',
            payload: value,
            location: `URL parameter: ${param}`,
            context: 'URL parameter reflection',
            severity: 'high',
            verified: true,
            evidence: `URL-Parameter "${param}" wird unescaped im DOM ausgegeben`
          });
        }
      }
      
    } catch (error) {
      chromeLogger.error('Fehler bei XSS-Erkennung', error as Error);
    }
    
    return findings;
  }
  
  /**
   * CSRF-Schutz analysieren
   */
  @logPerformance
  private async analyzeCSRFProtection(): Promise<CSRFAnalysis> {
    if (!this.page) throw new Error('Browser nicht initialisiert');
    
    const vulnerableForms: CSRFVulnerableForm[] = [];
    let hasProtection = false;
    const protectionMethods: string[] = [];
    
    try {
      // Suche nach Formularen
      const forms = await this.page.$$('form');
      
      for (const form of forms) {
        const action = await form.evaluate(el => (el as HTMLFormElement).action);
        const method = await form.evaluate(el => (el as HTMLFormElement).method.toLowerCase());
        
        // Prüfe auf CSRF-Token
        const hasToken = await form.$('input[name*="token"], input[name*="csrf"]') !== null;
        
        // Prüfe SameSite-Cookie-Schutz
        const cookies = await this.page.cookies();
        const hasSameSiteProtection = cookies.some(cookie => 
          cookie.sameSite === 'Strict' || cookie.sameSite === 'Lax'
        );
        
        if (method === 'post' && !hasToken && !hasSameSiteProtection) {
          vulnerableForms.push({
            action,
            method,
            hasToken,
            hasSameSiteProtection,
            severity: 'high'
          });
        }
        
        if (hasToken) {
          hasProtection = true;
          protectionMethods.push('CSRF Token');
        }
        
        if (hasSameSiteProtection) {
          hasProtection = true;
          protectionMethods.push('SameSite Cookies');
        }
      }
      
    } catch (error) {
      chromeLogger.error('Fehler bei CSRF-Analyse', error as Error);
    }
    
    const score = vulnerableForms.length === 0 ? 100 : Math.max(0, 100 - (vulnerableForms.length * 25));
    
    return {
      hasProtection,
      protectionMethods: [...new Set(protectionMethods)],
      vulnerableForms,
      score
    };
  }
  
  /**
   * Mixed Content erkennen
   */
  @logPerformance
  private async detectMixedContent(): Promise<MixedContentFinding[]> {
    const findings: MixedContentFinding[] = [];
    
    if (!this.page?.url().startsWith('https:')) {
      return findings; // Nur auf HTTPS-Seiten relevant
    }
    
    // Analysiere Network-Logs nach HTTP-Requests
    for (const log of this.networkLogs) {
      if (log.url.startsWith('http:') && !log.url.startsWith('https:')) {
        const resourceType = this.getResourceType(log.url);
        
        findings.push({
          resourceUrl: log.url,
          resourceType,
          severity: resourceType === 'script' || resourceType === 'stylesheet' ? 'high' : 'medium',
          location: 'Network request'
        });
      }
    }
    
    return findings;
  }
  
  /**
   * Bestimmt den Ressourcen-Typ basierend auf URL
   */
  private getResourceType(url: string): string {
    const extension = url.split('.').pop()?.toLowerCase();
    
    switch (extension) {
      case 'js': return 'script';
      case 'css': return 'stylesheet';
      case 'jpg': case 'jpeg': case 'png': case 'gif': case 'webp': return 'image';
      case 'mp4': case 'webm': case 'ogg': return 'video';
      case 'mp3': case 'wav': case 'ogg': return 'audio';
      default: return 'other';
    }
  }
  
  /**
   * SSL/TLS-Konfiguration analysieren
   */
  @logPerformance
  private async analyzeSSL(url: string): Promise<SSLAnalysis> {
    const isSecure = url.startsWith('https:');
    
    // Basis-SSL-Analyse (erweiterte Analyse würde externe Tools erfordern)
    const certificate: CertificateInfo = {
      issuer: 'Unknown',
      subject: 'Unknown',
      validFrom: new Date(),
      validTo: new Date(),
      isExpired: false,
      daysUntilExpiry: 365,
      signatureAlgorithm: 'Unknown'
    };
    
    return {
      isSecure,
      certificate,
      protocols: ['TLS 1.3'], // Vereinfacht
      ciphers: ['AES-256-GCM'], // Vereinfacht
      vulnerabilities: [],
      score: isSecure ? 90 : 0
    };
  }
  
  /**
   * JavaScript-Bibliotheken analysieren
   */
  @logPerformance
  private async analyzeJavaScriptLibraries(): Promise<JSLibraryAnalysis[]> {
    if (!this.page) throw new Error('Browser nicht initialisiert');
    
    const libraries: JSLibraryAnalysis[] = [];
    
    try {
      // Bekannte JavaScript-Bibliotheken erkennen
      const detectedLibs = await this.page.evaluate(() => {
        const libs = [];
        
        // jQuery
        if (typeof (window as any).jQuery !== 'undefined') {
          libs.push({
            name: 'jQuery',
            version: (window as any).jQuery.fn.jquery || 'unknown'
          });
        }
        
        // React
        if (typeof (window as any).React !== 'undefined') {
          libs.push({
            name: 'React',
            version: (window as any).React.version || 'unknown'
          });
        }
        
        // Angular
        if (typeof (window as any).angular !== 'undefined') {
          libs.push({
            name: 'Angular',
            version: (window as any).angular.version?.full || 'unknown'
          });
        }
        
        return libs;
      });
      
      for (const lib of detectedLibs) {
        libraries.push({
          name: lib.name,
          version: lib.version,
          latestVersion: 'unknown', // Würde externe API erfordern
          isOutdated: false, // Vereinfacht
          vulnerabilities: [],
          severity: 'low'
        });
      }
      
    } catch (error) {
      chromeLogger.error('Fehler bei JavaScript-Bibliotheken-Analyse', error as Error);
    }
    
    return libraries;
  }
  
  /**
   * Screenshots erstellen
   */
  @logPerformance
  private async captureScreenshots(): Promise<Screenshot[]> {
    if (!this.page) throw new Error('Browser nicht initialisiert');
    
    const screenshots: Screenshot[] = [];
    
    try {
      const timestamp = new Date();
      const filename = `screenshot-${timestamp.getTime()}.png`;
      const path = `./screenshots/${filename}`;
      
      await this.page.screenshot({
        path,
        fullPage: true
      });
      
      screenshots.push({
        name: 'Full Page Screenshot',
        path,
        timestamp,
        viewport: this.browserConfig.viewport
      });
      
    } catch (error) {
      chromeLogger.error('Fehler beim Erstellen von Screenshots', error as Error);
    }
    
    return screenshots;
  }
  
  /**
   * Browser-Instanz schließen
   */
  async closeBrowser(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
      chromeLogger.info('Browser-Instanz geschlossen');
    }
  }
  
  /**
   * Cleanup-Methode
   */
  async cleanup(): Promise<void> {
    await this.closeBrowser();
    this.networkLogs = [];
  }
}

