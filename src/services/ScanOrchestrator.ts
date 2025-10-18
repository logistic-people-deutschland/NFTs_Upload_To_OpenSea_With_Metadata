/**
 * WebSecurity SaaS - Scan Orchestrator
 * Zentrale Koordination zwischen Browser-Automatisierung und AI-Analyse
 */

import { 
  ScanConfig, 
  ScanResult, 
  ScanStatus, 
  ScanSummary, 
  ScanError,
  TopIssue,
  ComplianceStatus,
  SeverityLevel
} from '../types';
import { ChromeDevToolsService } from './ChromeDevToolsService';
import { GenkitAnalysisService } from './GenkitAnalysisService';
import { orchestratorLogger, logPerformance } from '../utils/Logger';
import { config } from '../config';

export class ScanOrchestrator {
  private chromeService: ChromeDevToolsService;
  private genkitService: GenkitAnalysisService;
  private activeScanIds: Set<string> = new Set();
  
  constructor() {
    this.chromeService = new ChromeDevToolsService();
    this.genkitService = new GenkitAnalysisService();
    
    orchestratorLogger.info('ScanOrchestrator initialisiert', {
      maxConcurrentScans: config.scan.maxConcurrentScans
    });
  }
  
  /**
   * Vollständigen Sicherheitsscan durchführen
   */
  @logPerformance
  async executeScan(scanConfig: ScanConfig): Promise<ScanResult> {
    const { scanId, targetUrl } = scanConfig;
    
    // Prüfe Concurrent-Limit
    if (this.activeScanIds.size >= config.scan.maxConcurrentScans) {
      throw new Error(`Maximale Anzahl gleichzeitiger Scans erreicht (${config.scan.maxConcurrentScans})`);
    }
    
    this.activeScanIds.add(scanId);
    
    const scanResult: ScanResult = {
      scanId,
      targetUrl,
      status: 'running',
      startedAt: new Date(),
      browserResults: {} as any,
      aiAnalysis: {} as any,
      summary: {} as any
    };
    
    orchestratorLogger.scanStarted(scanId, targetUrl, {
      profile: scanConfig.profile.name,
      timeout: scanConfig.timeout
    });
    
    try {
      // Phase 1: Browser-basierte Sicherheitsprüfung
      orchestratorLogger.scanProgress(scanId, 'Browser-Scan', 10);
      const browserResults = await this.executeBrowserScan(scanConfig);
      scanResult.browserResults = browserResults;
      
      // Phase 2: AI-gestützte Analyse
      orchestratorLogger.scanProgress(scanId, 'AI-Analyse', 60);
      const aiAnalysis = await this.executeAIAnalysis(browserResults);
      scanResult.aiAnalysis = aiAnalysis;
      
      // Phase 3: Zusammenfassung generieren
      orchestratorLogger.scanProgress(scanId, 'Zusammenfassung', 90);
      const summary = await this.generateScanSummary(browserResults, aiAnalysis);
      scanResult.summary = summary;
      
      // Scan erfolgreich abgeschlossen
      scanResult.status = 'completed';
      scanResult.completedAt = new Date();
      scanResult.duration = scanResult.completedAt.getTime() - scanResult.startedAt.getTime();
      
      orchestratorLogger.scanCompleted(scanId, scanResult.duration, summary.totalFindings);
      
      return scanResult;
      
    } catch (error) {
      // Fehler-Behandlung
      const scanError: ScanError = {
        code: 'SCAN_EXECUTION_ERROR',
        message: error instanceof Error ? error.message : 'Unbekannter Fehler',
        details: error instanceof Error ? error.stack : undefined,
        timestamp: new Date(),
        recoverable: this.isRecoverableError(error),
        retryCount: 0
      };
      
      scanResult.status = 'failed';
      scanResult.error = scanError;
      scanResult.completedAt = new Date();
      scanResult.duration = scanResult.completedAt.getTime() - scanResult.startedAt.getTime();
      
      orchestratorLogger.scanFailed(scanId, error as Error);
      
      return scanResult;
      
    } finally {
      // Cleanup
      this.activeScanIds.delete(scanId);
      await this.cleanup();
    }
  }
  
  /**
   * Browser-Scan durchführen
   */
  @logPerformance
  private async executeBrowserScan(scanConfig: ScanConfig) {
    const { targetUrl, profile, browserConfig } = scanConfig;
    
    orchestratorLogger.info('Starte Browser-Scan', {
      url: targetUrl,
      profile: profile.name,
      enabledChecks: profile.enabledChecks
    });
    
    try {
      // Browser-Service konfigurieren
      if (browserConfig) {
        this.chromeService = new ChromeDevToolsService(browserConfig);
      }
      
      // Scan durchführen
      const results = await this.chromeService.scanWebsite(targetUrl);
      
      orchestratorLogger.info('Browser-Scan abgeschlossen', {
        securityHeadersScore: results.securityHeaders.score,
        cookiesScore: results.cookies.score,
        xssFindings: results.xssFindings.length,
        csrfScore: results.csrfAnalysis.score
      });
      
      return results;
      
    } catch (error) {
      orchestratorLogger.error('Fehler beim Browser-Scan', error as Error, {
        url: targetUrl
      });
      throw error;
    }
  }
  
  /**
   * AI-Analyse durchführen
   */
  @logPerformance
  private async executeAIAnalysis(browserResults: any) {
    orchestratorLogger.info('Starte AI-Analyse');
    
    try {
      // Genkit-Service initialisieren falls nötig
      const results = await this.genkitService.analyzeSecurityFindings(browserResults);
      
      orchestratorLogger.info('AI-Analyse abgeschlossen', {
        riskScore: results.overallRiskScore,
        insightsCount: results.insights.length,
        recommendationsCount: results.recommendations.length,
        confidenceScore: results.confidenceScore
      });
      
      return results;
      
    } catch (error) {
      orchestratorLogger.error('Fehler bei AI-Analyse', error as Error);
      throw error;
    }
  }
  
  /**
   * Scan-Zusammenfassung generieren
   */
  @logPerformance
  private async generateScanSummary(browserResults: any, aiAnalysis: any): Promise<ScanSummary> {
    orchestratorLogger.info('Generiere Scan-Zusammenfassung');
    
    try {
      // Alle Findings sammeln
      const allFindings = [
        ...browserResults.xssFindings,
        ...browserResults.mixedContent,
        ...browserResults.cookies.issues,
        ...browserResults.csrfAnalysis.vulnerableForms,
        ...browserResults.securityHeaders.missing
      ];
      
      // Findings nach Schweregrad kategorisieren
      const findingsBySeverity: Record<SeverityLevel, number> = {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0
      };
      
      allFindings.forEach(finding => {
        const severity = this.determineFindingSeverity(finding);
        findingsBySeverity[severity]++;
      });
      
      // Gesamtscore berechnen (gewichteter Durchschnitt)
      const overallScore = this.calculateOverallScore(browserResults, aiAnalysis);
      
      // Risk Level bestimmen
      const riskLevel = this.determineRiskLevel(aiAnalysis.overallRiskScore);
      
      // Top Issues identifizieren
      const topIssues = this.identifyTopIssues(browserResults, aiAnalysis);
      
      // Compliance Status bewerten
      const complianceStatus = this.assessComplianceStatus(browserResults);
      
      // Verbesserungsbereiche identifizieren
      const improvementAreas = this.identifyImprovementAreas(aiAnalysis.recommendations);
      
      const summary: ScanSummary = {
        totalFindings: allFindings.length,
        findingsBySeverity,
        overallScore,
        riskLevel,
        topIssues,
        complianceStatus,
        improvementAreas
      };
      
      orchestratorLogger.info('Scan-Zusammenfassung generiert', {
        totalFindings: summary.totalFindings,
        overallScore: summary.overallScore,
        riskLevel: summary.riskLevel
      });
      
      return summary;
      
    } catch (error) {
      orchestratorLogger.error('Fehler bei Zusammenfassungs-Generierung', error as Error);
      throw error;
    }
  }
  
  /**
   * Schweregrad eines Findings bestimmen
   */
  private determineFindingSeverity(finding: any): SeverityLevel {
    // XSS-Findings
    if (finding.type && ['reflected', 'stored', 'dom_based'].includes(finding.type)) {
      return finding.severity || 'high';
    }
    
    // Security Headers
    if (finding.name && finding.description) {
      return finding.severity || 'medium';
    }
    
    // Cookie Issues
    if (finding.issue) {
      return finding.severity || 'medium';
    }
    
    // CSRF Vulnerabilities
    if (finding.action && finding.method) {
      return finding.severity || 'high';
    }
    
    // Mixed Content
    if (finding.resourceUrl) {
      return finding.severity || 'medium';
    }
    
    return 'low';
  }
  
  /**
   * Gesamtscore berechnen
   */
  private calculateOverallScore(browserResults: any, aiAnalysis: any): number {
    const scores = [
      browserResults.securityHeaders.score || 0,
      browserResults.cookies.score || 0,
      browserResults.csrfAnalysis.score || 0,
      browserResults.sslAnalysis.score || 0
    ];
    
    // AI Risk Score invertieren (niedriger Risk = höherer Score)
    const aiScore = Math.max(0, 100 - aiAnalysis.overallRiskScore);
    scores.push(aiScore);
    
    // Gewichteter Durchschnitt
    const weights = [0.25, 0.15, 0.2, 0.15, 0.25]; // AI-Score hat höchstes Gewicht
    let weightedSum = 0;
    let totalWeight = 0;
    
    for (let i = 0; i < scores.length; i++) {
      weightedSum += scores[i] * weights[i];
      totalWeight += weights[i];
    }
    
    return Math.round(weightedSum / totalWeight);
  }
  
  /**
   * Risk Level basierend auf AI Risk Score bestimmen
   */
  private determineRiskLevel(riskScore: number): SeverityLevel {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 30) return 'medium';
    return 'low';
  }
  
  /**
   * Top Issues identifizieren
   */
  private identifyTopIssues(browserResults: any, aiAnalysis: any): TopIssue[] {
    const issues: TopIssue[] = [];
    
    // XSS-Issues
    if (browserResults.xssFindings.length > 0) {
      issues.push({
        title: 'Cross-Site Scripting (XSS)',
        severity: 'high',
        count: browserResults.xssFindings.length,
        description: 'XSS-Schwachstellen ermöglichen Code-Injection-Angriffe',
        recommendation: 'Implementiere Input-Validierung und Output-Encoding'
      });
    }
    
    // Security Headers
    if (browserResults.securityHeaders.missing.length > 0) {
      issues.push({
        title: 'Fehlende Sicherheits-Header',
        severity: 'medium',
        count: browserResults.securityHeaders.missing.length,
        description: 'Wichtige Sicherheits-Header fehlen',
        recommendation: 'Implementiere Content-Security-Policy und andere Security Headers'
      });
    }
    
    // CSRF-Issues
    if (browserResults.csrfAnalysis.vulnerableForms.length > 0) {
      issues.push({
        title: 'CSRF-Schwachstellen',
        severity: 'high',
        count: browserResults.csrfAnalysis.vulnerableForms.length,
        description: 'Formulare sind anfällig für Cross-Site Request Forgery',
        recommendation: 'Implementiere CSRF-Token oder SameSite-Cookies'
      });
    }
    
    // Nach Schweregrad und Anzahl sortieren
    return issues.sort((a, b) => {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
      if (severityDiff !== 0) return severityDiff;
      return b.count - a.count;
    }).slice(0, 5); // Top 5 Issues
  }
  
  /**
   * Compliance Status bewerten
   */
  private assessComplianceStatus(browserResults: any): ComplianceStatus {
    // OWASP Compliance
    const owaspChecks = [
      browserResults.xssFindings.length === 0, // A03: Injection
      browserResults.securityHeaders.present.some((h: any) => h.name === 'Content-Security-Policy'), // A05: Security Misconfiguration
      browserResults.csrfAnalysis.hasProtection, // A01: Broken Access Control
      browserResults.sslAnalysis.isSecure // A02: Cryptographic Failures
    ];
    
    const passedOwaspChecks = owaspChecks.filter(check => check).length;
    const totalOwaspChecks = owaspChecks.length;
    const owaspScore = Math.round((passedOwaspChecks / totalOwaspChecks) * 100);
    
    const failedCategories = [];
    if (browserResults.xssFindings.length > 0) failedCategories.push('Injection Prevention');
    if (!browserResults.securityHeaders.present.some((h: any) => h.name === 'Content-Security-Policy')) {
      failedCategories.push('Security Configuration');
    }
    if (!browserResults.csrfAnalysis.hasProtection) failedCategories.push('Access Control');
    if (!browserResults.sslAnalysis.isSecure) failedCategories.push('Cryptographic Security');
    
    // GDPR Compliance (vereinfacht)
    const cookieCompliance = browserResults.cookies.issues.length === 0;
    const dataProtectionScore = cookieCompliance ? 100 : 50;
    const gdprIssues = cookieCompliance ? [] : ['Unsichere Cookie-Konfiguration'];
    
    return {
      owasp: {
        score: owaspScore,
        passedChecks: passedOwaspChecks,
        totalChecks: totalOwaspChecks,
        failedCategories
      },
      gdpr: {
        cookieCompliance,
        dataProtectionScore,
        issues: gdprIssues
      }
    };
  }
  
  /**
   * Verbesserungsbereiche identifizieren
   */
  private identifyImprovementAreas(recommendations: any[]): string[] {
    const areas = new Set<string>();
    
    recommendations.forEach(rec => {
      areas.add(rec.category);
    });
    
    return Array.from(areas).slice(0, 5); // Top 5 Bereiche
  }
  
  /**
   * Prüft ob ein Fehler wiederherstellbar ist
   */
  private isRecoverableError(error: any): boolean {
    if (error instanceof Error) {
      const recoverableErrors = [
        'TIMEOUT',
        'NETWORK_ERROR',
        'BROWSER_CRASH',
        'TEMPORARY_FAILURE'
      ];
      
      return recoverableErrors.some(errorType => 
        error.message.includes(errorType) || error.name.includes(errorType)
      );
    }
    
    return false;
  }
  
  /**
   * Aktive Scans abrufen
   */
  getActiveScans(): string[] {
    return Array.from(this.activeScanIds);
  }
  
  /**
   * Scan abbrechen
   */
  async cancelScan(scanId: string): Promise<boolean> {
    if (this.activeScanIds.has(scanId)) {
      this.activeScanIds.delete(scanId);
      orchestratorLogger.info('Scan abgebrochen', { scanId });
      return true;
    }
    
    return false;
  }
  
  /**
   * Cleanup-Operationen
   */
  private async cleanup(): Promise<void> {
    try {
      await this.chromeService.cleanup();
    } catch (error) {
      orchestratorLogger.error('Fehler beim Cleanup', error as Error);
    }
  }
  
  /**
   * Service herunterfahren
   */
  async shutdown(): Promise<void> {
    orchestratorLogger.info('ScanOrchestrator wird heruntergefahren');
    
    // Alle aktiven Scans abbrechen
    for (const scanId of this.activeScanIds) {
      await this.cancelScan(scanId);
    }
    
    // Services herunterfahren
    await Promise.all([
      this.chromeService.cleanup(),
      this.genkitService.shutdown()
    ]);
    
    orchestratorLogger.info('ScanOrchestrator heruntergefahren');
  }
}

