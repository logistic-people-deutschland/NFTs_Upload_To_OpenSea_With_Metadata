/**
 * WebSecurity SaaS - Type Definitions
 * Zentrale TypeScript-Interfaces für alle Datenstrukturen
 */

// ===== Basis-Typen =====
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type FindingType = 'xss' | 'csrf' | 'security_headers' | 'cookies' | 'mixed_content' | 'ssl' | 'javascript_vulnerabilities';

// ===== Scan-Konfiguration =====
export interface ScanConfig {
  /** URL der zu scannenden Website */
  targetUrl: string;
  
  /** Eindeutige Scan-ID */
  scanId: string;
  
  /** Scan-Profil (bestimmt welche Tests ausgeführt werden) */
  profile: ScanProfile;
  
  /** Browser-Konfiguration */
  browserConfig: BrowserConfig;
  
  /** AI-Analyse-Einstellungen */
  aiConfig: AIConfig;
  
  /** Timeout für den gesamten Scan in Millisekunden */
  timeout: number;
  
  /** Zusätzliche HTTP-Headers für Requests */
  customHeaders?: Record<string, string>;
  
  /** Benutzer-Agent String */
  userAgent?: string;
}

export interface ScanProfile {
  name: string;
  description: string;
  enabledChecks: FindingType[];
  maxDepth: number;
  followRedirects: boolean;
  checkSubdomains: boolean;
}

export interface BrowserConfig {
  headless: boolean;
  viewport: {
    width: number;
    height: number;
  };
  timeout: number;
  executablePath?: string;
  args?: string[];
}

export interface AIConfig {
  model: string;
  temperature: number;
  maxTokens: number;
  confidenceThreshold: number;
  enablePatternRecognition: boolean;
  enableRiskScoring: boolean;
}

// ===== Scan-Ergebnisse =====
export interface ScanResult {
  scanId: string;
  targetUrl: string;
  status: ScanStatus;
  startedAt: Date;
  completedAt?: Date;
  duration?: number;
  
  /** Browser-Scan-Ergebnisse */
  browserResults: BrowserScanResults;
  
  /** AI-Analyse-Ergebnisse */
  aiAnalysis: AIAnalysisResults;
  
  /** Zusammenfassung aller Befunde */
  summary: ScanSummary;
  
  /** Fehler-Informationen falls Scan fehlgeschlagen */
  error?: ScanError;
}

export interface BrowserScanResults {
  /** Grundlegende Seiten-Informationen */
  pageInfo: PageInfo;
  
  /** Sicherheits-Header Analyse */
  securityHeaders: SecurityHeadersAnalysis;
  
  /** Cookie-Analyse */
  cookies: CookieAnalysis;
  
  /** XSS-Vulnerability Tests */
  xssFindings: XSSFinding[];
  
  /** CSRF-Analyse */
  csrfAnalysis: CSRFAnalysis;
  
  /** Mixed Content Prüfung */
  mixedContent: MixedContentFinding[];
  
  /** SSL/TLS-Analyse */
  sslAnalysis: SSLAnalysis;
  
  /** JavaScript-Bibliotheken Analyse */
  jsLibraries: JSLibraryAnalysis[];
  
  /** Screenshots */
  screenshots: Screenshot[];
  
  /** Network-Traffic Logs */
  networkLogs: NetworkLog[];
}

export interface PageInfo {
  title: string;
  url: string;
  finalUrl: string;
  statusCode: number;
  loadTime: number;
  contentType: string;
  contentLength: number;
  redirectChain: string[];
}

export interface SecurityHeadersAnalysis {
  present: SecurityHeader[];
  missing: SecurityHeader[];
  misconfigured: SecurityHeader[];
  score: number;
  recommendations: string[];
}

export interface SecurityHeader {
  name: string;
  value?: string;
  expected?: string;
  severity: SeverityLevel;
  description: string;
}

export interface CookieAnalysis {
  cookies: CookieInfo[];
  secureCount: number;
  httpOnlyCount: number;
  sameSiteCount: number;
  issues: CookieIssue[];
  score: number;
}

export interface CookieInfo {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | undefined;
  expires?: Date;
  maxAge?: number;
}

export interface CookieIssue {
  cookieName: string;
  issue: string;
  severity: SeverityLevel;
  recommendation: string;
}

export interface XSSFinding {
  type: 'reflected' | 'stored' | 'dom_based';
  payload: string;
  location: string;
  context: string;
  severity: SeverityLevel;
  verified: boolean;
  evidence: string;
}

export interface CSRFAnalysis {
  hasProtection: boolean;
  protectionMethods: string[];
  vulnerableForms: CSRFVulnerableForm[];
  score: number;
}

export interface CSRFVulnerableForm {
  action: string;
  method: string;
  hasToken: boolean;
  hasSameSiteProtection: boolean;
  severity: SeverityLevel;
}

export interface MixedContentFinding {
  resourceUrl: string;
  resourceType: string;
  severity: SeverityLevel;
  location: string;
}

export interface SSLAnalysis {
  isSecure: boolean;
  certificate: CertificateInfo;
  protocols: string[];
  ciphers: string[];
  vulnerabilities: SSLVulnerability[];
  score: number;
}

export interface CertificateInfo {
  issuer: string;
  subject: string;
  validFrom: Date;
  validTo: Date;
  isExpired: boolean;
  daysUntilExpiry: number;
  signatureAlgorithm: string;
}

export interface SSLVulnerability {
  name: string;
  description: string;
  severity: SeverityLevel;
  cve?: string;
}

export interface JSLibraryAnalysis {
  name: string;
  version: string;
  latestVersion: string;
  isOutdated: boolean;
  vulnerabilities: JSVulnerability[];
  severity: SeverityLevel;
}

export interface JSVulnerability {
  cve: string;
  description: string;
  severity: SeverityLevel;
  patchedIn: string;
}

export interface Screenshot {
  name: string;
  path: string;
  timestamp: Date;
  viewport: {
    width: number;
    height: number;
  };
}

export interface NetworkLog {
  url: string;
  method: string;
  statusCode: number;
  responseTime: number;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  timestamp: Date;
}

// ===== AI-Analyse =====
export interface AIAnalysisResults {
  /** Gesamtbewertung der Website-Sicherheit */
  overallRiskScore: number;
  
  /** AI-generierte Insights */
  insights: AIInsight[];
  
  /** Empfehlungen zur Verbesserung */
  recommendations: AIRecommendation[];
  
  /** Erkannte Sicherheitsmuster */
  patterns: SecurityPattern[];
  
  /** Anomalie-Erkennung */
  anomalies: SecurityAnomaly[];
  
  /** Confidence Score der AI-Analyse */
  confidenceScore: number;
  
  /** Verwendetes AI-Modell */
  modelUsed: string;
  
  /** Verarbeitungszeit der AI-Analyse */
  processingTime: number;
}

export interface AIInsight {
  category: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  confidence: number;
  evidence: string[];
  relatedFindings: string[];
}

export interface AIRecommendation {
  priority: number;
  category: string;
  title: string;
  description: string;
  implementation: string;
  estimatedEffort: 'low' | 'medium' | 'high';
  businessImpact: string;
  technicalDetails: string;
}

export interface SecurityPattern {
  name: string;
  description: string;
  confidence: number;
  indicators: string[];
  riskLevel: SeverityLevel;
}

export interface SecurityAnomaly {
  type: string;
  description: string;
  severity: SeverityLevel;
  confidence: number;
  baseline: string;
  observed: string;
}

// ===== Zusammenfassung =====
export interface ScanSummary {
  totalFindings: number;
  findingsBySeverity: Record<SeverityLevel, number>;
  overallScore: number;
  riskLevel: SeverityLevel;
  topIssues: TopIssue[];
  complianceStatus: ComplianceStatus;
  improvementAreas: string[];
}

export interface TopIssue {
  title: string;
  severity: SeverityLevel;
  count: number;
  description: string;
  recommendation: string;
}

export interface ComplianceStatus {
  owasp: {
    score: number;
    passedChecks: number;
    totalChecks: number;
    failedCategories: string[];
  };
  gdpr: {
    cookieCompliance: boolean;
    dataProtectionScore: number;
    issues: string[];
  };
}

// ===== Fehler-Behandlung =====
export interface ScanError {
  code: string;
  message: string;
  details?: string;
  timestamp: Date;
  recoverable: boolean;
  retryCount: number;
}

// ===== Service-Konfiguration =====
export interface ServiceConfig {
  chrome: BrowserConfig;
  genkit: AIConfig;
  scan: {
    maxConcurrentScans: number;
    defaultTimeout: number;
    retryAttempts: number;
    retryDelay: number;
  };
  logging: {
    level: string;
    format: string;
    file?: string;
  };
}

// ===== Event-System =====
export interface ScanEvent {
  scanId: string;
  type: 'started' | 'progress' | 'completed' | 'failed' | 'cancelled';
  timestamp: Date;
  data?: any;
}

export interface ScanProgress {
  scanId: string;
  currentStep: string;
  completedSteps: number;
  totalSteps: number;
  percentage: number;
  estimatedTimeRemaining?: number;
}

