#!/usr/bin/env node

/**
 * WebSecurity SaaS - CLI Demo
 * Kommandozeilen-Interface für Proof-of-Concept Demonstration
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { ScanOrchestrator } from './services/ScanOrchestrator';
import { ScanConfig, ScanProfile, SeverityLevel } from './types';
import { config, scanProfiles } from './config';
import { logger } from './utils/Logger';
import { validateConfig } from './config';

const program = new Command();

// CLI-Konfiguration
program
  .name('websecurity-scan')
  .description('WebSecurity SaaS - Automatisierte Websicherheitsprüfung mit AI-Analyse')
  .version('1.0.0');

// Scan-Befehl
program
  .command('scan')
  .description('Führe einen Sicherheitsscan einer Website durch')
  .argument('<url>', 'URL der zu scannenden Website')
  .option('-p, --profile <profile>', 'Scan-Profil (quick, standard, comprehensive, compliance)', 'standard')
  .option('-o, --output <file>', 'Ausgabedatei für Ergebnisse (JSON)')
  .option('--timeout <ms>', 'Timeout in Millisekunden', '60000')
  .option('--headless', 'Browser im Headless-Modus ausführen', true)
  .option('--screenshots', 'Screenshots erstellen', false)
  .option('--verbose', 'Detaillierte Ausgabe', false)
  .action(async (url: string, options) => {
    await executeScan(url, options);
  });

// Profil-Liste-Befehl
program
  .command('profiles')
  .description('Verfügbare Scan-Profile anzeigen')
  .action(() => {
    showProfiles();
  });

// Konfiguration-Befehl
program
  .command('config')
  .description('Aktuelle Konfiguration anzeigen')
  .action(() => {
    showConfig();
  });

// Test-Befehl
program
  .command('test')
  .description('Teste die Integration mit einer Demo-Website')
  .action(async () => {
    await runIntegrationTest();
  });

/**
 * Hauptfunktion für Scan-Ausführung
 */
async function executeScan(url: string, options: any): Promise<void> {
  const spinner = ora('Initialisiere WebSecurity Scan...').start();
  
  try {
    // URL validieren
    if (!isValidUrl(url)) {
      spinner.fail(chalk.red('Ungültige URL bereitgestellt'));
      process.exit(1);
    }
    
    // Konfiguration validieren
    const configValidation = validateConfig();
    if (!configValidation.valid) {
      spinner.fail(chalk.red('Konfigurationsfehler:'));
      configValidation.errors.forEach(error => {
        console.log(chalk.red(`  ❌ ${error}`));
      });
      process.exit(1);
    }
    
    // Scan-Profil laden
    const profileName = options.profile;
    const profile = scanProfiles[profileName];
    
    if (!profile) {
      spinner.fail(chalk.red(`Unbekanntes Scan-Profil: ${profileName}`));
      console.log(chalk.yellow('Verfügbare Profile:'), Object.keys(scanProfiles).join(', '));
      process.exit(1);
    }
    
    spinner.text = `Starte ${profile.name} für ${url}`;
    
    // Scan-Konfiguration erstellen
    const scanConfig: ScanConfig = {
      targetUrl: url,
      scanId: generateScanId(),
      profile,
      browserConfig: {
        ...config.chrome,
        headless: options.headless
      },
      aiConfig: config.genkit,
      timeout: parseInt(options.timeout),
      userAgent: process.env.SCAN_USER_AGENT
    };
    
    if (options.verbose) {
      console.log(chalk.blue('\\n📋 Scan-Konfiguration:'));
      console.log(chalk.gray(JSON.stringify(scanConfig, null, 2)));
    }
    
    // Orchestrator initialisieren und Scan ausführen
    const orchestrator = new ScanOrchestrator();
    
    spinner.text = 'Führe Browser-Automatisierung durch...';
    
    const startTime = Date.now();
    const result = await orchestrator.executeScan(scanConfig);
    const duration = Date.now() - startTime;
    
    if (result.status === 'completed') {
      spinner.succeed(chalk.green(`✅ Scan erfolgreich abgeschlossen in ${duration}ms`));
      
      // Ergebnisse anzeigen
      displayResults(result);
      
      // Ergebnisse in Datei speichern
      if (options.output) {
        await saveResults(result, options.output);
        console.log(chalk.blue(`💾 Ergebnisse gespeichert in: ${options.output}`));
      }
      
    } else {
      spinner.fail(chalk.red('❌ Scan fehlgeschlagen'));
      
      if (result.error) {
        console.log(chalk.red('Fehler:'), result.error.message);
        if (options.verbose && result.error.details) {
          console.log(chalk.gray(result.error.details));
        }
      }
      
      process.exit(1);
    }
    
    // Cleanup
    await orchestrator.shutdown();
    
  } catch (error) {
    spinner.fail(chalk.red('Unerwarteter Fehler'));
    console.error(chalk.red(error instanceof Error ? error.message : 'Unbekannter Fehler'));
    
    if (options.verbose) {
      console.error(error);
    }
    
    process.exit(1);
  }
}

/**
 * Scan-Ergebnisse in der Konsole anzeigen
 */
function displayResults(result: any): void {
  console.log(chalk.blue('\\n🔍 Scan-Ergebnisse:'));
  console.log(chalk.blue('='.repeat(50)));
  
  // Grundlegende Informationen
  console.log(chalk.white(`🌐 URL: ${result.targetUrl}`));
  console.log(chalk.white(`⏱️  Dauer: ${result.duration}ms`));
  console.log(chalk.white(`📊 Gesamtscore: ${result.summary.overallScore}/100`));
  
  // Risk Level mit Farben
  const riskColor = getRiskColor(result.summary.riskLevel);
  console.log(chalk.white(`⚠️  Risiko-Level: ${riskColor(result.summary.riskLevel.toUpperCase())}`));
  
  // Findings nach Schweregrad
  console.log(chalk.blue('\\n📋 Befunde nach Schweregrad:'));
  const severities: SeverityLevel[] = ['critical', 'high', 'medium', 'low'];
  
  severities.forEach(severity => {
    const count = result.summary.findingsBySeverity[severity] || 0;
    if (count > 0) {
      const color = getSeverityColor(severity);
      console.log(`  ${color(`${severity.toUpperCase()}: ${count}`)}`);
    }
  });
  
  // Top Issues
  if (result.summary.topIssues.length > 0) {
    console.log(chalk.blue('\\n🚨 Wichtigste Probleme:'));
    result.summary.topIssues.slice(0, 3).forEach((issue: any, index: number) => {
      const color = getSeverityColor(issue.severity);
      console.log(`  ${index + 1}. ${color(issue.title)} (${issue.count}x)`);
      console.log(`     ${chalk.gray(issue.description)}`);
    });
  }
  
  // AI-Insights
  if (result.aiAnalysis.insights.length > 0) {
    console.log(chalk.blue('\\n🤖 AI-Insights:'));
    result.aiAnalysis.insights.slice(0, 3).forEach((insight: any, index: number) => {
      const color = getSeverityColor(insight.severity);
      console.log(`  ${index + 1}. ${color(insight.title)}`);
      console.log(`     ${chalk.gray(insight.description)}`);
      console.log(`     ${chalk.yellow(`Confidence: ${Math.round(insight.confidence * 100)}%`)}`);
    });
  }
  
  // Empfehlungen
  if (result.aiAnalysis.recommendations.length > 0) {
    console.log(chalk.blue('\\n💡 Top-Empfehlungen:'));
    result.aiAnalysis.recommendations.slice(0, 3).forEach((rec: any, index: number) => {
      console.log(`  ${index + 1}. ${chalk.white(rec.title)}`);
      console.log(`     ${chalk.gray(rec.description)}`);
      console.log(`     ${chalk.yellow(`Aufwand: ${rec.estimatedEffort}`)}`);
    });
  }
  
  // Compliance Status
  console.log(chalk.blue('\\n📜 Compliance Status:'));
  console.log(`  OWASP: ${result.summary.complianceStatus.owasp.score}/100 (${result.summary.complianceStatus.owasp.passedChecks}/${result.summary.complianceStatus.owasp.totalChecks} bestanden)`);
  console.log(`  GDPR: ${result.summary.complianceStatus.gdpr.cookieCompliance ? '✅ Compliant' : '❌ Issues found'}`);
  
  console.log(chalk.blue('\\n' + '='.repeat(50)));
}

/**
 * Verfügbare Scan-Profile anzeigen
 */
function showProfiles(): void {
  console.log(chalk.blue('📋 Verfügbare Scan-Profile:'));
  console.log(chalk.blue('='.repeat(40)));
  
  Object.entries(scanProfiles).forEach(([key, profile]) => {
    console.log(chalk.white(`\\n🔍 ${key}:`));
    console.log(`  Name: ${profile.name}`);
    console.log(`  Beschreibung: ${profile.description}`);
    console.log(`  Prüfungen: ${profile.enabledChecks.join(', ')}`);
    console.log(`  Max. Tiefe: ${profile.maxDepth}`);
    console.log(`  Subdomains: ${profile.checkSubdomains ? 'Ja' : 'Nein'}`);
  });
}

/**
 * Aktuelle Konfiguration anzeigen
 */
function showConfig(): void {
  console.log(chalk.blue('⚙️  Aktuelle Konfiguration:'));
  console.log(chalk.blue('='.repeat(40)));
  
  console.log(chalk.white('\\n🌐 Anwendung:'));
  console.log(`  Name: ${config.app.name}`);
  console.log(`  Version: ${config.app.version}`);
  console.log(`  Umgebung: ${config.app.environment}`);
  
  console.log(chalk.white('\\n🤖 AI-Konfiguration:'));
  console.log(`  Modell: ${config.genkit.model}`);
  console.log(`  Temperatur: ${config.genkit.temperature}`);
  console.log(`  Confidence Threshold: ${config.genkit.confidenceThreshold}`);
  
  console.log(chalk.white('\\n🌐 Browser-Konfiguration:'));
  console.log(`  Headless: ${config.chrome.headless}`);
  console.log(`  Viewport: ${config.chrome.viewport.width}x${config.chrome.viewport.height}`);
  console.log(`  Timeout: ${config.chrome.timeout}ms`);
  
  console.log(chalk.white('\\n🔍 Scan-Konfiguration:'));
  console.log(`  Max. parallele Scans: ${config.scan.maxConcurrentScans}`);
  console.log(`  Standard-Timeout: ${config.scan.defaultTimeout}ms`);
  console.log(`  Retry-Versuche: ${config.scan.retryAttempts}`);
  
  // Konfiguration validieren
  const validation = validateConfig();
  console.log(chalk.white('\\n✅ Validierung:'));
  if (validation.valid) {
    console.log(chalk.green('  Konfiguration ist gültig'));
  } else {
    console.log(chalk.red('  Konfigurationsfehler gefunden:'));
    validation.errors.forEach(error => {
      console.log(chalk.red(`    ❌ ${error}`));
    });
  }
}

/**
 * Integrations-Test ausführen
 */
async function runIntegrationTest(): Promise<void> {
  const spinner = ora('Führe Integrations-Test durch...').start();
  
  try {
    // Test mit einer sicheren Demo-Website
    const testUrl = 'https://httpbin.org/';
    
    spinner.text = 'Teste Browser-Integration...';
    
    const scanConfig: ScanConfig = {
      targetUrl: testUrl,
      scanId: 'integration-test',
      profile: scanProfiles.quick,
      browserConfig: config.chrome,
      aiConfig: config.genkit,
      timeout: 30000
    };
    
    const orchestrator = new ScanOrchestrator();
    const result = await orchestrator.executeScan(scanConfig);
    
    if (result.status === 'completed') {
      spinner.succeed(chalk.green('✅ Integrations-Test erfolgreich'));
      
      console.log(chalk.blue('\\n🧪 Test-Ergebnisse:'));
      console.log(`  Browser-Scan: ${result.browserResults ? '✅' : '❌'}`);
      console.log(`  AI-Analyse: ${result.aiAnalysis ? '✅' : '❌'}`);
      console.log(`  Zusammenfassung: ${result.summary ? '✅' : '❌'}`);
      console.log(`  Dauer: ${result.duration}ms`);
      
    } else {
      spinner.fail(chalk.red('❌ Integrations-Test fehlgeschlagen'));
      if (result.error) {
        console.log(chalk.red('Fehler:'), result.error.message);
      }
    }
    
    await orchestrator.shutdown();
    
  } catch (error) {
    spinner.fail(chalk.red('Integrations-Test fehlgeschlagen'));
    console.error(error instanceof Error ? error.message : 'Unbekannter Fehler');
  }
}

/**
 * Hilfsfunktionen
 */

function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

function generateScanId(): string {
  return `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

function getRiskColor(riskLevel: string): (text: string) => string {
  switch (riskLevel) {
    case 'critical': return chalk.red.bold;
    case 'high': return chalk.red;
    case 'medium': return chalk.yellow;
    case 'low': return chalk.green;
    default: return chalk.gray;
  }
}

function getSeverityColor(severity: SeverityLevel): (text: string) => string {
  switch (severity) {
    case 'critical': return chalk.red.bold;
    case 'high': return chalk.red;
    case 'medium': return chalk.yellow;
    case 'low': return chalk.green;
    default: return chalk.gray;
  }
}

async function saveResults(result: any, filename: string): Promise<void> {
  const fs = await import('fs/promises');
  const path = await import('path');
  
  // Stelle sicher, dass das Verzeichnis existiert
  const dir = path.dirname(filename);
  await fs.mkdir(dir, { recursive: true });
  
  // Ergebnisse als JSON speichern
  await fs.writeFile(filename, JSON.stringify(result, null, 2), 'utf8');
}

// CLI starten
if (require.main === module) {
  program.parse();
}

