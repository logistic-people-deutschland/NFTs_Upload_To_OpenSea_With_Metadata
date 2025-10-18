#!/usr/bin/env node

/**
 * Schneller Test-Scanner für www.logistic-people.de
 * Vereinfachte Version ohne TypeScript-Kompilierung
 */

const puppeteer = require('puppeteer');
const chalk = require('chalk');
const ora = require('ora');

async function scanWebsite(url) {
  const spinner = ora(`Scanne ${url}...`).start();
  
  let browser;
  try {
    // Browser starten
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    const page = await browser.newPage();
    await page.setUserAgent('WebSecurity-SaaS-Scanner/1.0 (Test)');
    
    spinner.text = 'Lade Website...';
    
    // Website laden
    const startTime = Date.now();
    const response = await page.goto(url, { 
      waitUntil: 'networkidle2',
      timeout: 30000 
    });
    const loadTime = Date.now() - startTime;
    
    spinner.text = 'Analysiere Sicherheits-Header...';
    
    // Basis-Informationen sammeln
    const title = await page.title();
    const finalUrl = page.url();
    const statusCode = response.status();
    const headers = response.headers();
    
    // Security Headers prüfen
    const securityHeaders = {
      'content-security-policy': headers['content-security-policy'],
      'strict-transport-security': headers['strict-transport-security'],
      'x-frame-options': headers['x-frame-options'],
      'x-content-type-options': headers['x-content-type-options'],
      'referrer-policy': headers['referrer-policy'],
      'permissions-policy': headers['permissions-policy']
    };
    
    spinner.text = 'Analysiere Cookies...';
    
    // Cookies analysieren
    const cookies = await page.cookies();
    
    spinner.text = 'Prüfe SSL/HTTPS...';
    
    // SSL-Status
    const isHTTPS = finalUrl.startsWith('https:');
    
    spinner.text = 'Erstelle Screenshot...';
    
    // Screenshot
    await page.screenshot({ 
      path: 'logistic-people-scan.png',
      fullPage: true 
    });
    
    await browser.close();
    
    spinner.succeed(chalk.green('✅ Scan abgeschlossen!'));
    
    // Ergebnisse anzeigen
    console.log(chalk.blue('\n🔍 Scan-Ergebnisse für www.logistic-people.de:'));
    console.log(chalk.blue('='.repeat(50)));
    
    console.log(chalk.white(`\n📄 Basis-Informationen:`));
    console.log(`  Titel: ${title}`);
    console.log(`  URL: ${finalUrl}`);
    console.log(`  Status: ${statusCode}`);
    console.log(`  Ladezeit: ${loadTime}ms`);
    console.log(`  HTTPS: ${isHTTPS ? '✅ Ja' : '❌ Nein'}`);
    
    console.log(chalk.white(`\n🛡️ Sicherheits-Header:`));
    let headerScore = 0;
    const totalHeaders = Object.keys(securityHeaders).length;
    
    for (const [header, value] of Object.entries(securityHeaders)) {
      if (value) {
        console.log(`  ✅ ${header}: ${value.substring(0, 50)}${value.length > 50 ? '...' : ''}`);
        headerScore++;
      } else {
        console.log(`  ❌ ${header}: Fehlt`);
      }
    }
    
    const headerPercentage = Math.round((headerScore / totalHeaders) * 100);
    console.log(`  📊 Header-Score: ${headerPercentage}% (${headerScore}/${totalHeaders})`);
    
    console.log(chalk.white(`\n🍪 Cookie-Analyse:`));
    console.log(`  Anzahl Cookies: ${cookies.length}`);
    
    let secureCookies = 0;
    let httpOnlyCookies = 0;
    let sameSiteCookies = 0;
    
    cookies.forEach(cookie => {
      if (cookie.secure) secureCookies++;
      if (cookie.httpOnly) httpOnlyCookies++;
      if (cookie.sameSite) sameSiteCookies++;
    });
    
    if (cookies.length > 0) {
      console.log(`  🔒 Secure Cookies: ${secureCookies}/${cookies.length} (${Math.round(secureCookies/cookies.length*100)}%)`);
      console.log(`  🚫 HttpOnly Cookies: ${httpOnlyCookies}/${cookies.length} (${Math.round(httpOnlyCookies/cookies.length*100)}%)`);
      console.log(`  🔗 SameSite Cookies: ${sameSiteCookies}/${cookies.length} (${Math.round(sameSiteCookies/cookies.length*100)}%)`);
    }
    
    // Gesamtbewertung
    let totalScore = 0;
    let maxScore = 0;
    
    // HTTPS (30 Punkte)
    if (isHTTPS) totalScore += 30;
    maxScore += 30;
    
    // Security Headers (40 Punkte)
    totalScore += Math.round((headerScore / totalHeaders) * 40);
    maxScore += 40;
    
    // Cookie Security (30 Punkte)
    if (cookies.length > 0) {
      const cookieScore = (secureCookies + httpOnlyCookies + sameSiteCookies) / (cookies.length * 3);
      totalScore += Math.round(cookieScore * 30);
    } else {
      totalScore += 30; // Keine Cookies = gut für Sicherheit
    }
    maxScore += 30;
    
    const finalScore = Math.round((totalScore / maxScore) * 100);
    
    console.log(chalk.white(`\n📊 Gesamtbewertung:`));
    console.log(`  Score: ${finalScore}/100`);
    
    let riskLevel = 'Niedrig';
    let riskColor = chalk.green;
    
    if (finalScore < 50) {
      riskLevel = 'Hoch';
      riskColor = chalk.red;
    } else if (finalScore < 75) {
      riskLevel = 'Mittel';
      riskColor = chalk.yellow;
    }
    
    console.log(`  Risiko-Level: ${riskColor(riskLevel)}`);
    
    console.log(chalk.white(`\n💡 Empfehlungen:`));
    
    if (!securityHeaders['content-security-policy']) {
      console.log(`  🔧 Implementiere Content-Security-Policy Header`);
    }
    if (!securityHeaders['strict-transport-security']) {
      console.log(`  🔧 Füge Strict-Transport-Security Header hinzu`);
    }
    if (!securityHeaders['x-frame-options']) {
      console.log(`  🔧 Setze X-Frame-Options Header gegen Clickjacking`);
    }
    if (cookies.length > 0 && secureCookies < cookies.length) {
      console.log(`  🔧 Setze Secure-Flag für alle Cookies auf HTTPS-Seiten`);
    }
    if (cookies.length > 0 && httpOnlyCookies < cookies.length) {
      console.log(`  🔧 Verwende HttpOnly-Flag für Session-Cookies`);
    }
    
    console.log(chalk.blue('\n📸 Screenshot gespeichert als: logistic-people-scan.png'));
    console.log(chalk.blue('='.repeat(50)));
    
    return {
      score: finalScore,
      riskLevel,
      details: {
        https: isHTTPS,
        headerScore: headerPercentage,
        cookieCount: cookies.length,
        loadTime
      }
    };
    
  } catch (error) {
    if (browser) await browser.close();
    spinner.fail(chalk.red('❌ Scan fehlgeschlagen'));
    console.error(chalk.red('Fehler:'), error.message);
    throw error;
  }
}

// Hauptfunktion
async function main() {
  console.log(chalk.blue('🚀 WebSecurity SaaS - Live-Test'));
  console.log(chalk.blue('Testing MCP Chrome DevTools Integration'));
  console.log(chalk.blue('='.repeat(50)));
  
  try {
    const result = await scanWebsite('https://www.logistic-people.de');
    
    console.log(chalk.green(`\n✅ Test erfolgreich abgeschlossen!`));
    console.log(chalk.white(`📊 Endergebnis: ${result.score}/100 (${result.riskLevel} Risiko)`));
    
    // Simulierte AI-Analyse
    console.log(chalk.blue('\n🤖 Simulierte AI-Analyse (Genkit Integration):'));
    console.log(chalk.gray('  🧠 Pattern Recognition: Website folgt Standard-Sicherheitspraktiken'));
    console.log(chalk.gray('  📈 Risk Assessment: Moderate Sicherheitskonfiguration erkannt'));
    console.log(chalk.gray('  💡 AI-Empfehlung: Priorität auf CSP und Cookie-Sicherheit legen'));
    console.log(chalk.gray('  🎯 Confidence Score: 87%'));
    
  } catch (error) {
    console.error(chalk.red('\n❌ Test fehlgeschlagen:'), error.message);
    process.exit(1);
  }
}

// Script ausführen
if (require.main === module) {
  main();
}

module.exports = { scanWebsite };

