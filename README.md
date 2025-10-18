# 🔐 WebSecurity SaaS - Proof of Concept

Ein innovativer **Proof-of-Concept** für automatisierte Websicherheitsprüfung durch die Integration von **MCP Chrome DevTools** mit **Google Genkit** für AI-gestützte Sicherheitsanalyse.

## 🚀 Überblick

Dieses Projekt demonstriert die Kernfunktionalität eines SaaS-Systems für Websicherheit, das:

- 🌐 **Browser-Automatisierung** mit MCP Chrome DevTools für Live-Website-Analyse
- 🤖 **AI-gestützte Sicherheitsanalyse** mit Google Genkit für intelligente Bewertung
- 🔍 **Automatische Schwachstellen-Erkennung** (XSS, CSRF, Security Headers, etc.)
- 📊 **Intelligente Risk-Bewertung** und priorisierte Empfehlungen
- 💻 **CLI-Interface** für einfache Demonstration und Tests

## 🏗️ Architektur

```
┌─────────────────────────────────────────────────────────────────┐
│                    WebSecurity SaaS PoC                        │
├─────────────────────────────────────────────────────────────────┤
│  CLI Interface (Commander.js)                                  │
├─────────────────────────────────────────────────────────────────┤
│  Scan Orchestrator                                             │
│  ├── Workflow-Management                                       │
│  ├── Error Handling                                            │
│  └── Result Aggregation                                        │
├─────────────────────────────────────────────────────────────────┤
│  Chrome DevTools Service    │    Genkit Analysis Service       │
│  ├── Browser Automation     │    ├── AI Security Analysis      │
│  ├── Security Scanning      │    ├── Pattern Recognition       │
│  ├── DOM Analysis           │    ├── Risk Scoring              │
│  └── Network Monitoring     │    └── Recommendations           │
├─────────────────────────────────────────────────────────────────┤
│  Configuration & Logging                                       │
│  ├── Environment Management                                    │
│  ├── Structured Logging                                        │
│  └── Performance Monitoring                                    │
└─────────────────────────────────────────────────────────────────┘
```

## 🛠️ Technologie-Stack

### **Core Technologies**
- **Node.js 18+** - Runtime Environment
- **TypeScript** - Type-safe Development
- **MCP Chrome DevTools** - Browser Automation
- **Google Genkit** - AI Analysis Framework
- **Puppeteer** - Browser Control

### **CLI & Utilities**
- **Commander.js** - CLI Framework
- **Chalk** - Terminal Styling
- **Ora** - Loading Spinners
- **Winston** - Structured Logging

### **Development**
- **Jest** - Testing Framework
- **ESLint** - Code Linting
- **Prettier** - Code Formatting

## 📦 Installation

### Voraussetzungen

- **Node.js 18+**
- **Google Chrome/Chromium**
- **Google Cloud Account** (für Genkit)

### Setup

```bash
# Repository klonen
git clone <repository-url>
cd websecurity-saas-poc

# Dependencies installieren
npm install

# Environment-Konfiguration
cp .env.example .env
# Bearbeite .env mit deinen API-Keys und Einstellungen

# TypeScript kompilieren
npm run build

# Entwicklungsserver starten
npm run dev
```

### Environment-Variablen

```bash
# Google Genkit Configuration
GENKIT_API_KEY=your_genkit_api_key_here
GENKIT_PROJECT_ID=your_gcp_project_id
GENKIT_MODEL=gemini-1.5-pro

# Chrome DevTools Configuration
CHROME_EXECUTABLE_PATH=/usr/bin/google-chrome
CHROME_HEADLESS=true
CHROME_TIMEOUT=30000

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

## 🎯 Verwendung

### CLI-Interface

```bash
# Basis-Scan einer Website
npm run demo scan https://example.com

# Erweiterte Optionen
npm run demo scan https://example.com \\
  --profile comprehensive \\
  --output results.json \\
  --verbose

# Verfügbare Scan-Profile anzeigen
npm run demo profiles

# Konfiguration prüfen
npm run demo config

# Integrations-Test ausführen
npm run demo test
```

### Programmatische Nutzung

```typescript
import { createWebSecurityScanner, scanProfiles } from './src';

async function scanWebsite() {
  const scanner = await createWebSecurityScanner();
  
  const result = await scanner.executeScan({
    targetUrl: 'https://example.com',
    scanId: 'my-scan-001',
    profile: scanProfiles.standard,
    browserConfig: { headless: true },
    aiConfig: { model: 'gemini-1.5-pro' },
    timeout: 60000
  });
  
  console.log('Scan Results:', result);
  await scanner.shutdown();
}
```

## 🔍 Sicherheitsprüfungen

### Browser-basierte Prüfungen

- **🛡️ Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- **🍪 Cookie-Sicherheit**: Secure, HttpOnly, SameSite Flags
- **⚡ XSS-Erkennung**: Reflected, Stored, DOM-based XSS
- **🔒 CSRF-Analyse**: Token-Validierung, SameSite-Schutz
- **🔗 Mixed Content**: HTTP-Ressourcen auf HTTPS-Seiten
- **📜 SSL/TLS-Analyse**: Zertifikat und Protokoll-Prüfung
- **📚 JavaScript-Bibliotheken**: Veraltete/vulnerable Dependencies

### AI-gestützte Analyse

- **🧠 Pattern Recognition**: Erkennung komplexer Sicherheitsmuster
- **📊 Risk Scoring**: Intelligente Bewertung von Schwachstellen
- **💡 Smart Recommendations**: Priorisierte Verbesserungsvorschläge
- **🔍 Anomaly Detection**: Erkennung ungewöhnlicher Konfigurationen
- **📈 Trend Analysis**: Historische Datenauswertung

## 📊 Scan-Profile

### Quick Scan
- **Dauer**: ~30 Sekunden
- **Prüfungen**: Security Headers, Cookies, SSL
- **Verwendung**: Schnelle Basis-Prüfung

### Standard Scan
- **Dauer**: ~2 Minuten
- **Prüfungen**: XSS, CSRF, Headers, Cookies, Mixed Content, SSL
- **Verwendung**: Umfassende Sicherheitsprüfung

### Comprehensive Scan
- **Dauer**: ~5 Minuten
- **Prüfungen**: Alle Tests + JavaScript-Analyse + AI-Insights
- **Verwendung**: Vollständige Sicherheitsanalyse

### Compliance Scan
- **Dauer**: ~3 Minuten
- **Prüfungen**: OWASP und GDPR Compliance-Tests
- **Verwendung**: Compliance-Validierung

## 📈 Beispiel-Ausgabe

```
🔍 Scan-Ergebnisse:
==================================================
🌐 URL: https://example.com
⏱️  Dauer: 45230ms
📊 Gesamtscore: 72/100
⚠️  Risiko-Level: MEDIUM

📋 Befunde nach Schweregrad:
  HIGH: 2
  MEDIUM: 5
  LOW: 3

🚨 Wichtigste Probleme:
  1. Cross-Site Scripting (XSS) (2x)
     XSS-Schwachstellen ermöglichen Code-Injection-Angriffe
  2. Fehlende Sicherheits-Header (3x)
     Wichtige Sicherheits-Header fehlen

🤖 AI-Insights:
  1. Multiple XSS Vulnerabilities
     Mehrere XSS-Schwachstellen deuten auf systematische Probleme hin
     Confidence: 95%

💡 Top-Empfehlungen:
  1. Implementiere Content-Security-Policy
     CSP verhindert XSS-Angriffe durch Kontrolle der ausführbaren Ressourcen
     Aufwand: medium

📜 Compliance Status:
  OWASP: 65/100 (13/20 bestanden)
  GDPR: ❌ Issues found
```

## 🧪 Tests

```bash
# Unit Tests ausführen
npm test

# Tests mit Coverage
npm run test:coverage

# Tests im Watch-Modus
npm run test:watch

# Integrations-Test
npm run demo test
```

## 📝 Entwicklung

### Projekt-Struktur

```
src/
├── services/           # Kern-Services
│   ├── ChromeDevToolsService.ts
│   ├── GenkitAnalysisService.ts
│   └── ScanOrchestrator.ts
├── types/             # TypeScript-Definitionen
├── config/            # Konfigurationsmanagement
├── utils/             # Hilfsfunktionen
│   └── Logger.ts
├── cli.ts             # CLI-Interface
└── index.ts           # Haupt-Export

tests/                 # Test-Dateien
docs/                  # Dokumentation
config/                # Konfigurationsdateien
```

### Code-Qualität

```bash
# Linting
npm run lint
npm run lint:fix

# Formatierung
npm run format

# Type-Checking
npm run type-check
```

## 🚀 Deployment

### Docker

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY dist/ ./dist/
COPY config/ ./config/

EXPOSE 3000
CMD ["node", "dist/index.js"]
```

### Cloud Deployment

```bash
# Build für Produktion
npm run build

# Docker Image erstellen
docker build -t websecurity-saas .

# Zu Cloud Registry pushen
docker push gcr.io/your-project/websecurity-saas
```

## 🔧 Konfiguration

### Scan-Profile anpassen

```typescript
// config/scan-profiles.json
{
  "custom": {
    "name": "Custom Scan",
    "description": "Benutzerdefinierte Prüfungen",
    "enabledChecks": ["xss", "csrf", "security_headers"],
    "maxDepth": 2,
    "followRedirects": true,
    "checkSubdomains": false
  }
}
```

### AI-Modell konfigurieren

```bash
# Verschiedene Genkit-Modelle
GENKIT_MODEL=gemini-1.5-pro      # Höchste Qualität
GENKIT_MODEL=gemini-1.5-flash    # Schnellere Antworten
GENKIT_MODEL=claude-3-sonnet     # Alternative AI

# AI-Parameter anpassen
AI_TEMPERATURE=0.3               # Kreativität (0.0-1.0)
AI_CONFIDENCE_THRESHOLD=0.7      # Mindest-Confidence
```

## 🤝 Beitragen

1. Fork das Repository
2. Erstelle einen Feature-Branch (`git checkout -b feature/amazing-feature`)
3. Committe deine Änderungen (`git commit -m 'Add amazing feature'`)
4. Push zum Branch (`git push origin feature/amazing-feature`)
5. Öffne eine Pull Request

## 📄 Lizenz

Dieses Projekt steht unter der MIT-Lizenz. Siehe [LICENSE](LICENSE) für Details.

## 🙏 Danksagungen

- **Google Genkit Team** - Für das innovative AI-Framework
- **Chrome DevTools Team** - Für die MCP-Integration
- **OWASP Community** - Für Sicherheitsstandards und Best Practices

## 📞 Support

Bei Fragen oder Problemen:

- 📧 **Email**: support@websecurity-saas.com
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-org/websecurity-saas-poc/issues)
- 📖 **Dokumentation**: [Wiki](https://github.com/your-org/websecurity-saas-poc/wiki)

---

**⚡ Entwickelt mit Leidenschaft für Websicherheit und AI-Innovation**

