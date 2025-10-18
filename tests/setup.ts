/**
 * Jest Test Setup
 * Globale Test-Konfiguration und Mocks
 */

import dotenv from 'dotenv';

// Environment-Variablen für Tests laden
dotenv.config({ path: '.env.test' });

// Global Test Timeout
jest.setTimeout(30000);

// Mock für Puppeteer (da Browser-Tests in CI schwierig sind)
jest.mock('puppeteer', () => ({
  launch: jest.fn().mockResolvedValue({
    newPage: jest.fn().mockResolvedValue({
      goto: jest.fn().mockResolvedValue({
        status: () => 200,
        headers: () => ({}),
        request: () => ({
          redirectChain: () => []
        })
      }),
      title: jest.fn().mockResolvedValue('Test Page'),
      url: jest.fn().mockReturnValue('https://example.com'),
      content: jest.fn().mockResolvedValue('<html><body>Test</body></html>'),
      cookies: jest.fn().mockResolvedValue([]),
      screenshot: jest.fn().mockResolvedValue(Buffer.from('fake-screenshot')),
      setUserAgent: jest.fn(),
      setRequestInterception: jest.fn(),
      on: jest.fn(),
      $$: jest.fn().mockResolvedValue([]),
      evaluate: jest.fn().mockResolvedValue({}),
      close: jest.fn()
    }),
    close: jest.fn()
  })
}));

// Console-Ausgaben in Tests unterdrücken (außer Errors)
const originalConsole = console;
global.console = {
  ...originalConsole,
  log: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: originalConsole.error
};

