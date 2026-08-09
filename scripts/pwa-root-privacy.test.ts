import assert from 'node:assert/strict';
import test from 'node:test';
import { buildServiceWorkerSource } from '../webapp/vite.config';

test('the service worker never restores the conventional root from its application shell cache', () => {
  const source = buildServiceWorkerSource(['/vault', '/assets/app.js'], 'privacy-test');

  assert.match(source, /event\.respondWith\(networkFirstNavigation\(request\)\)/);
  assert.match(source, /url\.pathname === '\/' \|\| url\.pathname\.toLowerCase\(\) === '\/index\.html'/);
  assert.doesNotMatch(source, /event\.respondWith\(appShellNavigation\(request\)\)/);
  assert.doesNotMatch(source, /cache\.put\('\/'/);
  assert.doesNotMatch(source, /CRITICAL_SHELL_URLS/);

  const privateEntryBypass = source.indexOf("PRIVATE_ENTRY_PATH_RE.test(url.pathname)) return");
  const navigationHandler = source.indexOf('event.respondWith(networkFirstNavigation(request))');
  assert.ok(privateEntryBypass > 0, 'private entry navigations must bypass the Service Worker');
  assert.ok(privateEntryBypass < navigationHandler, 'the private entry bypass must run before SPA navigation handling');
});
