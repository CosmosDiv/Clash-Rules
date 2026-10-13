/**
 * Sub-Store Raw Preflight V1.0
 * Place as the FIRST Script Operator in each subscription's processing pipeline.
 * Warm up GitHub Raw through Sub-Store's existing outbound route.
 * Best effort only: never block updates or modify the input.
 * Do not load this preflight through a remote Raw URL when deploying it:
 * the preflight would then depend on Raw being reachable before it runs.
 */
async function operator(input) {
  const prefix = '[RawPreflight]';
  const log = (message, warning = false) => {
    try {
      const fn = (warning && $substore.warn) || $substore.info;
      if (typeof fn === 'function') fn.call($substore, `\${prefix} \${message}`);
    } catch (_) {}
  };

  try {
    const settings = $substore.read('settings') || {};
    const origin = 'https://raw.githubusercontent.com/github/gitignore/main/README.md';
    let url = origin;

    // Follow the same GitHub download proxy prefix convention as Sub-Store.
    const githubProxy = String(settings.githubProxy || '').trim().replace(/\/+$/, '');
    if (githubProxy && settings.githubProxyRegex) {
      try {
        if (new RegExp(String(settings.githubProxyRegex), 'i').test(origin)) {
          url = `\${githubProxy}/\${origin}`;
        }
      } catch (_) {
        log('invalid GitHub proxy regex; probing original Raw URL');
      }
    }

    let proxy = settings.defaultProxy || '';
    if (!proxy && typeof require === 'function') {
      try { proxy = require('process').env.SUB_STORE_BACKEND_DEFAULT_PROXY || ''; }
      catch (_) {}
    }

    let last = 'unknown';
    const waits = [0, 1500, 3000];
    for (let i = 0; i < waits.length; i++) {
      if (waits[i]) await new Promise(resolve => setTimeout(resolve, waits[i]));
      const start = Date.now();
      try {
        const response = await $substore.http.get({
          url,
          timeout: 5000,
          headers: {
            'User-Agent': settings.defaultUserAgent || 'clash.meta/v1.19.23',
            Accept: 'text/plain'
          },
          ...(proxy ? { proxy } : {})
        });

        const body = response && response.body;
        if (response.statusCode === 200 && typeof body === 'string' &&
            body.length > 1024 && body.includes('.gitignore') &&
            body.includes('templates')) {
          log(`PASS attempt=\${i + 1} elapsed=\${Date.now() - start}ms`);
          return input;
        }
        last = `HTTP_\${response.statusCode || 'unknown'}_or_unexpected_body`;
      } catch (error) {
        // Never print a URL, credential, or complete exception message.
        last = String(error?.code || error?.cause?.code || error?.name || 'network_error').slice(0, 48);
      }
      log(`attempt=\${i + 1}/3 failed (\${last})`);
    }
    log(`WARN: all attempts failed (\${last}); continuing`, true);
  } catch (_) {
    log('WARN: unexpected preflight error; continuing', true);
  }
  return input;
}
