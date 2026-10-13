/**
 * Sub-Store Gist Preflight V1.1
 * Place as the LAST Script Operator in a Mihomo YAML file's processing pipeline.
 * Read-only probe of the same Gist-list API used before uploading artifacts.
 * Best effort only: never block updates or modify the YAML input.
 */
async function operator(input) {
  const prefix = '[GistPreflight]';
  const log = (message, warning = false) => {
    try {
      const fn = (warning && $substore.warn) || $substore.info;
      if (typeof fn === 'function') fn.call($substore, `${prefix} ${message}`);
    } catch (_) {}
  };

  try {
    const settings = $substore.read('settings') || {};
    if (!settings.gistToken) {
      log('SKIP: no Gist token configured; continuing', true);
      return input;
    }

    // Mirror Sub-Store's Gist base URL selection without changing settings.
    const defaultApi = 'https://api.github.com';
    const configuredApi = String(settings.githubApiUrl || '').trim().replace(/\/+$/, '') || defaultApi;
    const githubProxy = String(settings.githubProxy || '').trim().replace(/\/+$/, '');
    const base = configuredApi !== defaultApi
      ? configuredApi
      : (githubProxy ? `${githubProxy}/${defaultApi}` : defaultApi);
    const url = `${base}/gists?per_page=100&page=1`;

    let proxy = settings.defaultProxy || '';
    if (!proxy && typeof require === 'function') {
      try { proxy = require('process').env.SUB_STORE_BACKEND_DEFAULT_PROXY || ''; }
      catch (_) {}
    }

    let last = 'unknown';
    // Gradual backoff: 5 attempts, 24 seconds of total retry waits.
    const waits = [0, 2500, 4500, 7000, 10000];
    for (let i = 0; i < waits.length; i++) {
      if (waits[i]) await new Promise(resolve => setTimeout(resolve, waits[i]));
      const start = Date.now();
      try {
        const response = await $substore.http.get({
          url,
          timeout: 6000,
          headers: {
            Authorization: `token ${settings.gistToken}`,
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36',
            Accept: 'application/vnd.github+json'
          },
          ...(proxy ? { proxy } : {})
        });
        const body = response && response.body;
        let valid = false;
        if (response.statusCode === 200 && typeof body === 'string') {
          try { valid = Array.isArray(JSON.parse(body)); } catch (_) {}
        }
        if (valid) {
          log(`PASS attempt=${i + 1} elapsed=${Date.now() - start}ms`);
          return input;
        }
        last = `HTTP_${response.statusCode || 'unknown'}_or_invalid_gist_list`;
      } catch (error) {
        // Avoid logging URLs, response bodies, or anything containing the token.
        last = String(error?.code || error?.cause?.code || error?.name || 'network_error').slice(0, 48);
      }
      log(`attempt=${i + 1}/${waits.length} failed (${last})`);
    }
    log(`WARN: all ${waits.length} attempts failed (${last}); continuing`, true);
  } catch (_) {
    log('WARN: unexpected preflight error; continuing', true);
  }
  return input;
}
