const backendUrl = (process.env.BACKEND_URL || 'http://20.41.223.88').replace(/\/$/, '');
const frontendOrigin = (process.env.FRONTEND_ORIGIN || 'http://frontend.greensand-a82f7b12.southindia.azurecontainerapps.io').replace(/\/$/, '');
const timeout = AbortSignal.timeout(10_000);

async function request(path, options = {}) {
  const response = await fetch(`${backendUrl}${path}`, {
    signal: timeout,
    ...options
  });
  return response;
}

try {
  const health = await request('/health');
  if (!health.ok) throw new Error(`/health returned HTTP ${health.status}`);

  const session = await request('/api/me', {
    headers: { Origin: frontendOrigin }
  });
  const allowedOrigin = session.headers.get('access-control-allow-origin');
  const allowsCredentials = session.headers.get('access-control-allow-credentials');

  if (allowedOrigin !== frontendOrigin) {
    throw new Error(`CORS failed: Access-Control-Allow-Origin is ${JSON.stringify(allowedOrigin)}, expected ${JSON.stringify(frontendOrigin)}`);
  }
  if (allowsCredentials !== 'true') {
    throw new Error(`CORS failed: Access-Control-Allow-Credentials is ${JSON.stringify(allowsCredentials)}, expected "true"`);
  }
  if (![200, 401].includes(session.status)) {
    throw new Error(`/api/me returned unexpected HTTP ${session.status}`);
  }

  console.log(`Connection succeeded: ${backendUrl}`);
  console.log(`CORS allows: ${frontendOrigin}`);
  console.log(`/api/me returned HTTP ${session.status}${session.status === 401 ? ' (expected before login)' : ''}`);
} catch (error) {
  console.error(`Connection test failed: ${error.message}`);
  process.exitCode = 1;
}
