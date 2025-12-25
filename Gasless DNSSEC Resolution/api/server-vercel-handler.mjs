
// Vercel serverless handler - to be appended to server-new.mjs
export default async function handler(req, res) {
  // Add CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, ngrok-skip-browser-warning');

  const { url, method } = req;

  // Preflight
  if (method === 'OPTIONS' && (url.startsWith('/resolve') || url.startsWith('/ccip-read'))) {
    res.status(204).end();
    return;
  }

  if (method === 'GET' && url.startsWith('/health')) {
    return handleHealth(req, res);
  }

  if (method === 'GET' && url.startsWith('/resolve')) {
    return handleResolveGet(req, res);
  }

  if (method === 'POST' && url.startsWith('/resolve')) {
    return handleResolvePost(req, res);
  }

  if (url.startsWith('/ccip-read')) {
    return handleCCIPRead(req, res);
  }

  res.status(404).json({ error: 'not_found' });
}

