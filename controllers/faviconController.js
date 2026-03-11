export const getFavicon = async (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).send('Domain query parameter is required');
  }

  try {
    const googleUrl = `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
    
    // Pass along headers mimicking a standard browser to avoid detection/blocks
    const response = await fetch(googleUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      }
    });

    // If Google cannot find a specific favicon, it ultimately returns a 404 (even if it redirects first)
    // We catch this and return our own 404 so the frontend can render the custom Globe fallback icon.
    if (response.status === 404) {
      return res.status(404).send('Favicon not found');
    }

    if (!response.ok) {
      return res.status(response.status).send('Failed to fetch favicon');
    }

    const contentType = response.headers.get('content-type');
    if (contentType) {
      res.setHeader('Content-Type', contentType);
    }
    
    // Setup cache control so the browser caches the image, reducing backend load
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 1 day

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    
    res.send(buffer);
  } catch (error) {
    console.error('Favicon Proxy Error:', error);
    res.status(500).send('Internal Server Error fetching favicon');
  }
};
