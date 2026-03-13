const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// IP lookup proxy endpoint (avoids CORS issues)
app.get('/api/lookup/:ip', async (req, res) => {
  const { ip } = req.params;

  // Basic IP validation
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([a-fA-F0-9:]+)$/;
  if (!ipRegex.test(ip)) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }

  try {
    // Using ip-api.com (free, no key needed)
    const fetch = (await import('node-fetch')).default;
    const response = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`
    );
    const data = await response.json();

    if (data.status === 'fail') {
      return res.status(400).json({ error: data.message || 'Lookup failed' });
    }

    // Add threat assessment
    data.threatScore = calculateThreatScore(data);
    data.riskLevel = getRiskLevel(data.threatScore);

    res.json(data);
  } catch (err) {
    console.error('Lookup error:', err);
    res.status(500).json({ error: 'Failed to fetch IP data' });
  }
});

// Get requester's own IP
app.get('/api/myip', async (req, res) => {
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress ||
    '8.8.8.8';
  res.json({ ip: ip.replace('::ffff:', '') });
});

function calculateThreatScore(data) {
  let score = 0;
  if (data.proxy) score += 40;
  if (data.hosting) score += 25;
  if (data.mobile) score += 5;
  if (data.org && /vpn|proxy|tor|anonymous/i.test(data.org)) score += 30;
  if (data.isp && /vpn|proxy|anonymous/i.test(data.isp)) score += 20;
  return Math.min(score, 100);
}

function getRiskLevel(score) {
  if (score >= 70) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

app.listen(PORT, () => {
  console.log(`\n🚀 IP Threat Intelligence Tool running at http://localhost:${PORT}\n`);
});
