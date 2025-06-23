const express = require('express');
const router = express.Router();
const sslScanner = require('../utils/sslScanner');
const headerScanner = require('../utils/headerScanner');
const portScanner = require('../utils/portScanner');
const db = require('../db');

router.post('/', async (req, res) => {
  const { url } = req.body;
  console.log('Received URL:', url);

  try {
    const sslResults = await sslScanner(url).catch(() => null);
    const headerResults = await headerScanner(url);
    const portResults = await portScanner(url);

    const score = calculateScore({ ssl: sslResults, headers: headerResults, ports: portResults });

    db.query(`
      INSERT INTO scans (user_id, domain, ssl_protocol, ssl_valid_from, ssl_valid_to, issuer, headers, open_ports, score)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      req.user.id,
      url,
      sslResults?.protocol,
      sslResults?.valid_from,
      sslResults?.valid_to,
      sslResults?.issuer.CN,
      JSON.stringify(headerResults),
      JSON.stringify(portResults),
      score
    ], (err) => {
      if (err) console.error('Error saving scan:', err);
    });

    res.json({
      ssl: sslResults,
      headers: headerResults,
      ports: portResults,
      score
    });
  } catch (error) {
    console.error('Scanning failed:', error);
    res.status(500).json({ error: 'Scanning failed', details: error.message });
  }
});

function calculateScore(data) {
  let score = 100;

  if (!data.ssl) score -= 30;
  else {
    const expiry = new Date(data.ssl.valid_to);
    const now = new Date();
    const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
    if (daysLeft < 30) score -= 20;
    if (!['TLSv1.3', 'TLSv1.2'].includes(data.ssl.protocol)) score -= 20;
  }

  const requiredHeaders = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection"
  ];
  requiredHeaders.forEach(header => {
    if (!data.headers[header]) score -= 5;
  });

  const riskyPorts = [21, 22, 23, 25, 110, 135, 139, 143, 3389];
  data.ports.forEach(port => {
    if (riskyPorts.includes(port)) score -= 10;
  });

  return Math.max(0, score);
}

module.exports = router;