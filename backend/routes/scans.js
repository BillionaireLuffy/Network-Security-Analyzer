const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/', (req, res) => {
  db.query('SELECT id, domain, scan_date, score FROM scans WHERE user_id = ?', [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

router.delete('/:id', (req, res) => {
  db.query('DELETE FROM scans WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Scan not found' });
    res.json({ message: 'Scan deleted successfully' });
  });
});

module.exports = router;