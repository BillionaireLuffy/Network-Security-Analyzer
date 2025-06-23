const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { body, validationResult } = require('express-validator');

const router = express.Router();
const SECRET = 'your_jwt_secret';

router.post('/register', [
  body('name').notEmpty(),
  body('username').notEmpty(),
  body('email').isEmail(),
  body('password').isLength({ min: 5 }),
  body('role').isIn(['Student', 'Teacher', 'Developer', 'Others'])
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, username, email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  db.query('INSERT INTO users (name, username, email, password, role) VALUES (?, ?, ?, ?, ?)',
    [name, username, email, hashedPassword, role], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      const token = jwt.sign({ id: result.insertId, username }, SECRET, { expiresIn: '1h' });
      res.json({ message: 'User registered successfully', token });
    });
});

router.post('/login', [
  body('username').notEmpty(),
  body('password').notEmpty()
], (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

    const user = results[0];
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  });
});

router.get('/profile', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });

    db.query('SELECT name, email, role FROM users WHERE id = ?', [user.id], (err, results) => {
      if (err || results.length === 0) return res.status(400).json({ error: 'User not found' });
      res.json(results[0]);
    });
  });
});

module.exports = router;