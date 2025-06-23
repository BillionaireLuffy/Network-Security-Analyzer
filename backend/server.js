const express = require('express');
const cors = require('cors');
const scanRoutes = require('./routes/scan');
const authRoutes = require('./routes/auth');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = 'your_jwt_secret';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

app.use('/api/auth', authRoutes);
app.use('/api/scan', authenticateToken, scanRoutes);
app.use('/api/scans', authenticateToken, require('./routes/scans'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
