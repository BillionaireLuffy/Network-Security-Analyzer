const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Mohan137',
  database: 'security_app'
});

connection.connect((err) => {
  if (err) throw err;
  console.log('✅ Connected to MySQL');

  // Create users table
  connection.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      username VARCHAR(100) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      role ENUM('Student', 'Teacher', 'Developer', 'Others') DEFAULT 'Student',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) throw err;
  });

  // Create scans table
  connection.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      domain VARCHAR(255) NOT NULL,
      scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ssl_protocol VARCHAR(20),
      ssl_valid_from DATETIME,
      ssl_valid_to DATETIME,
      issuer VARCHAR(255),
      headers TEXT,
      open_ports TEXT,
      score INT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `, (err) => {
    if (err) throw err;
  });
});

module.exports = connection;