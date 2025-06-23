let isLoggingIn = false;
let isRegistering = false;
let validations = {
  username: false,
  email: false,
  password: false,
  passwordMatch: false
};

function checkAuth() {
  const token = localStorage.getItem('token');
  if (!token && !['login.html', 'register.html'].includes(window.location.pathname.split('/').pop())) {
    window.location.href = 'login.html';
  }
}

checkAuth();

function togglePassword(inputId) {
  const input = document.getElementById(inputId);
  const icon = input.parentElement.querySelector('.password-toggle i');
  if (input.type === 'password') {
    input.type = 'text';
    icon.classList.remove('fa-eye');
    icon.classList.add('fa-eye-slash');
  } else {
    input.type = 'password';
    icon.classList.remove('fa-eye-slash');
    icon.classList.add('fa-eye');
  }
}

function showError(message, page) {
  const errorDiv = document.getElementById('errorMessage');
  if (errorDiv) {
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    document.getElementById('successMessage').style.display = 'none';
  } else {
    alert(message);
  }
}

function showSuccess(message, page) {
  const successDiv = document.getElementById('successMessage');
  if (successDiv) {
    successDiv.textContent = message;
    successDiv.style.display = 'block';
    document.getElementById('errorMessage').style.display = 'none';
  } else {
    alert(message);
  }
}

function hideMessages() {
  const errorDiv = document.getElementById('errorMessage');
  const successDiv = document.getElementById('successMessage');
  if (errorDiv) errorDiv.style.display = 'none';
  if (successDiv) successDiv.style.display = 'none';
}

function validateUsername() {
  const username = document.getElementById('registerUsername')?.value.trim();
  const input = document.getElementById('registerUsername');
  const validation = document.getElementById('usernameValidation');
  if (!username || !input || !validation) return;

  if (username.length >= 3 && /^[a-zA-Z0-9_]+$/.test(username)) {
    input.classList.remove('invalid');
    input.classList.add('valid');
    validation.className = 'validation-icon valid fas fa-check';
    validations.username = true;
  } else if (username.length > 0) {
    input.classList.remove('valid');
    input.classList.add('invalid');
    validation.className = 'validation-icon invalid fas fa-times';
    validations.username = false;
  } else {
    input.classList.remove('valid', 'invalid');
    validation.className = 'validation-icon';
    validations.username = false;
  }
  updateSubmitButton();
}

function validateEmail() {
  const email = document.getElementById('registerEmail')?.value.trim();
  const input = document.getElementById('registerEmail');
  const validation = document.getElementById('emailValidation');
  if (!email || !input || !validation) return;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (emailRegex.test(email)) {
    input.classList.remove('invalid');
    input.classList.add('valid');
    validation.className = 'validation-icon valid fas fa-check';
    validations.email = true;
  } else if (email.length > 0) {
    input.classList.remove('valid');
    input.classList.add('invalid');
    validation.className = 'validation-icon invalid fas fa-times';
    validations.email = false;
  } else {
    input.classList.remove('valid', 'invalid');
    validation.className = 'validation-icon';
    validations.email = false;
  }
  updateSubmitButton();
}

function validatePassword() {
  const password = document.getElementById('registerPassword')?.value;
  const input = document.getElementById('registerPassword');
  const validation = document.getElementById('passwordValidation');
  const strengthBar = document.getElementById('strengthBar');
  const strengthText = document.getElementById('strengthText');
  if (!password || !input || !validation || !strengthBar || !strengthText) return;

  const lengthReq = document.getElementById('req-length');
  const uppercaseReq = document.getElementById('req-uppercase');
  const lowercaseReq = document.getElementById('req-lowercase');
  const numberReq = document.getElementById('req-number');

  const hasLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);

  lengthReq.className = 'requirement' + (hasLength ? ' met' : '');
  lengthReq.querySelector('i').className = 'fas fa-' + (hasLength ? 'check' : 'times');
  uppercaseReq.className = 'requirement' + (hasUppercase ? ' met' : '');
  uppercaseReq.querySelector('i').className = 'fas fa-' + (hasUppercase ? 'check' : 'times');
  lowercaseReq.className = 'requirement' + (hasLowercase ? ' met' : '');
  lowercaseReq.querySelector('i').className = 'fas fa-' + (hasLowercase ? 'check' : 'times');
  numberReq.className = 'requirement' + (hasNumber ? ' met' : '');
  numberReq.querySelector('i').className = 'fas fa-' + (hasNumber ? 'check' : 'times');

  let strength = 0;
  if (hasLength) strength++;
  if (hasUppercase) strength++;
  if (hasLowercase) strength++;
  if (hasNumber) strength++;

  if (strength >= 4) {
    strengthBar.className = 'strength-bar strength-strong';
    strengthText.textContent = 'Strong password';
    input.classList.remove('invalid');
    input.classList.add('valid');
    validation.className = 'validation-icon valid fas fa-check';
    validations.password = true;
  } else if (strength >= 2) {
    strengthBar.className = 'strength-bar strength-medium';
    strengthText.textContent = 'Medium password';
    input.classList.remove('invalid');
    input.classList.add('valid');
    validations.password = true;
  } else if (password.length > 0) {
    strengthBar.className = 'strength-bar strength-weak';
    strengthText.textContent = 'Weak password';
    input.classList.remove('valid');
    input.classList.add('invalid');
    validation.className = 'validation-icon invalid fas fa-times';
    validations.password = false;
  } else {
    strengthBar.className = 'strength-bar';
    strengthText.textContent = 'Password strength';
    input.classList.remove('valid', 'invalid');
    validation.className = 'validation-icon';
    validations.password = false;
  }
  validatePasswordMatch();
  updateSubmitButton();
}

function validatePasswordMatch() {
  const password = document.getElementById('registerPassword')?.value;
  const confirmPassword = document.getElementById('confirmPassword')?.value;
  const input = document.getElementById('confirmPassword');
  const validation = document.getElementById('confirmValidation');
  if (!password || !confirmPassword || !input || !validation) return;

  if (password === confirmPassword && confirmPassword.length > 0) {
    input.classList.remove('invalid');
    input.classList.add('valid');
    validation.className = 'validation-icon valid fas fa-check';
    validations.passwordMatch = true;
  } else if (confirmPassword.length > 0) {
    input.classList.remove('valid');
    input.classList.add('invalid');
    validation.className = 'validation-icon invalid fas fa-times';
    validations.passwordMatch = false;
  } else {
    input.classList.remove('valid', 'invalid');
    validation.className = 'validation-icon';
    validations.passwordMatch = false;
  }
  updateSubmitButton();
}

function updateSubmitButton() {
  const termsCheck = document.getElementById('termsCheck')?.checked;
  const registerBtn = document.getElementById('registerBtn');
  if (!registerBtn) return;
  registerBtn.disabled = !(validations.username && validations.email && validations.password && validations.passwordMatch && termsCheck);
}

async function handleRegister(event) {
  event.preventDefault();
  if (isRegistering) return;

  const name = document.getElementById('registerName')?.value.trim();
  const username = document.getElementById('registerUsername')?.value.trim();
  const email = document.getElementById('registerEmail')?.value.trim();
  const role = document.getElementById('registerRole')?.value;
  const password = document.getElementById('registerPassword')?.value;

  if (!name || !username || !email || !role || !password) {
    showError('Please fill in all fields', 'register');
    return;
  }

  isRegistering = true;
  const registerBtn = document.getElementById('registerBtn');
  registerBtn.disabled = true;
  registerBtn.innerHTML = '<div class="loading"></div><span>Creating Account...</span>';
  hideMessages();

  try {
    const response = await fetch('http://localhost:3000/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, username, email, password, role })
    });
    const data = await response.json();
    if (data.token) {
      showSuccess('Registration successful! Redirecting...', 'register');
      localStorage.setItem('token', data.token);
      setTimeout(() => {
        window.location.href = 'index.html';
      }, 1000);
    } else {
      showError(data.error || 'Registration failed', 'register');
    }
  } catch (error) {
    showError('Connection error. Please check your internet connection.', 'register');
  } finally {
    isRegistering = false;
    registerBtn.disabled = false;
    registerBtn.innerHTML = '<span>Create Account</span>';
  }
}

async function handleLogin(event) {
  event.preventDefault();
  if (isLoggingIn) return;

  const username = document.getElementById('loginUsername')?.value.trim();
  const password = document.getElementById('loginPassword')?.value;

  if (!username || !password) {
    showError('Please fill in all fields', 'login');
    return;
  }

  isLoggingIn = true;
  const loginBtn = document.getElementById('loginBtn');
  loginBtn.disabled = true;
  loginBtn.innerHTML = '<div class="loading"></div><span>Signing In...</span>';
  hideMessages();

  try {
    const response = await fetch('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await response.json();
    if (data.token) {
      showSuccess('Login successful! Redirecting...', 'login');
      localStorage.setItem('token', data.token);
      setTimeout(() => {
        window.location.href = 'index.html';
      }, 1000);
    } else {
      showError(data.error || 'Login failed', 'login');
    }
  } catch (error) {
    showError('Connection error. Please check your internet connection.', 'login');
  } finally {
    isLoggingIn = false;
    loginBtn.disabled = false;
    loginBtn.innerHTML = '<span>Sign In</span>';
  }
}

function logout() {
  localStorage.removeItem('token');
  window.location.href = 'login.html';
}

async function startScan() {
  const rawUrl = document.getElementById('urlInput')?.value;
  if (!rawUrl) {
    alert('Please enter a domain to scan');
    return;
  }
  const sanitizedUrl = rawUrl.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
  const loader = document.getElementById('loader');
  const scoreDiv = document.getElementById('score');
  const resultsDiv = document.getElementById('results');
  if (!loader || !scoreDiv || !resultsDiv) return;

  loader.classList.remove('hidden');
  scoreDiv.classList.add('hidden');
  resultsDiv.innerHTML = '';

  try {
    const response = await fetch('http://localhost:3000/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + localStorage.getItem('token')
      },
      body: JSON.stringify({ url: sanitizedUrl })
    });

    const data = await response.json();
    if (response.ok) {
      displayResults(data);
      const score = calculateScore(data);
      scoreDiv.innerHTML = `🔐 Security Score: ${score}/100`;
      scoreDiv.classList.remove('hidden');
    } else {
      resultsDiv.innerHTML = `<p style="color:red;">Error: ${data.error}</p>`;
    }
  } catch (error) {
    resultsDiv.innerHTML = `<p style="color:red;">Error: ${error.message}</p>`;
  } finally {
    loader.classList.add('hidden');
  }
}

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

function analyzeResults(data) {
  const vulnerabilities = [];

  if (!data.ssl) vulnerabilities.push("❌ SSL certificate missing or invalid.");
  else {
    const expiry = new Date(data.ssl.valid_to);
    const now = new Date();
    const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
    if (daysLeft < 30) vulnerabilities.push("⚠️ SSL certificate expires in less than 30 days.");
    if (!['TLSv1.3', 'TLSv1.2'].includes(data.ssl.protocol))
      vulnerabilities.push(`❌ Insecure SSL protocol used: ${data.ssl.protocol}`);
  }

  const requiredHeaders = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection"
  ];
  requiredHeaders.forEach(header => {
    if (!data.headers[header]) vulnerabilities.push(`⚠️ Missing security header: ${header}`);
  });

  const riskyPorts = [21, 22, 23, 25, 110, 135, 139, 143, 3389];
  (data.ports || []).forEach(port => {
    if (riskyPorts.includes(port))
      vulnerabilities.push(`🛑 Risky port open: ${port}`);
  });

  return vulnerabilities;
}

function displayResults(data) {
  const vulnerabilities = analyzeResults(data);
  const resultsDiv = document.getElementById('results');

  resultsDiv.innerHTML = `
    <div class="card">
      <h2>🔐 SSL Info</h2>
      <p><b>Protocol:</b> ${data.ssl?.protocol || 'N/A'}</p>
      <p><b>Valid From:</b> ${data.ssl?.valid_from || 'N/A'}</p>
      <p><b>Valid To:</b> ${data.ssl?.valid_to || 'N/A'}</p>
      <p><b>Issued By:</b> ${data.ssl?.issuer.CN || 'N/A'}</p>
    </div>
    <div class="card">
      <h2>📦 HTTP Headers</h2>
      <ul>${Object.entries(data.headers || {}).map(([k, v]) => `<li><b>${k}:</b> ${v}</li>`).join('')}</ul>
    </div>
    <div class="card">
      <h2>🌐 Open Ports</h2>
      <p>${data.ports.join(', ') || 'None'}</p>
    </div>
    <div class="card ${vulnerabilities.length ? 'alert' : 'safe'}">
      <h2>${vulnerabilities.length ? '⚠️ Vulnerabilities Found' : '✅ No Critical Vulnerabilities'}</h2>
      <ul>${vulnerabilities.map(v => `<li>${v}</li>`).join('')}</ul>
    </div>
  `;
}

async function fetchScans() {
  const sortBy = document.getElementById('sortBy')?.value;
  if (!sortBy) return;

  try {
    const response = await fetch('http://localhost:3000/api/scans', {
      headers: {
        'Authorization': 'Bearer ' + localStorage.getItem('token')
      }
    });
    const scans = await response.json();
    displayScans(scans, sortBy);
  } catch (error) {
    console.error('Error fetching scans:', error);
  }
}

function displayScans(scans, sortBy) {
  const scanHistory = document.getElementById('scanHistory');
  if (!scanHistory) return;

  scans.sort((a, b) => {
    if (sortBy.includes('score')) {
      return sortBy.includes('DESC') ? b.score - a.score : a.score - b.score;
    } else {
      return sortBy.includes('DESC') ? new Date(b.scan_date) - new Date(a.scan_date) : new Date(a.scan_date) - new Date(b.scan_date);
    }
  });

  scanHistory.innerHTML = scans.map(scan => `
    <div class="scan-item">
      <div>
        <p><b>Domain:</b> ${scan.domain}</p>
        <p><b>Date:</b> ${new Date(scan.scan_date).toLocaleString()}</p>
        <p><b>Score:</b> ${scan.score}/100</p>
      </div>
      <button onclick="deleteScan(${scan.id})">🗑️ Delete</button>
    </div>
  `).join('');
}

async function deleteScan(id) {
  if (!confirm('Are you sure you want to delete this scan?')) return;
  try {
    const response = await fetch(`http://localhost:3000/api/scans/${id}`, {
      method: 'DELETE',
      headers: {
        'Authorization': 'Bearer ' + localStorage.getItem('token')
      }
    });
    if (response.ok) {
      fetchScans();
    } else {
      alert('Failed to delete scan');
    }
  } catch (error) {
    alert('Error: ' + error.message);
  }
}

async function fetchUserProfile() {
  try {
    const response = await fetch('http://localhost:3000/api/auth/profile', {
      headers: {
        'Authorization': 'Bearer ' + localStorage.getItem('token')
      }
    });
    const user = await response.json();
    document.getElementById('userName').textContent = user.name;
    document.getElementById('userEmail').textContent = user.email;
    document.getElementById('userRole').textContent = user.role;
    fetchScans();
  } catch (error) {
    console.error('Error fetching profile:', error);
    logout();
  }
}

if (window.location.pathname.includes('profile.html')) {
  fetchUserProfile();
}

// Add input event listeners for real-time validation
document.addEventListener('DOMContentLoaded', () => {
  const inputs = ['registerUsername', 'registerEmail', 'registerPassword', 'confirmPassword', 'loginUsername', 'loginPassword'];
  inputs.forEach(id => {
    const input = document.getElementById(id);
    if (input) input.addEventListener('input', hideMessages);
  });
});