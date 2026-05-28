// Security: Authentication JavaScript Utilities

// Security: Check if user is authenticated
function isAuthenticated() {
  const token = localStorage.getItem('token');
  return !!token;
}

// Security: Get JWT token from localStorage
function getToken() {
  return localStorage.getItem('token');
}

// Security: Get current user from localStorage
function getCurrentUser() {
  const userStr = localStorage.getItem('user');
  return userStr ? JSON.parse(userStr) : null;
}

// Security: Logout user and clear tokens
function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  window.location.href = 'index.html';
}

// Security: Redirect to login if not authenticated
function requireAuth() {
  if (!isAuthenticated()) {
    window.location.href = 'login.html';
  }
}

// Security: Redirect to login if not admin
function requireAdmin() {
  if (!isAuthenticated()) {
    window.location.href = 'login.html';
    return;
  }

  const user = getCurrentUser();
  if (user && user.role !== 'admin') {
    alert('Access Denied: Admin privileges required');
    window.location.href = 'dashboard.html';
  }
}

// Security: API call with JWT token in headers
async function apiCall(url, options = {}) {
  const token = getToken();

  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    ...options.headers
  };

  const response = await fetch(url, {
    ...options,
    headers
  });

  // Security: If token expired or invalid, redirect to login
  if (response.status === 401) {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
    return;
  }

  return response;
}

// Security: Escape HTML to prevent XSS
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Security: Display success message
function showSuccess(message) {
  const element = document.getElementById('successMessage');
  if (element) {
    element.textContent = message;
    element.style.display = 'block';
    element.classList.remove('error');
    element.classList.add('success');
  }
}

// Security: Display error message
function showError(message) {
  const element = document.getElementById('errorMessage');
  if (element) {
    element.textContent = message;
    element.style.display = 'block';
    element.classList.remove('success');
    element.classList.add('error');
  }
}

// Security: Clear messages
function clearMessages() {
  const successElement = document.getElementById('successMessage');
  const errorElement = document.getElementById('errorMessage');
  if (successElement) successElement.style.display = 'none';
  if (errorElement) errorElement.style.display = 'none';
}

// Security: Format date to readable string
function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

// Security: Setup logout button if it exists
document.addEventListener('DOMContentLoaded', () => {
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }

  // Display current user in navbar
  const userInfoElement = document.getElementById('userInfo');
  if (userInfoElement && isAuthenticated()) {
    const user = getCurrentUser();
    if (user) {
      userInfoElement.textContent = `${user.name} (${user.role})`;
    }
  }
});
