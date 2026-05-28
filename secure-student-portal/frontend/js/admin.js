// Security: Admin Dashboard JavaScript

// Security: Require admin authentication
requireAdmin();

// Load admin data on page load
document.addEventListener('DOMContentLoaded', async () => {
  loadUsers();
  setupEventListeners();
});

// Setup event listeners
function setupEventListeners() {
  const refreshBtn = document.getElementById('refreshBtn');
  const auditBtn = document.getElementById('auditBtn');
  const closeAuditBtn = document.getElementById('closeAuditBtn');

  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadUsers);
  }

  if (auditBtn) {
    auditBtn.addEventListener('click', showAuditLogs);
  }

  if (closeAuditBtn) {
    closeAuditBtn.addEventListener('click', closeAuditLogs);
  }
}

// Load all users
async function loadUsers() {
  try {
    const response = await apiCall('/api/admin/users', {
      method: 'GET'
    });

    const users = await response.json();

    if (response.ok) {
      displayUsers(users);
      clearMessages();
    } else {
      showError(users.error || 'Failed to load users');
    }
  } catch (error) {
    console.error('Error loading users:', error);
    showError('Connection error. Please try again.');
  }
}

// Display users in table
function displayUsers(users) {
  const tbody = document.getElementById('usersTableBody');

  if (!users || users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">No users found</td></tr>';
    return;
  }

  tbody.innerHTML = users
    .map(
      (user) => `
    <tr>
      <td>${escapeHtml(user.name)}</td>
      <td>${escapeHtml(user.email)}</td>
      <td>${escapeHtml(user.studentId)}</td>
      <td>${escapeHtml(user.phone)}</td>
      <td>
        <select id="role-${user.id}" data-user-id="${user.id}" style="padding: 0.5rem; border: 1px solid #bdc3c7; border-radius: 4px;">
          <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
          <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
        </select>
      </td>
      <td>${formatDate(user.createdAt)}</td>
      <td>
        <button onclick="deleteUser(${user.id})" class="btn danger" style="padding: 0.5rem 1rem; font-size: 0.85rem;">Delete</button>
      </td>
    </tr>
  `
    )
    .join('');

  // Add event listeners for role changes
  users.forEach((user) => {
    const roleSelect = document.getElementById(`role-${user.id}`);
    if (roleSelect) {
      roleSelect.addEventListener('change', (e) => {
        changeUserRole(user.id, e.target.value);
      });
    }
  });
}

// Change user role
async function changeUserRole(userId, newRole) {
  const user = getCurrentUser();

  if (user && user.id && user.id === userId && newRole !== 'admin') {
    alert('Cannot demote yourself from admin');
    location.reload();
    return;
  }

  try {
    const response = await apiCall(`/api/admin/users/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role: newRole })
    });

    const data = await response.json();

    if (response.ok) {
      showSuccess('User role updated successfully!');
      setTimeout(() => {
        loadUsers();
      }, 1000);
    } else {
      showError(data.error || 'Failed to update user role');
      loadUsers();
    }
  } catch (error) {
    console.error('Error updating user role:', error);
    showError('Connection error. Please try again.');
    loadUsers();
  }
}

// Delete user
async function deleteUser(userId) {
  const currentUser = getCurrentUser();

  if (currentUser && currentUser.id && currentUser.id === userId) {
    alert('Cannot delete your own account');
    return;
  }

  // Security: Confirm action before deletion
  if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
    return;
  }

  try {
    const response = await apiCall(`/api/admin/users/${userId}`, {
      method: 'DELETE'
    });

    const data = await response.json();

    if (response.ok) {
      showSuccess('User deleted successfully!');
      setTimeout(() => {
        loadUsers();
      }, 1000);
    } else {
      showError(data.error || 'Failed to delete user');
      loadUsers();
    }
  } catch (error) {
    console.error('Error deleting user:', error);
    showError('Connection error. Please try again.');
    loadUsers();
  }
}

// Show audit logs modal
async function showAuditLogs() {
  try {
    const response = await apiCall('/api/admin/audit-logs', {
      method: 'GET'
    });

    const logs = await response.json();

    if (response.ok) {
      displayAuditLogs(logs);
      document.getElementById('auditModal').style.display = 'block';
    } else {
      showError(logs.error || 'Failed to load audit logs');
    }
  } catch (error) {
    console.error('Error loading audit logs:', error);
    showError('Connection error. Please try again.');
  }
}

// Display audit logs
function displayAuditLogs(logs) {
  const tbody = document.getElementById('auditLogsBody');

  if (!logs || logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center;">No audit logs found</td></tr>';
    return;
  }

  tbody.innerHTML = logs
    .map(
      (log) => `
    <tr>
      <td>${escapeHtml(log.action)}</td>
      <td>${escapeHtml(log.user_email || '-')}</td>
      <td>${escapeHtml(log.ip_address || '-')}</td>
      <td>${formatDate(log.created_at)}</td>
    </tr>
  `
    )
    .join('');
}

// Close audit logs modal
function closeAuditLogs() {
  document.getElementById('auditModal').style.display = 'none';
}

// Close modal when clicking outside
window.addEventListener('click', (e) => {
  const modal = document.getElementById('auditModal');
  if (e.target === modal) {
    modal.style.display = 'none';
  }
});
