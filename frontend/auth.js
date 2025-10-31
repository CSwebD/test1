// Add this script to your existing pages to handle authentication

const API_URL = 'http://localhost:3000'; // Update with your backend URL

// Check if user is logged in
function isLoggedIn() {
    return localStorage.getItem('authToken') !== null;
}

// Get current user
function getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

// Logout function
async function logout() {
    const token = localStorage.getItem('authToken');
    
    if (token) {
        try {
            await fetch(`${API_URL}/api/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
        } catch (error) {
            console.error('Logout error:', error);
        }
    }
    
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
}

// Make authenticated request
async function authenticatedFetch(url, options = {}) {
    const token = localStorage.getItem('authToken');
    
    if (!token) {
        window.location.href = 'login.html';
        return;
    }
    
    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
    };
    
    try {
        const response = await fetch(url, { ...options, headers });
        
        if (response.status === 401) {
            // Token expired or invalid
            localStorage.removeItem('authToken');
            localStorage.removeItem('user');
            window.location.href = 'login.html';
            return;
        }
        
        return response;
    } catch (error) {
        console.error('Request error:', error);
        throw error;
    }
}

// Update navbar to show user info
function updateNavbar() {
    if (isLoggedIn()) {
        const user = getCurrentUser();
        
        // Find login/signup buttons and replace with user menu
        const navButtons = document.querySelector('.nav-buttons');
        if (navButtons) {
            navButtons.innerHTML = `
                <div class="user-menu">
                    <span class="username">Welcome, ${user.username}!</span>
                    <button onclick="logout()" class="btn-logout">Logout</button>
                </div>
            `;
        }
    }
}

// Protect pages that require authentication
function requireAuth() {
    if (!isLoggedIn()) {
        window.location.href = 'login.html';
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    updateNavbar();
});

// Export functions for use in other scripts
window.auth = {
    isLoggedIn,
    getCurrentUser,
    logout,
    authenticatedFetch,
    requireAuth,
    updateNavbar,
};