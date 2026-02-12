// ---- Auth Frontend Logic ----

// Check if user is already logged in
(async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        if (res.ok) {
            window.location.href = '/dashboard';
        }
    } catch (e) { /* not logged in, stay on login page */ }
})();

// Check for error from OAuth redirect
const urlParams = new URLSearchParams(window.location.search);
const oauthError = urlParams.get('error');
if (oauthError) {
    setTimeout(() => showError(decodeURIComponent(oauthError)), 300);
    // Clean URL
    window.history.replaceState({}, document.title, '/');
}

// ---- Load OAuth Configuration ----
(async function loadOAuthConfig() {
    try {
        const res = await fetch('/api/auth/config');
        const config = await res.json();

        // Initialize Google Sign-In if configured
        if (config.googleClientId && config.googleClientId !== 'your-google-client-id') {
            initGoogleSignIn(config.googleClientId);
        } else {
            // Show fallback (disabled) button
            document.getElementById('google-signin-container').style.display = 'none';
            document.getElementById('google-signin-fallback').style.display = 'block';
        }

        // Configure GitHub button
        if (!config.githubConfigured) {
            const ghBtn = document.getElementById('github-login');
            ghBtn.disabled = true;
            ghBtn.style.opacity = '0.5';
            ghBtn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
        GitHub Sign-In (not configured)
      `;
        }
    } catch (e) {
        console.error('Failed to load OAuth config:', e);
    }
})();

// ---- Google Sign-In ----
function initGoogleSignIn(clientId) {
    // Wait for Google library to load
    function tryInit() {
        if (typeof google !== 'undefined' && google.accounts) {
            google.accounts.id.initialize({
                client_id: clientId,
                callback: handleGoogleResponse,
                auto_select: false,
                context: 'signin'
            });

            google.accounts.id.renderButton(
                document.getElementById('google-signin-container'),
                {
                    theme: 'filled_blue',
                    size: 'large',
                    width: '100%',
                    shape: 'rectangular',
                    text: 'continue_with',
                    logo_alignment: 'left'
                }
            );
        } else {
            setTimeout(tryInit, 200);
        }
    }
    tryInit();
}

async function handleGoogleResponse(response) {
    try {
        const res = await fetch('/api/auth/google', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credential: response.credential })
        });
        const data = await res.json();

        if (res.ok) {
            showSuccess('Google login successful! Redirecting...');
            setTimeout(() => window.location.href = '/dashboard', 800);
        } else {
            showError(data.error || 'Google login failed');
        }
    } catch (err) {
        showError('Network error during Google login.');
    }
}

// ---- GitHub Login — redirects to server which redirects to GitHub ----
document.getElementById('github-login').addEventListener('click', () => {
    if (document.getElementById('github-login').disabled) return;
    window.location.href = '/api/auth/github';
});

// ---- Tab switching ----
const tabs = document.querySelectorAll('.auth-tab');
const loginForm = document.getElementById('login-form');
const signupForm = document.getElementById('signup-form');
const errorEl = document.getElementById('auth-error');
const successEl = document.getElementById('auth-success');

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        hideMessages();

        if (tab.dataset.tab === 'login') {
            loginForm.classList.add('active');
            signupForm.classList.remove('active');
        } else {
            signupForm.classList.add('active');
            loginForm.classList.remove('active');
        }
    });
});

function showError(msg) {
    errorEl.textContent = msg;
    errorEl.classList.add('show');
    successEl.classList.remove('show');
}

function showSuccess(msg) {
    successEl.textContent = msg;
    successEl.classList.add('show');
    errorEl.classList.remove('show');
}

function hideMessages() {
    errorEl.classList.remove('show');
    successEl.classList.remove('show');
}

function setLoading(btn, loading) {
    if (loading) {
        btn.dataset.originalText = btn.textContent;
        btn.innerHTML = '<span class="spinner-sm"></span> Please wait...';
        btn.disabled = true;
    } else {
        btn.textContent = btn.dataset.originalText || 'Submit';
        btn.disabled = false;
    }
}

// ---- Login Form ----
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideMessages();
    const btn = document.getElementById('login-btn');
    setLoading(btn, true);

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: document.getElementById('login-email').value.trim(),
                password: document.getElementById('login-password').value
            })
        });
        const data = await res.json();

        if (res.ok) {
            showSuccess('Login successful! Redirecting...');
            setTimeout(() => window.location.href = '/dashboard', 800);
        } else {
            showError(data.error || 'Login failed');
            setLoading(btn, false);
        }
    } catch (err) {
        showError('Network error. Please try again.');
        setLoading(btn, false);
    }
});

// ---- Signup Form ----
signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideMessages();
    const btn = document.getElementById('signup-btn');
    setLoading(btn, true);

    try {
        const res = await fetch('/api/auth/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: document.getElementById('signup-name').value.trim(),
                email: document.getElementById('signup-email').value.trim(),
                password: document.getElementById('signup-password').value
            })
        });
        const data = await res.json();

        if (res.ok) {
            showSuccess('Account created! Redirecting...');
            setTimeout(() => window.location.href = '/dashboard', 800);
        } else {
            showError(data.error || 'Signup failed');
            setLoading(btn, false);
        }
    } catch (err) {
        showError('Network error. Please try again.');
        setLoading(btn, false);
    }
});
