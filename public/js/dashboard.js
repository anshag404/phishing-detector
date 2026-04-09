// ---- Dashboard Frontend Logic ----

// Check authentication
let currentUser = null;

(async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        if (!res.ok) throw new Error();
        const data = await res.json();
        currentUser = data.user;
        document.getElementById('user-name').textContent = currentUser.name;
        document.getElementById('user-email').textContent = currentUser.email;
        document.getElementById('user-avatar').textContent = currentUser.name.charAt(0).toUpperCase();
        loadHistory();
    } catch (e) {
        window.location.href = '/';
    }
})();

// Logout
document.getElementById('logout-btn').addEventListener('click', async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.href = '/';
});

// Open scan modals
document.getElementById('card-url').addEventListener('click', () => openModal('url'));
document.getElementById('card-email').addEventListener('click', () => openModal('email'));
document.getElementById('card-website').addEventListener('click', () => openModal('website'));
document.getElementById('card-bulk').addEventListener('click', () => openModal('bulk'));

function openModal(type) {
    document.getElementById(`modal-${type}`).classList.add('show');
}

function closeModal(type) {
    document.getElementById(`modal-${type}`).classList.remove('show');
}

// Close modal on overlay click
document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            overlay.classList.remove('show');
        }
    });
});

// Close on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('show'));
    }
});

// Scanning animation messages
const scanMessages = [
    'Checking phishing indicators...',
    'Analyzing URL structure...',
    'Checking against known threats...',
    'Evaluating SSL certificates...',
    'Scanning for typosquatting...',
    'Detecting suspicious patterns...',
    'Generating threat report...'
];

function showScanning() {
    const overlay = document.getElementById('scanning-overlay');
    overlay.classList.add('show');
    let i = 0;
    const interval = setInterval(() => {
        document.getElementById('scanning-subtext').textContent = scanMessages[i % scanMessages.length];
        i++;
    }, 600);
    return interval;
}

function hideScanning(interval) {
    clearInterval(interval);
    document.getElementById('scanning-overlay').classList.remove('show');
}

// Submit scan
async function submitScan(e, type) {
    e.preventDefault();
    const inputId = `input-${type}`;
    const target = document.getElementById(inputId).value.trim();
    if (!target) return;

    closeModal(type);
    const interval = showScanning();

    try {
        // Add artificial delay for scanning effect
        await new Promise(r => setTimeout(r, 2000 + Math.random() * 1500));

        const res = await fetch(`/api/scan/${type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await res.json();
        hideScanning(interval);

        if (res.ok) {
            // Store report data and redirect
            sessionStorage.setItem('lastReport', JSON.stringify(data));
            window.location.href = '/report';
        } else {
            alert(data.error || 'Scan failed');
        }
    } catch (err) {
        hideScanning(interval);
        alert('Network error. Please try again.');
    }
}

// Bulk scan
async function submitBulkScan(e) {
    e.preventDefault();
    const input = document.getElementById('input-bulk').value.trim();
    if (!input) return;

    const targets = input.split('\n').map(u => u.trim()).filter(u => u);
    if (targets.length === 0) return;

    closeModal('bulk');
    const interval = showScanning();

    try {
        await new Promise(r => setTimeout(r, 2500 + Math.random() * 2000));

        const res = await fetch('/api/scan/bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targets })
        });

        const data = await res.json();
        hideScanning(interval);

        if (res.ok) {
            sessionStorage.setItem('lastReport', JSON.stringify({
                type: 'bulk',
                results: data.results,
                timestamp: data.timestamp
            }));
            window.location.href = '/report';
        } else {
            alert(data.error || 'Scan failed');
        }
    } catch (err) {
        hideScanning(interval);
        alert('Network error. Please try again.');
    }
}

// Load scan history
async function loadHistory() {
    try {
        const res = await fetch('/api/scan/history');
        if (!res.ok) return;
        const data = await res.json();

        const list = document.getElementById('history-list');
        const emptyState = document.getElementById('empty-history');

        if (data.scans.length === 0) {
            emptyState.style.display = '';
            return;
        }

        emptyState.style.display = 'none';
        list.innerHTML = '';

        data.scans.forEach(scan => {
            const item = document.createElement('div');
            item.className = 'history-item';
            item.onclick = () => viewReport(scan.id);

            const badgeClass = `badge-${scan.risk_level || 'safe'}`;
            const colorMap = { safe: 'var(--accent-green)', low: '#2196f3', medium: 'var(--accent-orange)', high: '#ff9800', critical: 'var(--danger)' };
            const scoreColor = colorMap[scan.risk_level] || 'var(--accent-green)';

            const date = new Date(scan.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

            item.innerHTML = `
        <span class="history-badge ${badgeClass}">${scan.risk_level}</span>
        <span class="history-type">${scan.type}</span>
        <span class="history-target">${scan.target}</span>
        <span class="history-score" style="color: ${scoreColor}">${scan.score}</span>
        <span class="history-date">${date}</span>
      `;
            list.appendChild(item);
        });
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

// View a past report
async function viewReport(id) {
    const interval = showScanning();
    try {
        const res = await fetch(`/api/scan/report/${id}`);
        const data = await res.json();
        hideScanning(interval);

        if (res.ok) {
            sessionStorage.setItem('lastReport', JSON.stringify({
                ...data,
                factors: data.details,
                riskLevel: data.risk_level
            }));
            window.location.href = '/report';
        }
    } catch (err) {
        hideScanning(interval);
        alert('Failed to load report');
    }
}
