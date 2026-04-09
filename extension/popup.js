// ---- Popup Logic ----

document.addEventListener('DOMContentLoaded', async () => {
    // Get current tab scan result
    chrome.runtime.sendMessage({ type: 'GET_CURRENT_SCAN' }, (scan) => {
        const loading = document.getElementById('loading');
        const result = document.getElementById('scan-result');
        const factorsSection = document.getElementById('factors-section');

        if (scan) {
            loading.style.display = 'none';
            result.style.display = 'block';

            // Score animation
            const scoreNum = document.getElementById('score-number');
            const scoreCircle = document.getElementById('score-circle');
            const riskBadge = document.getElementById('risk-badge');
            const siteUrl = document.getElementById('site-url');

            // Set URL
            try {
                siteUrl.textContent = new URL(scan.url).hostname;
            } catch { siteUrl.textContent = scan.url; }

            // Animate score
            const circumference = 2 * Math.PI * 52;
            const offset = circumference - (scan.score / 100) * circumference;

            let color;
            if (scan.risk === 'safe') color = '#00e676';
            else if (scan.risk === 'low') color = '#2196f3';
            else if (scan.risk === 'medium') color = '#ffc107';
            else if (scan.risk === 'high') color = '#ff9800';
            else color = '#ff1744';

            scoreCircle.style.stroke = color;
            scoreCircle.style.strokeDashoffset = offset;
            scoreNum.style.color = color;

            // Animate number
            let current = 0;
            const step = Math.max(1, Math.floor(scan.score / 30));
            const timer = setInterval(() => {
                current = Math.min(current + step, scan.score);
                scoreNum.textContent = current;
                if (current >= scan.score) clearInterval(timer);
            }, 30);

            // Risk badge
            const badgeLabels = {
                safe: '✅ Safe', low: '🟢 Low Risk', medium: '⚠️ Caution',
                high: '🔶 High Risk', critical: '🚨 Critical'
            };
            riskBadge.textContent = badgeLabels[scan.risk] || scan.risk;
            riskBadge.className = 'risk-badge ' + scan.risk;

            // Factors
            if (scan.factors && scan.factors.length > 0) {
                factorsSection.style.display = 'block';
                const list = document.getElementById('factors-list');
                list.innerHTML = '';
                scan.factors.forEach(f => {
                    const item = document.createElement('div');
                    item.className = 'factor-item';
                    item.innerHTML = `
            <span class="factor-dot ${f.severity}"></span>
            <span class="factor-name">${f.name}</span>
            <span class="factor-pts">${f.points > 0 ? '+' : ''}${f.points}</span>
          `;
                    list.appendChild(item);
                });
            }
        } else {
            loading.innerHTML = '<p class="empty">Navigate to a website to scan it</p>';
        }
    });

    // Load history
    chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, (history) => {
        const list = document.getElementById('history-list');
        if (!history || history.length === 0) return;

        list.innerHTML = '';
        history.slice(0, 15).forEach(item => {
            let hostname;
            try { hostname = new URL(item.url).hostname; }
            catch { hostname = item.url; }

            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = `
        <span class="history-dot ${item.risk}"></span>
        <span class="history-url" title="${hostname}">${hostname}</span>
        <span class="history-score ${item.risk}">${item.score}</span>
      `;
            list.appendChild(div);
        });
    });
});
