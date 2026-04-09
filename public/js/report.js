// ---- Report Page Frontend Logic ----

// Load report data from session storage
const reportData = JSON.parse(sessionStorage.getItem('lastReport'));

if (!reportData) {
    window.location.href = '/dashboard';
} else if (reportData.type === 'bulk') {
    renderBulkReport(reportData);
} else {
    renderSingleReport(reportData);
}

// ---- Single Report ----
function renderSingleReport(data) {
    document.getElementById('single-report').classList.remove('hidden');
    document.getElementById('bulk-report').classList.add('hidden');

    // Target
    document.getElementById('report-target').textContent = data.target || 'Unknown';

    // Determine risk level
    const riskLevel = data.riskLevel || data.risk_level || 'safe';
    const score = data.score || 0;

    // Set gauge class
    const gauge = document.getElementById('gauge');
    gauge.classList.remove('score-good', 'score-average', 'score-bad');
    gauge.classList.add(`score-${riskLevel}`);

    // Animate gauge
    animateGauge(score, riskLevel);

    // Render factors
    const factors = data.factors || data.details || [];
    renderFactors(factors);

    // Render recommendations
    const recommendations = data.recommendations || [];
    renderRecommendations(recommendations, riskLevel);
}

// Animate the circular gauge
function animateGauge(targetScore, riskLevel) {
    const gaugeEl = document.getElementById('gauge-fill');
    const scoreEl = document.getElementById('gauge-score');
    const labelEl = document.getElementById('gauge-label');

    const circumference = 2 * Math.PI * 85; // ~534
    const offset = circumference - (targetScore / 100) * circumference;

    // Labels
    const labels = {
        safe: 'SAFE',
        low: 'LOW RISK',
        medium: 'CAUTION',
        high: 'HIGH RISK',
        critical: 'CRITICAL'
    };

    // Animate number counting
    let currentScore = 0;
    const duration = 1500;
    const increment = targetScore / (duration / 16);

    const counter = setInterval(() => {
        currentScore += increment;
        if (currentScore >= targetScore) {
            currentScore = targetScore;
            clearInterval(counter);
        }
        scoreEl.textContent = Math.round(currentScore);
    }, 16);

    // Animate gauge fill
    setTimeout(() => {
        gaugeEl.style.strokeDashoffset = offset;
    }, 100);

    labelEl.textContent = labels[riskLevel] || 'UNKNOWN';
}

// Render risk factors
function renderFactors(factors) {
    const container = document.getElementById('factors-list');
    container.innerHTML = '';

    if (factors.length === 0) {
        container.innerHTML = `
      <div class="factor-item">
        <span class="factor-severity severity-safe">SAFE</span>
        <div class="factor-details">
          <div class="factor-name">No Threats Detected</div>
          <div class="factor-description">The scanned target appears to be safe. No phishing indicators were found.</div>
        </div>
      </div>
    `;
        return;
    }

    factors.forEach(factor => {
        const item = document.createElement('div');
        item.className = 'factor-item';

        const severityClass = `severity-${factor.severity || 'low'}`;
        const pointsClass = factor.points < 0 ? 'safe' : '';
        const pointsDisplay = factor.points > 0 ? `+${factor.points}` : factor.points;

        item.innerHTML = `
      <span class="factor-severity ${severityClass}">${(factor.severity || 'info').toUpperCase()}</span>
      <div class="factor-details">
        <div class="factor-name">${escapeHtml(factor.name)}</div>
        <div class="factor-description">${escapeHtml(factor.description)}</div>
      </div>
      <div class="factor-points ${pointsClass}">${pointsDisplay}</div>
    `;
        container.appendChild(item);
    });
}

// Render safety recommendations
function renderRecommendations(recommendations, riskLevel) {
    const section = document.getElementById('recommendations-section');
    const container = document.getElementById('recommendations-list');
    container.innerHTML = '';

    if (!recommendations || recommendations.length === 0) {
        section.classList.add('hidden');
        return;
    }

    section.classList.remove('hidden');

    recommendations.forEach(rec => {
        const item = document.createElement('div');
        item.className = 'recommendation-item';

        const priorityClass = `priority-${rec.priority || 'optional'}`;

        item.innerHTML = `
      <div class="recommendation-icon">${rec.icon || '💡'}</div>
      <div class="recommendation-content">
        <div class="recommendation-header">
          <span class="recommendation-title">${escapeHtml(rec.title)}</span>
          <span class="priority-badge ${priorityClass}">${(rec.priority || 'info').toUpperCase()}</span>
        </div>
        <div class="recommendation-description">${escapeHtml(rec.description)}</div>
      </div>
    `;
        container.appendChild(item);
    });
}

// ---- Bulk Report ----
function renderBulkReport(data) {
    document.getElementById('single-report').classList.add('hidden');
    document.getElementById('bulk-report').classList.remove('hidden');

    const container = document.getElementById('bulk-results-list');
    container.innerHTML = '';

    if (!data.results || data.results.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No results to display.</p></div>';
        return;
    }

    data.results.forEach(result => {
        const riskLevel = result.riskLevel || 'safe';
        const badgeClass = `badge-${riskLevel}`;
        const colorMap = { safe: 'var(--accent-green)', low: '#2196f3', medium: 'var(--accent-orange)', high: '#ff9800', critical: 'var(--danger)' };
        const scoreColor = colorMap[riskLevel] || 'var(--accent-green)';

        const card = document.createElement('div');
        card.className = 'glass-card';
        card.style.marginBottom = '16px';
        card.style.cursor = 'pointer';

        card.innerHTML = `
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <span class="history-badge ${badgeClass}">${riskLevel.toUpperCase()}</span>
        <span class="mono" style="flex: 1; font-size: 14px; color: var(--text-secondary); word-break: break-all;">${escapeHtml(result.target)}</span>
        <span style="font-size: 28px; font-weight: 900; color: ${scoreColor};">${result.score}</span>
      </div>
      <div style="margin-top: 12px;">
        ${result.factors.map(f => `
          <span style="display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 4px; font-size: 11px; background: rgba(255,255,255,0.05); color: var(--text-secondary);">
            ${escapeHtml(f.name)}
          </span>
        `).join('')}
      </div>
    `;

        card.addEventListener('click', () => {
            sessionStorage.setItem('lastReport', JSON.stringify({
                ...result,
                riskLevel: result.riskLevel
            }));
            renderSingleReport(result);
        });

        container.appendChild(card);
    });
}

// Download report as text
function downloadReport() {
    if (!reportData) return;

    const riskLevel = reportData.riskLevel || reportData.risk_level || 'unknown';
    const labels = { safe: 'SAFE', low: 'LOW RISK', medium: 'CAUTION', high: 'HIGH RISK', critical: 'CRITICAL' };

    let text = `╔══════════════════════════════════════════╗\n`;
    text += `║     PhishGuard — Threat Analysis Report   ║\n`;
    text += `╚══════════════════════════════════════════╝\n\n`;
    text += `Target: ${reportData.target || 'N/A'}\n`;
    text += `Type: ${reportData.type || 'N/A'}\n`;
    text += `Score: ${reportData.score}/100\n`;
    text += `Status: ${labels[riskLevel] || riskLevel.toUpperCase()}\n`;
    text += `Date: ${new Date().toLocaleString()}\n`;
    text += `\n${'─'.repeat(45)}\n\n`;

    text += `RISK FACTORS:\n\n`;
    const factors = reportData.factors || reportData.details || [];
    factors.forEach(f => {
        text += `  [${(f.severity || 'info').toUpperCase()}] ${f.name} (+${f.points})\n`;
        text += `    ${f.description}\n\n`;
    });

    text += `${'─'.repeat(45)}\n\n`;
    text += `SAFETY RECOMMENDATIONS:\n\n`;
    const recs = reportData.recommendations || [];
    recs.forEach(r => {
        text += `  ${r.icon || '•'} [${(r.priority || 'info').toUpperCase()}] ${r.title}\n`;
        text += `    ${r.description}\n\n`;
    });

    text += `\n${'─'.repeat(45)}\n`;
    text += `Generated by PhishGuard — Phishing Detection System\n`;

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-report-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// Utility: escape HTML
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
