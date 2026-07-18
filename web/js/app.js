// ============================================
// S.O.W.A Security - DNS Protection Dashboard
// Main Application JavaScript v2
// With Authentication Flow
// ============================================

const API_BASE = '';
let statsRefreshInterval = null;
let qlRefreshInterval = null;
let queriesChart = null;
let queryTypesChart = null;
let authToken = localStorage.getItem('sowa_token') || '';
let currentPage = 'dashboard';

// ==================== Auth ====================

// Server info cache
let serverInfo = null;

async function checkAuth() {
    try {
        const resp = await apiFetch('/api/auth/status');
        if (!resp.ok) throw new Error('Auth check failed');
        const data = await resp.json();

        if (!data.configured) {
            // First time setup - show wizard
            localStorage.removeItem('sowa_wizard_done');
            showLoginScreen('setup');
            return;
        }

        // If wizard was not completed, resume it
        if (!localStorage.getItem('sowa_wizard_done') && data.authenticated) {
            showLoginScreen('setup');
            const savedStep = parseInt(localStorage.getItem('sowa_wizard_step')) || 3;
            wizardNext(savedStep);
            loadServerInfo();
            return;
        }

        if (!data.authenticated) {
            // Show login form
            showLoginScreen('login');
            return;
        }

        // Authenticated - show app
        showApp();
    } catch (e) {
        // If auth endpoint doesn't exist yet (no auth configured), show app
        console.warn('Auth check:', e.message);
        showApp();
    }
}

function showLoginScreen(mode) {
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('appContainer').style.display = 'none';

    if (mode === 'setup') {
        document.getElementById('setupWizard').style.display = 'block';
        document.getElementById('loginForm').style.display = 'none';
        wizardNext(1);
        loadServerInfo();
    } else {
        document.getElementById('setupWizard').style.display = 'none';
        document.getElementById('loginForm').style.display = 'block';
    }
}

function showApp() {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('appContainer').style.display = 'flex';
    initApp();
}

// ==================== Setup Wizard ====================

let currentWizardStep = 1;

function wizardNext(step) {
    currentWizardStep = step;
    localStorage.setItem('sowa_wizard_step', step);

    // Update progress indicators
    document.querySelectorAll('.wizard-step').forEach(el => {
        const s = parseInt(el.dataset.step);
        el.classList.remove('active', 'done');
        if (s < step) el.classList.add('done');
        if (s === step) el.classList.add('active');
    });

    // Show active panel
    document.querySelectorAll('.wizard-panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById(`wizardStep${step}`);
    if (panel) panel.classList.add('active');
}

async function loadServerInfo() {
    try {
        const resp = await fetch(`${API_BASE}/api/system/info`);
        if (resp.ok) {
            serverInfo = await resp.json();
            const ip = serverInfo.ips?.[0] || '127.0.0.1';
            const dnsPort = serverInfo.dns_port || 53;
            const webPort = serverInfo.web_port || 8080;
            const webURL = `http://${ip}:${webPort}`;

            // Wizard info
            const wizardIP = document.getElementById('wizardServerIP');
            const wizardPort = document.getElementById('wizardDNSPort');
            const wizardWeb = document.getElementById('wizardWebURL');
            if (wizardIP) wizardIP.textContent = ip;
            if (wizardPort) wizardPort.textContent = dnsPort;
            if (wizardWeb) wizardWeb.textContent = webURL;

            // Guide DNS codes in wizard
            ['guideDNS1', 'guideDNS2', 'guideDNS3', 'guideDNS4'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.textContent = ip;
            });
        }
    } catch (e) {
        console.warn('Failed to load server info:', e);
    }
}

// Setup tabs in wizard
document.addEventListener('click', (e) => {
    const tab = e.target.closest('.setup-tab');
    if (!tab) return;
    const target = tab.dataset.target;

    tab.closest('.setup-tabs').querySelectorAll('.setup-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    const wizard = tab.closest('.wizard-card') || tab.closest('.wizard-panel');
    if (wizard) {
        wizard.querySelectorAll('.setup-guide').forEach(g => g.classList.remove('active'));
        const guide = document.getElementById(target);
        if (guide) guide.classList.add('active');
    }
});

// Password strength indicator
document.addEventListener('input', (e) => {
    if (e.target.id === 'setupPassword') {
        const val = e.target.value;
        const bar = document.getElementById('passwordStrength');
        if (!bar) return;
        let strength = 0;
        if (val.length >= 8) strength += 25;
        if (val.length >= 12) strength += 25;
        if (/[A-Z]/.test(val) && /[a-z]/.test(val)) strength += 25;
        if (/[0-9!@#$%^&*]/.test(val)) strength += 25;
        const colors = { 25: '#ff4466', 50: '#ffaa00', 75: '#00aaff', 100: '#00ff88' };
        bar.style.setProperty('--strength', strength + '%');
        bar.style.setProperty('--strength-color', colors[strength] || '#ff4466');
    }
});

function initLoginForms() {
    // Setup form (wizard step 2)
    document.getElementById('setupForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('setupPassword').value;
        const confirm = document.getElementById('setupPasswordConfirm').value;
        const errEl = document.getElementById('setupError');

        if (password.length < 8) {
            if (errEl) { errEl.textContent = 'Password must be at least 8 characters'; errEl.style.display = 'block'; errEl.classList.add('visible'); }
            return;
        }
        if (password !== confirm) {
            if (errEl) { errEl.textContent = 'Passwords do not match'; errEl.style.display = 'block'; errEl.classList.add('visible'); }
            return;
        }

        try {
            const resp = await fetch(`${API_BASE}/api/auth/setup`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: document.getElementById('setupUsername').value || 'admin',
                    password: password
                })
            });

            if (resp.ok) {
                // Now auto-login
                const loginResp = await fetch(`${API_BASE}/api/auth/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: document.getElementById('setupUsername').value || 'admin',
                        password: password
                    })
                });
                if (loginResp.ok) {
                    const data = await loginResp.json();
                    if (data.token) {
                        authToken = data.token;
                        localStorage.setItem('sowa_token', authToken);
                    }
                }
                // Move to DNS setup step
                wizardNext(3);
            } else {
                const err = await resp.json().catch(() => ({}));
                if (errEl) { errEl.textContent = err.error || 'Setup failed'; errEl.style.display = 'block'; errEl.classList.add('visible'); }
            }
        } catch (e) {
            if (errEl) { errEl.textContent = 'Connection error'; errEl.style.display = 'block'; errEl.classList.add('visible'); }
        }
    });

    // Wizard finish → open dashboard
    document.getElementById('wizardFinish')?.addEventListener('click', () => {
        localStorage.setItem('sowa_wizard_done', '1');
        localStorage.removeItem('sowa_wizard_step');
        showApp();
    });

    // Login form (returning users)
    document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const resp = await fetch(`${API_BASE}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (resp.ok) {
                const data = await resp.json();
                if (data.token) {
                    authToken = data.token;
                    localStorage.setItem('sowa_token', authToken);
                }
                localStorage.setItem('sowa_wizard_done', '1');
                localStorage.removeItem('sowa_wizard_step');
                hideLoginError();
                showApp();
            } else {
                showLoginError('Invalid username or password');
            }
        } catch (e) {
            showLoginError('Connection error');
        }
    });
}

function showLoginError(msg) {
    const el = document.getElementById('loginError');
    if (el) {
        el.textContent = msg;
        el.classList.add('visible');
        el.style.display = 'block';
    }
}

function hideLoginError() {
    const el = document.getElementById('loginError');
    if (el) {
        el.classList.remove('visible');
        el.style.display = 'none';
    }
}

async function logout() {
    try {
        await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch (e) { /* ignore */ }
    authToken = '';
    localStorage.removeItem('sowa_token');
    showLoginScreen('login');
    if (statsRefreshInterval) {
        clearInterval(statsRefreshInterval);
        statsRefreshInterval = null;
    }
    if (qlRefreshInterval) {
        clearInterval(qlRefreshInterval);
        qlRefreshInterval = null;
    }
    currentPage = 'dashboard';
}

// Wrapper for authenticated API calls
async function apiFetch(url, options = {}) {
    if (!options.headers) options.headers = {};
    if (authToken) {
        options.headers['Authorization'] = `Bearer ${authToken}`;
    }
    const resp = await fetch(`${API_BASE}${url}`, options);
    if (resp.status === 401) {
        // Token expired or invalid
        authToken = '';
        localStorage.removeItem('sowa_token');
        showLoginScreen('login');
        throw new Error('Unauthorized');
    }
    return resp;
}

// ==================== Init ====================

document.addEventListener('DOMContentLoaded', () => {
    initLoginForms();
    checkAuth();
});

let appInitialized = false;

function initApp() {
    if (appInitialized) {
        // Re-login after logout: reload dashboard and restart auto-refresh
        loadDashboard();
        startAutoRefresh();
        loadConfig();
        return;
    }
    appInitialized = true;
    initNavigation();
    initForms();
    initTheme();
    initKeyboardShortcuts();
    initBackupRestore();
    loadDashboard();
    startAutoRefresh();
    loadConfig();
}

// ==================== Navigation ====================

function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('sidebar');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            const page = item.dataset.page;
            currentPage = page;

            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            const pageEl = document.getElementById(`page-${page}`);
            if (pageEl) pageEl.classList.add('active');

            document.getElementById('pageTitle').textContent = item.querySelector('span').textContent;
            sidebar.classList.remove('open');
            loadPageData(page);

            // Manage query log auto-refresh
            startQueryLogRefresh(page === 'querylog');
        });
    });

    menuToggle?.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });

    // Logout
    document.getElementById('logoutBtn')?.addEventListener('click', (e) => {
        e.preventDefault();
        logout();
    });

    // Quick domain test
    document.getElementById('quickTestBtn')?.addEventListener('click', () => {
        const domain = document.getElementById('quickTestDomain')?.value?.trim();
        if (domain) testDomain(domain);
    });

    document.getElementById('quickTestDomain')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const domain = e.target.value.trim();
            if (domain) testDomain(domain);
        }
    });
}

function loadPageData(page) {
    switch (page) {
        case 'dashboard': loadDashboard(); break;
        case 'blocklists': loadBlocklists(); break;
        case 'querylog': loadQueryLog(); break;
        case 'clients': loadClients(); break;
        case 'dhcp': loadDHCPLeases(); break;
        case 'safesearch': loadSafeSearch(); break;
        case 'dns': loadDNSSettings(); break;
        case 'settings': loadGeneralSettings(); break;
        case 'access': loadAccessSettings(); break;
        case 'encryption': loadEncryptionSettings(); break;
        case 'filters': loadCustomRules(); break;
        case 'guide': loadSetupGuide(); break;
        case 'blocked-services': loadBlockedServices(); break;
        case 'dns-rewrites': loadDNSRewrites(); break;
        case 'sessions': loadSessions(); break;
        case 'health': loadSystemHealth(); break;
        case 'parental': loadParentalControls(); break;
    }
}

// ==================== Setup Guide Page ====================

async function loadSetupGuide() {
    try {
        const resp = await apiFetch('/api/system/info');
        if (!resp.ok) return;
        const data = await resp.json();
        serverInfo = data;

        const ip = data.ips?.[0] || '127.0.0.1';
        const el = document.getElementById('guideIP');
        if (el) el.textContent = ip;

        const portEl = document.getElementById('guideDNSPort');
        if (portEl) portEl.textContent = data.dns_port || 53;

        const webEl = document.getElementById('guideWebPanel');
        if (webEl) webEl.textContent = `http://${ip}:${data.web_port || 8080}`;

        // Fill all .guide-ip-code elements
        document.querySelectorAll('.guide-ip-code').forEach(el => {
            el.textContent = ip;
        });
    } catch (e) {
        console.warn('Failed to load guide info:', e);
    }
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    }).catch(() => {
        // Fallback
        const input = document.createElement('input');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showToast('Copied!', 'success');
    });
}

// ==================== Dashboard ====================

async function loadDashboard() {
    try {
        const [statsResp, statusResp] = await Promise.all([
            apiFetch('/api/stats'),
            apiFetch('/api/status')
        ]);

        if (statsResp.ok) {
            const data = await statsResp.json();

            animateNumber('totalQueries', data.total_queries || 0);
            animateNumber('blockedQueries', data.blocked_queries || 0);
            animateNumber('cachedQueries', data.cached_queries || 0);
            animateNumber('rateLimitedQueries', data.rate_limited_queries || 0);

            const percentage = data.total_queries > 0
                ? ((data.blocked_queries / data.total_queries) * 100).toFixed(1)
                : 0;
            document.getElementById('blockedPercentage').textContent = percentage + '%';
            document.getElementById('avgResponseTime').textContent = (data.average_time_ms || 0).toFixed(1) + 'ms';

            updateCharts(data);
            updateTopTables(data);
        }

        if (statusResp.ok) {
            const status = await statusResp.json();
            const cacheEl = document.getElementById('cacheSize');
            if (cacheEl) cacheEl.textContent = formatNumber(status.cache_size || 0);

            const uptimeEl = document.getElementById('serverUptime');
            if (uptimeEl) uptimeEl.textContent = formatUptime(status.uptime || 0);

            animateNumber('filteringRules', status.filtering_rules || 0);

            // Update protection status indicator
            const indicator = document.getElementById('serverStatus');
            const dot = indicator?.querySelector('.status-dot');
            const label = indicator?.querySelector('span:last-child');
            if (indicator && dot && label) {
                if (status.protection) {
                    dot.className = 'status-dot online';
                    label.textContent = 'Protection Active';
                    indicator.classList.remove('disabled');
                } else {
                    dot.className = 'status-dot offline';
                    label.textContent = 'Protection Disabled';
                    indicator.classList.add('disabled');
                }
            }
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading dashboard:', e);
    }
}

function animateNumber(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.textContent.replace(/[^0-9]/g, '')) || 0;
    if (current === target) {
        el.textContent = formatNumber(target);
        return;
    }
    const diff = target - current;
    const steps = 20;
    const stepVal = diff / steps;
    let step = 0;

    function tick() {
        step++;
        const val = step >= steps ? target : Math.round(current + stepVal * step);
        el.textContent = formatNumber(val);
        if (step < steps) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

// Reads the current theme's colors from CSS variables so charts
// always match the active (dark/light) theme.
function chartTheme() {
    const styles = getComputedStyle(document.documentElement);
    const v = (name, fallback) => (styles.getPropertyValue(name).trim() || fallback);
    return {
        accent: v('--accent-primary', '#00d4ff'),
        danger: v('--danger', '#ff5c7a'),
        text: v('--text-secondary', '#97a3bd'),
        muted: v('--text-muted', '#5d6a88'),
        grid: hexToRgba(v('--border-color', '#1b2540'), 0.5),
        tooltipBg: v('--bg-elevated', '#121a2c'),
        tooltipBorder: v('--border-strong', '#26335a'),
        textPrimary: v('--text-primary', '#e8ecf6'),
    };
}

function hexToRgba(hex, alpha) {
    const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex.trim());
    if (!m) return hex;
    return `rgba(${parseInt(m[1], 16)}, ${parseInt(m[2], 16)}, ${parseInt(m[3], 16)}, ${alpha})`;
}

function chartTooltipOptions(t) {
    return {
        backgroundColor: t.tooltipBg,
        titleColor: t.textPrimary,
        bodyColor: t.text,
        borderColor: t.tooltipBorder,
        borderWidth: 1,
        cornerRadius: 8,
        padding: 12,
    };
}

// Re-applies theme colors to existing charts (used on theme toggle)
function restyleCharts() {
    const t = chartTheme();
    [queriesChart, queryTypesChart].forEach(chart => {
        if (!chart) return;
        const legend = chart.options.plugins?.legend;
        if (legend?.labels) legend.labels.color = t.text;
        if (chart.options.plugins?.tooltip) {
            Object.assign(chart.options.plugins.tooltip, chartTooltipOptions(t));
        }
        if (chart.options.scales) {
            Object.values(chart.options.scales).forEach(scale => {
                if (scale.ticks) scale.ticks.color = t.muted;
                if (scale.grid) scale.grid.color = t.grid;
            });
        }
        chart.update('none');
    });
    if (queriesChart) {
        const [total, blocked] = queriesChart.data.datasets;
        total.borderColor = t.accent;
        total.backgroundColor = hexToRgba(t.accent, 0.08);
        total.pointHoverBackgroundColor = t.accent;
        blocked.borderColor = t.danger;
        blocked.backgroundColor = hexToRgba(t.danger, 0.08);
        blocked.pointHoverBackgroundColor = t.danger;
        queriesChart.update('none');
    }
}

function updateCharts(data) {
    const t = chartTheme();
    const ctx1 = document.getElementById('queriesChart')?.getContext('2d');
    if (ctx1) {
        const hours = Array.from({ length: 24 }, (_, i) => `${i}:00`);
        const hourlyQueries = data.hourly_queries || new Array(24).fill(0);
        const hourlyBlocked = data.hourly_blocked || new Array(24).fill(0);

        if (queriesChart) {
            // Update data in-place to preserve legend toggle state
            queriesChart.data.datasets[0].data = hourlyQueries;
            queriesChart.data.datasets[1].data = hourlyBlocked;
            queriesChart.update('none'); // 'none' = no animation on update
        } else {
            queriesChart = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: hours,
                    datasets: [{
                        label: 'Total Queries',
                        data: hourlyQueries,
                        borderColor: t.accent,
                        backgroundColor: hexToRgba(t.accent, 0.08),
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        pointHoverBackgroundColor: t.accent,
                    }, {
                        label: 'Blocked',
                        data: hourlyBlocked,
                        borderColor: t.danger,
                        backgroundColor: hexToRgba(t.danger, 0.08),
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        pointHoverBackgroundColor: t.danger,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { intersect: false, mode: 'index' },
                    plugins: {
                        legend: { labels: { color: t.text, font: { size: 11 }, usePointStyle: true, pointStyle: 'circle' } },
                        tooltip: chartTooltipOptions(t)
                    },
                    scales: {
                        x: { ticks: { color: t.muted, font: { size: 10 } }, grid: { color: t.grid } },
                        y: { ticks: { color: t.muted, font: { size: 10 } }, grid: { color: t.grid }, beginAtZero: true }
                    }
                }
            });
        }
    }

    const ctx2 = document.getElementById('queryTypesChart')?.getContext('2d');
    if (ctx2) {
        const queryTypes = data.query_types || {};
        const labels = Object.keys(queryTypes);
        const values = Object.values(queryTypes);

        if (queryTypesChart) {
            // Update data in-place to preserve legend toggle state
            queryTypesChart.data.labels = labels.length > 0 ? labels : ['No Data'];
            queryTypesChart.data.datasets[0].data = values.length > 0 ? values : [1];
            queryTypesChart.update('none');
        } else {
            queryTypesChart = new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels: labels.length > 0 ? labels : ['No Data'],
                    datasets: [{
                        data: values.length > 0 ? values : [1],
                        backgroundColor: [
                            '#00d4ff', '#7c5cff', '#ff5c7a', '#2ee6a8',
                            '#ffb224', '#ff66aa', '#38bdf8', '#a3e635'
                        ],
                        borderWidth: 0,
                        hoverOffset: 8,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '68%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: t.text, font: { size: 11 }, padding: 12, usePointStyle: true, pointStyle: 'circle' }
                        },
                        tooltip: chartTooltipOptions(t)
                    }
                }
            });
        }
    }
}

function updateTopTables(data) {
    fillTopTable('topQueriedTable', data.top_queried_domains || {});
    fillTopTable('topBlockedTable', data.top_blocked_domains || {});
    fillTopTable('topClientsTable', data.top_clients || {});
}

function fillTopTable(tableId, dataMap) {
    const tbody = document.querySelector(`#${tableId} tbody`);
    if (!tbody) return;

    const sorted = Object.entries(dataMap)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    if (sorted.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-state"><i class="fas fa-inbox"></i> No data yet</td></tr>';
        return;
    }

    const isBlocked = tableId === 'topBlockedTable';
    const isClients = tableId === 'topClientsTable';
    tbody.innerHTML = sorted.map(([key, val]) => {
        let actionCell = '';
        if (isClients) {
            // Click to view client's queries
            actionCell = `<button class="btn btn-xs" onclick="filterQueryLogByClient('${jsArg(key)}')" title="View queries"><i class="fas fa-eye"></i></button>`;
        } else if (isBlocked) {
            actionCell = `<button class="btn btn-xs btn-success" onclick="quickAllowDomain('${jsArg(key)}')" title="Allow"><i class="fas fa-check"></i></button>`;
        } else {
            actionCell = `<button class="btn btn-xs btn-danger" onclick="quickBlockDomain('${jsArg(key)}')" title="Block"><i class="fas fa-ban"></i></button>`;
        }
        let nameCell;
        if (isClients) {
            nameCell = `<td>
                <span class="client-link" onclick="filterQueryLogByClient('${jsArg(key)}')" title="Click to view queries">
                    <i class="fas fa-desktop" style="color:var(--accent-primary);margin-right:6px;"></i>${escapeHtml(key)}
                </span>
            </td>`;
        } else {
            nameCell = `<td class="ql-domain-cell">
                <span class="domain-link" onclick="testDomain('${jsArg(key)}')" title="Test this domain">${escapeHtml(key)}</span>
                <span class="ql-whois-icon" data-domain="${escapeHtml(key)}" onmouseenter="showWhoisTooltip(event, this)" onmouseleave="hideWhoisTooltip()" title="WHOIS info">
                    <i class="fas fa-info-circle"></i>
                </span>
            </td>`;
        }
        return `<tr>
            ${nameCell}
            <td>${formatNumber(val)}</td>
            <td>${actionCell}</td>
        </tr>`;
    }).join('');
}

// Navigate to Query Log filtered by client IP
function filterQueryLogByClient(clientIP) {
    navigateToPage('querylog');
    // Wait for page to render, then set search filter
    setTimeout(() => {
        const searchInput = document.getElementById('queryLogSearch');
        if (searchInput) {
            searchInput.value = clientIP;
            qlCurrentPage = 0;
            loadQueryLog();
        }
    }, 100);
}

// ==================== Domain Test ====================

async function testDomain(domain) {
    try {
        const resp = await apiFetch(`/api/test?domain=${encodeURIComponent(domain)}`);
        if (!resp.ok) {
            showToast('Failed to test domain', 'error');
            return;
        }
        const data = await resp.json();
        const blocked = data.blocked;
        const reason = data.reason || '';

        // Show toast for quick test
        if (blocked) {
            showToast(`${domain} is BLOCKED (${reason})`, 'error');
        } else {
            showToast(`${domain} is ALLOWED`, 'success');
        }

        // Also update the test result panel if visible
        const resultEl = document.getElementById('testDomainResult');
        if (resultEl) {
            resultEl.style.display = 'block';
            resultEl.className = `test-result ${blocked ? 'blocked' : 'allowed'}`;
            resultEl.innerHTML = blocked
                ? `<i class="fas fa-ban"></i> <strong>${escapeHtml(domain)}</strong> is <strong>BLOCKED</strong> — ${escapeHtml(reason)}`
                : `<i class="fas fa-check-circle"></i> <strong>${escapeHtml(domain)}</strong> is <strong>ALLOWED</strong>`;
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error testing domain', 'error');
    }
}

// ==================== Config Loading ====================

async function loadConfig() {
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();
        applyConfigToUI(cfg);
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading config:', e);
    }
}

function applyConfigToUI(cfg) {
    // General settings
    setChecked('filteringEnabled', cfg.filtering?.enabled);
    setChecked('safeBrowsing', cfg.filtering?.safe_browsing);

    // Safe Search
    const ss = cfg.filtering?.safe_search || {};
    setChecked('safeSearchEnabled', ss.enabled);
    setChecked('ssGoogle', ss.google);
    setChecked('ssBing', ss.bing);
    setChecked('ssYahoo', ss.yahoo);
    setChecked('ssYandex', ss.yandex);
    setChecked('ssDuckDuckGo', ss.duckduckgo);
    setChecked('ssYouTube', ss.youtube);
    setChecked('ssEcosia', ss.ecosia);
    setChecked('ssStartPage', ss.startpage);
    setChecked('ssBrave', ss.brave);

    // DNS settings
    setValue('dnsBindHost', cfg.dns?.bind_host);
    setValue('dnsPort', cfg.dns?.port);
    setChecked('enableIPv6', cfg.dns?.enable_ipv6);
    setValue('upstreamServers', (cfg.dns?.upstreams || []).join('\n'));
    setValue('bootstrapDns', (cfg.dns?.bootstrap_dns || []).join('\n'));
    setChecked('cacheEnabled', cfg.dns?.cache_enabled);
    setValue('cacheSizeSetting', cfg.dns?.cache_size);
    setValue('cacheTTLMin', cfg.dns?.cache_ttl_min);
    setValue('cacheTTLMax', cfg.dns?.cache_ttl_max);
    setValue('rateLimit', cfg.dns?.rate_limit);

    // Encryption
    setChecked('dohEnabled', cfg.dns?.doh_enabled);
    setValue('dohPort', cfg.dns?.doh_port);
    setChecked('dotEnabled', cfg.dns?.dot_enabled);
    setValue('dotPort', cfg.dns?.dot_port);
    setValue('tlsCert', cfg.dns?.doh_cert || cfg.dns?.dot_cert);
    setValue('tlsKey', cfg.dns?.doh_key || cfg.dns?.dot_key);

    // DHCP
    setChecked('dhcpEnabled', cfg.dhcp?.enabled);
    setValue('dhcpInterface', cfg.dhcp?.interface_name);
    setValue('dhcpGateway', cfg.dhcp?.gateway_ip);
    setValue('dhcpSubnet', cfg.dhcp?.subnet_mask);
    setValue('dhcpRangeStart', cfg.dhcp?.range_start);
    setValue('dhcpRangeEnd', cfg.dhcp?.range_end);
    setValue('dhcpLease', cfg.dhcp?.lease_duration);

    // Access
    setValue('allowedClients', (cfg.access?.allowed_clients || []).join('\n'));
    setValue('disallowedClients', (cfg.access?.disallowed_clients || []).join('\n'));
    setValue('blockedHosts', (cfg.access?.blocked_hosts || []).join('\n'));

    // Custom rules
    setValue('customRules', (cfg.filtering?.custom_rules || []).join('\n'));

    // Auto-update interval
    const auEl = document.getElementById('autoUpdateInterval');
    if (auEl) auEl.value = String(cfg.filtering?.auto_update_interval ?? 24);

    // DNS Server Addresses info box
    loadDNSAddresses();
}

async function loadDNSAddresses() {
    try {
        if (!serverInfo) {
            const resp = await apiFetch('/api/system/info');
            if (resp.ok) serverInfo = await resp.json();
        }
        if (serverInfo) {
            const ip = serverInfo.ips?.[0] || '127.0.0.1';
            const dnsPort = serverInfo.dns_port || 53;
            const webPort = serverInfo.web_port || 8080;

            const ipv4El = document.getElementById('dnsServerIPv4');
            const portEl = document.getElementById('dnsServerPort');
            const webEl = document.getElementById('dnsServerWeb');

            if (ipv4El) ipv4El.textContent = ip;
            if (portEl) portEl.textContent = dnsPort;
            if (webEl) webEl.textContent = `http://${ip}:${webPort}`;

            // If there are multiple IPs, show them all
            const grid = document.getElementById('dnsAddressesGrid');
            if (grid && serverInfo.ips && serverInfo.ips.length > 1) {
                // Add additional IPs
                serverInfo.ips.slice(1).forEach(extraIp => {
                    if (!document.getElementById('dnsAddr-' + extraIp)) {
                        const item = document.createElement('div');
                        item.className = 'dns-addr-item';
                        item.id = 'dnsAddr-' + extraIp;
                        item.innerHTML = `<span class="dns-addr-label">IPv4 Address</span><span class="dns-addr-value">${escapeHtml(extraIp)}</span>`;
                        grid.appendChild(item);
                    }
                });
            }
        }
    } catch (e) {
        console.warn('Failed to load DNS addresses:', e);
    }
}

// ==================== Form Handlers ====================

function initForms() {
    // General Settings
    document.getElementById('generalSettingsForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            filtering: {
                enabled: getChecked('filteringEnabled'),
                safe_browsing: getChecked('safeBrowsing')
            }
        });
    });

    // Change Password
    document.getElementById('changePasswordForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const current = document.getElementById('currentPassword').value;
        const newPass = document.getElementById('newPassword').value;
        if (!current || !newPass) {
            showToast('Please fill in all fields', 'error');
            return;
        }
        try {
            const resp = await apiFetch('/api/auth/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_password: current, new_password: newPass })
            });
            if (resp.ok) {
                showToast('Password changed successfully. Please login again.', 'success');
                document.getElementById('currentPassword').value = '';
                document.getElementById('newPassword').value = '';
                setTimeout(() => logout(), 2000);
            } else {
                const err = await resp.json().catch(() => ({}));
                showToast(err.error || 'Failed to change password', 'error');
            }
        } catch (e) {
            if (e.message !== 'Unauthorized') showToast('Error changing password', 'error');
        }
    });

    // DNS Settings
    document.getElementById('dnsSettingsForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            dns: {
                bind_host: getValue('dnsBindHost'),
                port: parseInt(getValue('dnsPort')),
                enable_ipv6: getChecked('enableIPv6'),
                upstreams: getLines('upstreamServers'),
                bootstrap_dns: getLines('bootstrapDns'),
                cache_enabled: getChecked('cacheEnabled'),
                cache_size: parseInt(getValue('cacheSizeSetting')),
                cache_ttl_min: parseInt(getValue('cacheTTLMin')),
                cache_ttl_max: parseInt(getValue('cacheTTLMax')),
                rate_limit: parseInt(getValue('rateLimit'))
            }
        });
    });

    // DHCP
    document.getElementById('dhcpForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            dhcp: {
                enabled: getChecked('dhcpEnabled'),
                interface_name: getValue('dhcpInterface'),
                gateway_ip: getValue('dhcpGateway'),
                subnet_mask: getValue('dhcpSubnet'),
                range_start: getValue('dhcpRangeStart'),
                range_end: getValue('dhcpRangeEnd'),
                lease_duration: parseInt(getValue('dhcpLease'))
            }
        });
    });

    // Encryption
    document.getElementById('encryptionForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            dns: {
                doh_enabled: getChecked('dohEnabled'),
                doh_port: parseInt(getValue('dohPort')),
                dot_enabled: getChecked('dotEnabled'),
                dot_port: parseInt(getValue('dotPort')),
                doh_cert: getValue('tlsCert'),
                doh_key: getValue('tlsKey'),
                dot_cert: getValue('tlsCert'),
                dot_key: getValue('tlsKey')
            }
        });
    });

    // Access Control
    document.getElementById('accessForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            access: {
                allowed_clients: getLines('allowedClients'),
                disallowed_clients: getLines('disallowedClients'),
                blocked_hosts: getLines('blockedHosts')
            }
        });
    });

    // Safe Search
    document.getElementById('saveSafeSearch')?.addEventListener('click', async () => {
        await saveConfig({
            filtering: {
                safe_search: {
                    enabled: getChecked('safeSearchEnabled'),
                    google: getChecked('ssGoogle'),
                    bing: getChecked('ssBing'),
                    yahoo: getChecked('ssYahoo'),
                    yandex: getChecked('ssYandex'),
                    duckduckgo: getChecked('ssDuckDuckGo'),
                    youtube: getChecked('ssYouTube'),
                    ecosia: getChecked('ssEcosia'),
                    startpage: getChecked('ssStartPage'),
                    brave: getChecked('ssBrave')
                }
            }
        });
    });

    // Custom Rules
    document.getElementById('saveCustomRules')?.addEventListener('click', async () => {
        await saveConfig({
            filtering: {
                custom_rules: getLines('customRules')
            }
        });
    });

    // Test Domain button on filters page
    document.getElementById('testDomainBtn')?.addEventListener('click', () => {
        const domain = document.getElementById('testDomainInput')?.value?.trim();
        if (domain) testDomain(domain);
    });

    document.getElementById('testDomainInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const domain = e.target.value.trim();
            if (domain) testDomain(domain);
        }
    });

    // Blocklist actions
    document.getElementById('addBlocklist')?.addEventListener('click', showAddBlocklistModal);
    document.getElementById('addWhitelist')?.addEventListener('click', showAddWhitelistModal);
    document.getElementById('refreshLists')?.addEventListener('click', refreshAllLists);

    // Auto-update interval
    document.getElementById('autoUpdateInterval')?.addEventListener('change', async (e) => {
        const hours = parseInt(e.target.value);
        await saveConfig({ filtering: { auto_update_interval: hours } });
    });

    // Clear cache
    document.getElementById('clearCache')?.addEventListener('click', async () => {
        try {
            const resp = await apiFetch('/api/cache/clear', { method: 'POST' });
            if (resp.ok) showToast('DNS cache cleared', 'success');
            else showToast('Failed to clear cache', 'error');
        } catch (e) {
            if (e.message !== 'Unauthorized') showToast('Error clearing cache', 'error');
        }
    });

    // Dashboard stats reset
    document.getElementById('resetStats')?.addEventListener('click', async () => {
        if (!confirm('Reset all dashboard statistics (counters, charts, top tables)?\nQuery Log will NOT be affected.')) return;
        try {
            const resp = await apiFetch('/api/stats/reset', { method: 'POST' });
            if (resp.ok) {
                showToast('Dashboard statistics reset', 'success');
                loadDashboard();
            } else showToast('Failed to reset statistics', 'error');
        } catch (e) {
            if (e.message !== 'Unauthorized') showToast('Error resetting statistics', 'error');
        }
    });

    // Test upstream DNS
    document.getElementById('testUpstreams')?.addEventListener('click', testUpstreamServers);

    // Dashboard upstream ping
    document.getElementById('pingUpstreams')?.addEventListener('click', pingUpstreamsDashboard);

    // WHOIS lookup
    document.getElementById('whoisBtn')?.addEventListener('click', () => {
        const domain = document.getElementById('whoisDomain')?.value?.trim();
        if (domain) lookupWhois(domain);
    });
    document.getElementById('whoisDomain')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const domain = e.target.value.trim();
            if (domain) lookupWhois(domain);
        }
    });

    // Query log filter, search, pagination, export
    document.getElementById('queryLogFilter')?.addEventListener('change', () => { qlCurrentPage = 0; loadQueryLog(); });
    document.getElementById('refreshQueryLog')?.addEventListener('click', loadQueryLog);
    document.getElementById('queryLogSearch')?.addEventListener('input', debounce(() => { qlCurrentPage = 0; loadQueryLog(); }, 400));
    document.getElementById('qlPrevPage')?.addEventListener('click', () => { if (qlCurrentPage > 0) { qlCurrentPage--; loadQueryLog(); } });
    document.getElementById('qlNextPage')?.addEventListener('click', () => { qlCurrentPage++; loadQueryLog(); });
    document.getElementById('exportQueryLog')?.addEventListener('click', async () => {
        try {
            const resp = await apiFetch('/api/querylog/export?format=csv');
            if (!resp.ok) throw new Error('Export failed');
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `querylog-${new Date().toISOString().slice(0, 10)}.csv`;
            a.click();
            URL.revokeObjectURL(url);
            showToast('Query log exported', 'success');
        } catch (e) {
            if (e.message !== 'Unauthorized') showToast('Failed to export query log', 'error');
        }
    });
    document.getElementById('clearQueryLog')?.addEventListener('click', clearQueryLog);

    // Add client
    document.getElementById('addClient')?.addEventListener('click', showAddClientModal);

    // Toggle protection
    document.getElementById('toggleProtection')?.addEventListener('click', toggleProtection);

    // Blocked Services
    document.getElementById('saveBlockedServices')?.addEventListener('click', saveBlockedServices);

    // DNS Rewrites
    document.getElementById('addDNSRewrite')?.addEventListener('click', showAddDNSRewriteModal);

    // Modal close
    document.getElementById('modalClose')?.addEventListener('click', closeModal);
    document.getElementById('modal')?.addEventListener('click', (e) => {
        if (e.target.id === 'modal') closeModal();
    });
}

// ==================== API Calls ====================

async function saveConfig(partial) {
    try {
        const resp = await apiFetch('/api/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(partial)
        });
        if (resp.ok) {
            showToast('Settings saved successfully', 'success');
            loadConfig();
        } else {
            showToast('Failed to save settings', 'error');
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error saving settings: ' + e.message, 'error');
    }
}

async function toggleProtection() {
    try {
        const resp = await apiFetch('/api/protection/toggle', { method: 'POST' });
        if (resp.ok) {
            const data = await resp.json();
            const indicator = document.getElementById('serverStatus');
            const dot = indicator?.querySelector('.status-dot');
            const label = indicator?.querySelector('span:last-child');
            if (data.enabled) {
                dot.className = 'status-dot online';
                label.textContent = 'Protection Active';
                indicator.classList.remove('disabled');
                showToast('Protection enabled', 'success');
            } else {
                dot.className = 'status-dot offline';
                label.textContent = 'Protection Disabled';
                indicator.classList.add('disabled');
                showToast('Protection disabled', 'warning');
            }
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error toggling protection', 'error');
    }
}

// ==================== Blocklists ====================

async function loadBlocklists() {
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();

        renderBlocklists(cfg.filtering?.blocklists || [], 'blocklistsList');
        renderBlocklists(cfg.filtering?.whitelists || [], 'whitelistsList');

        const statsResp = await apiFetch('/api/filtering/stats');
        if (statsResp.ok) {
            const stats = await statsResp.json();
            const el = document.getElementById('filterStats');
            if (el) {
                el.innerHTML = `
                    <div class="filter-stat"><strong>${formatNumber(stats.total_rules || 0)}</strong> blocked domains</div>
                    <div class="filter-stat"><strong>${stats.blocklists || 0}</strong> blocklists</div>
                    <div class="filter-stat"><strong>${stats.whitelists || 0}</strong> whitelists</div>
                    <div class="filter-stat">Last update: <strong>${stats.last_update || 'Never'}</strong></div>
                `;
            }
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading blocklists:', e);
    }
}

function renderBlocklists(lists, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (lists.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-list"></i><p>No lists configured</p></div>';
        return;
    }

    container.innerHTML = lists.map((list, index) => `
        <div class="blocklist-item">
            <div class="blocklist-info">
                <div class="name">${escapeHtml(list.name)}${list.default ? ' <span class="badge active" style="font-size:0.7em;margin-left:6px;">Default</span>' : ''}</div>
                <div class="url" title="${escapeHtml(list.url)}">${escapeHtml(list.url)}</div>
            </div>
            <div class="blocklist-actions">
                <label class="switch">
                    <input type="checkbox" ${list.enabled ? 'checked' : ''} 
                        onchange="toggleBlocklist('${containerId}', ${index}, this.checked)">
                    <span class="slider"></span>
                </label>
                ${list.default ? '' : `<button class="btn btn-sm btn-danger" onclick="removeBlocklist('${containerId}', ${index})">
                    <i class="fas fa-trash"></i>
                </button>`}
            </div>
        </div>
    `).join('');
}

async function toggleBlocklist(type, index, enabled) {
    const listType = type === 'blocklistsList' ? 'blocklist' : 'whitelist';
    try {
        const resp = await apiFetch(`/api/filtering/${listType}/${index}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (resp.ok) showToast(`List ${enabled ? 'enabled' : 'disabled'}`, 'success');
        else showToast('Failed to toggle list', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error toggling list', 'error');
    }
}

async function removeBlocklist(type, index) {
    if (!confirm('Are you sure you want to remove this list?')) return;
    const listType = type === 'blocklistsList' ? 'blocklist' : 'whitelist';
    try {
        const resp = await apiFetch(`/api/filtering/${listType}/${index}`, { method: 'DELETE' });
        if (resp.ok) {
            showToast('List removed', 'success');
            loadBlocklists();
        } else showToast('Failed to remove list', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error removing list', 'error');
    }
}

async function refreshAllLists() {
    const btn = document.getElementById('refreshLists');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
    }
    showToast('Downloading and updating all lists... This may take a moment.', 'info');
    try {
        const resp = await apiFetch('/api/filtering/refresh', { method: 'POST' });
        if (resp.ok) {
            const data = await resp.json();
            const rules = data.stats?.total_rules || 0;
            if (data.status === 'ok') {
                showToast(`All lists updated successfully! ${rules} rules loaded.`, 'success');
            } else {
                showToast(`Lists updated with errors. ${rules} rules loaded.`, 'warning');
            }
            loadBlocklists();
        } else showToast('Failed to update lists', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error updating lists', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-download"></i> Update All Lists Now';
        }
    }
}

// ==================== Query Log ====================

let qlCurrentPage = 0;
const qlPageSize = 50;
let qlTotalEntries = 0;

async function loadQueryLog() {
    try {
        const filter = getValue('queryLogFilter') || 'all';
        const search = getValue('queryLogSearch') || '';
        const offset = qlCurrentPage * qlPageSize;
        const filterParam = filter === 'all' ? '' : `&filter=${filter}`;
        const searchParam = search ? `&search=${encodeURIComponent(search)}` : '';

        const resp = await apiFetch(`/api/querylog?limit=${qlPageSize}&offset=${offset}${filterParam}${searchParam}`);
        if (!resp.ok) return;
        const data = await resp.json();

        qlTotalEntries = data.total || 0;
        const totalPages = Math.max(1, Math.ceil(qlTotalEntries / qlPageSize));

        const tbody = document.querySelector('#queryLogTable tbody');
        if (!tbody) return;

        const entries = data.entries || [];
        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><i class="fas fa-clipboard-list"></i> No queries logged yet</td></tr>';
        } else {
            tbody.innerHTML = entries.map(entry => {
                const rowClass = entry.blocked ? 'blocked-row' : 'allowed-row';
                const status = entry.blocked
                    ? `<span style="color:var(--danger)"><i class="fas fa-ban"></i> Blocked (${escapeHtml(entry.reason)})</span>`
                    : `<span style="color:var(--success)"><i class="fas fa-check"></i> ${escapeHtml(entry.reason)}</span>`;
                const dt = new Date(entry.timestamp);
                const timeAgo = formatRelativeTime(dt);
                const fullTime = dt.toLocaleString();
                const actionBtn = entry.blocked
                    ? `<button class="btn btn-xs btn-success" onclick="quickAllowDomain('${jsArg(entry.domain)}')" title="Allow this domain"><i class="fas fa-check"></i></button>`
                    : `<button class="btn btn-xs btn-danger" onclick="quickBlockDomain('${jsArg(entry.domain)}')" title="Block this domain"><i class="fas fa-ban"></i></button>`;
                return `<tr class="${rowClass}">
                    <td><span class="ql-time" title="${escapeHtml(fullTime)}">${timeAgo}</span></td>
                    <td class="ql-domain-cell">
                        <span class="ql-domain-name" title="Click to copy" onclick="copyText('${jsArg(entry.domain)}')">${escapeHtml(entry.domain)}</span>
                        <span class="ql-whois-icon" data-domain="${escapeHtml(entry.domain)}" onmouseenter="showWhoisTooltip(event, this)" onmouseleave="hideWhoisTooltip()" title="WHOIS info">
                            <i class="fas fa-info-circle"></i>
                        </span>
                    </td>
                    <td><span class="ql-type-badge">${escapeHtml(entry.type)}</span></td>
                    <td><span class="ql-client" title="Click to filter by this client" onclick="filterQueryLogByClient('${jsArg(entry.client_ip)}')">${escapeHtml(entry.client_ip)}</span></td>
                    <td>${status}</td>
                    <td>${escapeHtml(entry.duration)}</td>
                    <td>${actionBtn}</td>
                </tr>`;
            }).join('');
        }

        // Update pagination
        const pageInfo = document.getElementById('qlPageInfo');
        if (pageInfo) pageInfo.textContent = `Page ${qlCurrentPage + 1} of ${totalPages} (${qlTotalEntries} entries)`;

        const prevBtn = document.getElementById('qlPrevPage');
        const nextBtn = document.getElementById('qlNextPage');
        if (prevBtn) prevBtn.disabled = qlCurrentPage === 0;
        if (nextBtn) nextBtn.disabled = qlCurrentPage >= totalPages - 1;
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading query log:', e);
    }
}

// ==================== Modals ====================

async function clearQueryLog() {
    if (!confirm('Are you sure you want to clear the entire query log? This cannot be undone.')) return;
    try {
        const resp = await apiFetch('/api/querylog/clear', { method: 'POST' });
        if (resp.ok) {
            showToast('Query log cleared', 'success');
            qlCurrentPage = 0;
            loadQueryLog();
        } else showToast('Failed to clear query log', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error clearing query log', 'error');
    }
}

function showAddBlocklistModal() {
    showModal('Add Blocklist', `
        <div class="form-group">
            <label>List Name</label>
            <input type="text" id="newListName" placeholder="My Custom Blocklist">
        </div>
        <div class="form-group">
            <label>URL</label>
            <input type="text" id="newListURL" placeholder="https://example.com/blocklist.txt">
        </div>
        <button class="btn btn-primary" onclick="addList('blocklist')">
            <i class="fas fa-plus"></i> Add Blocklist
        </button>
    `);
}

function showAddWhitelistModal() {
    showModal('Add Whitelist', `
        <div class="form-group">
            <label>List Name</label>
            <input type="text" id="newListName" placeholder="My Whitelist">
        </div>
        <div class="form-group">
            <label>URL</label>
            <input type="text" id="newListURL" placeholder="https://example.com/whitelist.txt">
        </div>
        <button class="btn btn-primary" onclick="addList('whitelist')">
            <i class="fas fa-plus"></i> Add Whitelist
        </button>
    `);
}

async function addList(type) {
    const name = getValue('newListName');
    const url = getValue('newListURL');
    if (!name || !url) {
        showToast('Please fill in all fields', 'error');
        return;
    }

    try {
        const resp = await apiFetch(`/api/filtering/${type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, url, enabled: true, type: 'url' })
        });
        if (resp.ok) {
            showToast(`${type} added successfully`, 'success');
            closeModal();
            loadBlocklists();
        } else showToast(`Failed to add ${type}`, 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast(`Error adding ${type}`, 'error');
    }
}

function showAddClientModal() {
    showModal('Add Client Device', `
        <div class="form-group">
            <label>Client Name</label>
            <input type="text" id="newClientName" placeholder="Living Room TV">
        </div>
        <div class="form-group">
            <label>IDs (IPs, MACs - one per line)</label>
            <textarea id="newClientIDs" rows="3" placeholder="192.168.1.100&#10;AA:BB:CC:DD:EE:FF"></textarea>
        </div>
        <div class="form-group">
            <label>Filtering Enabled</label>
            <label class="switch"><input type="checkbox" id="newClientFiltering" checked><span class="slider"></span></label>
        </div>
        <div class="form-group">
            <label>Safe Search</label>
            <label class="switch"><input type="checkbox" id="newClientSafeSearch" checked><span class="slider"></span></label>
        </div>
        <div class="form-group">
            <label>Parental Control</label>
            <label class="switch"><input type="checkbox" id="newClientParental"><span class="slider"></span></label>
        </div>
        <button class="btn btn-primary" onclick="addClient()">
            <i class="fas fa-plus"></i> Add Client
        </button>
    `);
}

async function addClient() {
    const name = getValue('newClientName');
    const ids = getLines('newClientIDs');
    if (!name || ids.length === 0) {
        showToast('Please fill in all required fields', 'error');
        return;
    }

    try {
        const resp = await apiFetch('/api/clients', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                ids,
                filtering_enabled: getChecked('newClientFiltering'),
                safe_search: getChecked('newClientSafeSearch'),
                parental_control: getChecked('newClientParental'),
                use_global_config: true
            })
        });
        if (resp.ok) {
            showToast('Client added successfully', 'success');
            closeModal();
            loadClients();
        } else showToast('Failed to add client', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error adding client', 'error');
    }
}

// ==================== Load Functions ====================

async function loadClients() {
    try {
        // Load configured clients
        const resp = await apiFetch('/api/clients');
        if (!resp.ok) return;
        const clients = await resp.json();

        // Load active clients from stats
        const statsResp = await apiFetch('/api/stats');
        let activeClients = {};
        if (statsResp.ok) {
            const stats = await statsResp.json();
            activeClients = stats.top_clients || {};
        }

        const container = document.getElementById('clientsList');
        if (!container) return;

        let html = '';

        // Show active (auto-detected) clients from DNS queries
        const activeEntries = Object.entries(activeClients).sort((a, b) => b[1] - a[1]);
        if (activeEntries.length > 0) {
            html += '<div class="section-label"><i class="fas fa-wifi" style="margin-right:6px;color:var(--success);"></i>Active Clients (Auto-detected)</div>';
            html += activeEntries.map(([ip, queries]) => `
                <div class="client-item">
                    <div class="client-info">
                        <div class="name"><i class="fas fa-desktop" style="color:var(--success);margin-right:8px;"></i>${escapeHtml(ip)}</div>
                        <div class="ids">${formatNumber(queries)} queries</div>
                    </div>
                    <span class="badge active">Connected</span>
                </div>
            `).join('');
        }

        // Show configured (manual) clients
        if (clients && clients.length > 0) {
            html += '<div class="section-label"><i class="fas fa-cog" style="margin-right:6px;"></i>Configured Clients</div>';
            html += clients.map((client, i) => `
                <div class="client-item">
                    <div class="client-info">
                        <div class="name"><i class="fas fa-laptop"></i> ${escapeHtml(client.name)}</div>
                        <div class="ids">${(client.ids || []).map(id => escapeHtml(id)).join(', ')}</div>
                        <div class="client-badges">
                            <span class="badge ${client.filtering_enabled ? 'active' : 'inactive'}">Filtering</span>
                            <span class="badge ${client.safe_search ? 'active' : 'inactive'}">Safe Search</span>
                            <span class="badge ${client.parental_control ? 'active' : 'inactive'}">Parental</span>
                        </div>
                    </div>
                    <button class="btn btn-sm btn-danger" onclick="removeClient(${i})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `).join('');
        }

        if (!html) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-laptop"></i><p>No clients detected yet. Connect a device using this DNS server to see it here.</p></div>';
        } else {
            container.innerHTML = html;
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading clients:', e);
    }
}

async function removeClient(index) {
    if (!confirm('Remove this client?')) return;
    try {
        const resp = await apiFetch(`/api/clients/${index}`, { method: 'DELETE' });
        if (resp.ok) {
            showToast('Client removed', 'success');
            loadClients();
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error removing client', 'error');
    }
}

async function loadDHCPLeases() {
    try {
        const resp = await apiFetch('/api/dhcp/leases');
        if (!resp.ok) return;
        const leases = await resp.json();

        const tbody = document.querySelector('#dhcpLeasesTable tbody');
        if (!tbody) return;

        if (!leases || leases.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><i class="fas fa-network-wired"></i> No active leases</td></tr>';
            return;
        }

        tbody.innerHTML = leases.map(lease => `
            <tr>
                <td><code>${escapeHtml(lease.mac)}</code></td>
                <td>${escapeHtml(lease.ip)}</td>
                <td>${escapeHtml(lease.hostname || '-')}</td>
                <td>${lease.static ? '<span class="badge static">Static</span>' : '-'}</td>
                <td>${lease.static ? 'Never' : new Date(lease.expires_at).toLocaleString()}</td>
            </tr>
        `).join('');
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading DHCP leases:', e);
    }
}

function loadSafeSearch() { loadConfig(); }
function loadGeneralSettings() { loadConfig(); }
function loadDNSSettings() { loadConfig(); }
function loadAccessSettings() { loadConfig(); }
function loadEncryptionSettings() { loadConfig(); }

async function loadCustomRules() {
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();
        setValue('customRules', (cfg.filtering?.custom_rules || []).join('\n'));
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading custom rules:', e);
    }
}

// ==================== Blocked Services ====================

const serviceIcons = {
    facebook: 'fab fa-facebook', instagram: 'fab fa-instagram', twitter: 'fab fa-twitter',
    youtube: 'fab fa-youtube', tiktok: 'fab fa-tiktok', snapchat: 'fab fa-snapchat',
    discord: 'fab fa-discord', telegram: 'fab fa-telegram', whatsapp: 'fab fa-whatsapp',
    twitch: 'fab fa-twitch', netflix: 'fas fa-film', spotify: 'fab fa-spotify',
    reddit: 'fab fa-reddit', pinterest: 'fab fa-pinterest', steam: 'fab fa-steam',
    epicgames: 'fas fa-gamepad', amazon: 'fab fa-amazon', ebay: 'fas fa-shopping-cart',
    roblox: 'fas fa-cube', vk: 'fab fa-vk', tumblr: 'fab fa-tumblr',
    linkedin: 'fab fa-linkedin', skype: 'fab fa-skype'
};

async function loadBlockedServices() {
    try {
        const [blockedResp, availResp] = await Promise.all([
            apiFetch('/api/blocked-services'),
            apiFetch('/api/blocked-services/available')
        ]);

        let blocked = [];
        let available = [];

        if (blockedResp.ok) {
            const data = await blockedResp.json();
            blocked = data.blocked || [];
        }
        if (availResp.ok) {
            const data = await availResp.json();
            available = data.services || [];
        }

        const grid = document.getElementById('servicesGrid');
        if (!grid) return;

        // Sort alphabetically
        available.sort();

        grid.innerHTML = available.map(svc => {
            const isBlocked = blocked.includes(svc);
            const icon = serviceIcons[svc] || 'fas fa-globe';
            const name = svc.charAt(0).toUpperCase() + svc.slice(1);
            return `
                <div class="service-item ${isBlocked ? 'blocked' : ''}" data-service="${escapeHtml(svc)}">
                    <div class="service-name">
                        <i class="${icon}"></i>
                        <span>${name}</span>
                    </div>
                    <label class="switch">
                        <input type="checkbox" ${isBlocked ? 'checked' : ''} data-svc="${escapeHtml(svc)}">
                        <span class="slider"></span>
                    </label>
                </div>
            `;
        }).join('');

        // Update visual state on toggle
        grid.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            cb.addEventListener('change', () => {
                cb.closest('.service-item').classList.toggle('blocked', cb.checked);
            });
        });
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading blocked services:', e);
    }
}

async function saveBlockedServices() {
    const checkboxes = document.querySelectorAll('#servicesGrid input[data-svc]');
    const services = [];
    checkboxes.forEach(cb => {
        if (cb.checked) services.push(cb.dataset.svc);
    });

    try {
        const resp = await apiFetch('/api/blocked-services', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ services })
        });
        if (resp.ok) showToast(`${services.length} services blocked`, 'success');
        else showToast('Failed to save blocked services', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error saving blocked services', 'error');
    }
}

// ==================== DNS Rewrites ====================

async function loadDNSRewrites() {
    try {
        const resp = await apiFetch('/api/dns-rewrites');
        if (!resp.ok) return;
        const data = await resp.json();
        const rewrites = data.rewrites || [];

        const tbody = document.querySelector('#dnsRewritesTable tbody');
        if (!tbody) return;

        if (rewrites.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="empty-state"><i class="fas fa-exchange-alt"></i> No DNS rewrites configured</td></tr>';
            return;
        }

        tbody.innerHTML = rewrites.map((rw, i) => `
            <tr>
                <td><code>${escapeHtml(rw.domain)}</code></td>
                <td><code>${escapeHtml(rw.answer)}</code></td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="removeDNSRewrite(${i})">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading DNS rewrites:', e);
    }
}

function showAddDNSRewriteModal() {
    showModal('Add DNS Rewrite', `
        <div class="form-group">
            <label>Domain</label>
            <input type="text" id="rwDomain" placeholder="example.com">
        </div>
        <div class="form-group">
            <label>Answer (IP or CNAME target)</label>
            <input type="text" id="rwAnswer" placeholder="192.168.1.10 or other.example.com">
        </div>
        <button class="btn btn-primary" onclick="addDNSRewrite()">
            <i class="fas fa-plus"></i> Add Rewrite
        </button>
    `);
}

async function addDNSRewrite() {
    const domain = getValue('rwDomain');
    const answer = getValue('rwAnswer');
    if (!domain || !answer) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    try {
        const resp = await apiFetch('/api/dns-rewrites', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, answer })
        });
        if (resp.ok) {
            showToast('DNS rewrite added', 'success');
            closeModal();
            loadDNSRewrites();
        } else showToast('Failed to add rewrite', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error adding rewrite', 'error');
    }
}

async function removeDNSRewrite(index) {
    if (!confirm('Remove this DNS rewrite?')) return;
    try {
        const resp = await apiFetch(`/api/dns-rewrites?index=${index}`, { method: 'DELETE' });
        if (resp.ok) {
            showToast('DNS rewrite removed', 'success');
            loadDNSRewrites();
        } else showToast('Failed to remove rewrite', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error removing rewrite', 'error');
    }
}

// ==================== Utilities ====================

function showModal(title, body) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = body;
    document.getElementById('modal').classList.add('active');
}

function closeModal() {
    document.getElementById('modal').classList.remove('active');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = { success: 'check-circle', error: 'exclamation-circle', info: 'info-circle', warning: 'exclamation-triangle' };
    toast.innerHTML = `<i class="fas fa-${icons[type] || 'info-circle'}"></i> ${escapeHtml(message)}`;

    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 350);
    }, 3500);
}

function startAutoRefresh() {
    if (statsRefreshInterval) clearInterval(statsRefreshInterval);
    statsRefreshInterval = setInterval(loadDashboard, 10000);
}

function startQueryLogRefresh(active) {
    if (qlRefreshInterval) {
        clearInterval(qlRefreshInterval);
        qlRefreshInterval = null;
    }
    if (active) {
        qlRefreshInterval = setInterval(loadQueryLog, 5000);
    }
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function escapeHtml(str) {
    if (!str) return '';
    // Escapes quotes as well so values are safe inside HTML attributes
    // (e.g. onclick="...('${escapeHtml(x)}')") — DNS query names can
    // contain arbitrary characters and must never break out of markup.
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/`/g, '&#96;');
}

// Makes a value safe to embed inside single quotes of an inline
// event handler: onclick="fn('${jsArg(value)}')". Escapes for the JS
// string first, then for the HTML attribute.
function jsArg(str) {
    return escapeHtml(String(str ?? '')
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'"));
}

function getValue(id) {
    const el = document.getElementById(id);
    return el ? el.value : '';
}

function setValue(id, value) {
    const el = document.getElementById(id);
    if (el && value !== undefined && value !== null) el.value = value;
}

function getChecked(id) {
    const el = document.getElementById(id);
    return el ? el.checked : false;
}

function setChecked(id, value) {
    const el = document.getElementById(id);
    if (el) el.checked = !!value;
}

function getLines(id) {
    return getValue(id).split('\n').map(l => l.trim()).filter(l => l);
}

function formatUptime(seconds) {
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
    if (seconds < 86400) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        return h + 'h ' + m + 'm';
    }
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    return d + 'd ' + h + 'h';
}

function debounce(fn, delay) {
    let timer;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}

// ==================== Relative Time Formatting ====================

function formatRelativeTime(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDays = Math.floor(diffHr / 24);

    if (diffSec < 5) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ${diffMin % 60}m ago`;
    if (diffDays === 1) return 'yesterday';
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' + date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

// ==================== WHOIS Tooltip (Query Log) ====================

const whoisCache = {};
let activeWhoisTooltip = null;
let whoisTooltipTimeout = null;

async function showWhoisTooltip(event, element) {
    const domain = element.dataset.domain;
    if (!domain) return;

    // Extract base domain (remove subdomains for WHOIS)
    const parts = domain.split('.');
    const baseDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain;

    // Clear any pending hide
    if (whoisTooltipTimeout) {
        clearTimeout(whoisTooltipTimeout);
        whoisTooltipTimeout = null;
    }

    // Remove existing tooltip
    removeWhoisTooltip();

    // Create tooltip
    const tooltip = document.createElement('div');
    tooltip.className = 'whois-tooltip';
    tooltip.innerHTML = '<div class="whois-tooltip-loading"><i class="fas fa-spinner fa-spin"></i> Loading WHOIS...</div>';

    // Position tooltip
    const rect = element.getBoundingClientRect();
    tooltip.style.position = 'fixed';
    tooltip.style.left = (rect.left + rect.width / 2) + 'px';
    tooltip.style.top = (rect.bottom + 8) + 'px';

    document.body.appendChild(tooltip);
    activeWhoisTooltip = tooltip;

    // Keep tooltip visible when hovering over it
    tooltip.addEventListener('mouseenter', () => {
        if (whoisTooltipTimeout) {
            clearTimeout(whoisTooltipTimeout);
            whoisTooltipTimeout = null;
        }
    });
    tooltip.addEventListener('mouseleave', () => {
        hideWhoisTooltip();
    });

    // Reposition if out of viewport
    requestAnimationFrame(() => {
        const tooltipRect = tooltip.getBoundingClientRect();
        if (tooltipRect.right > window.innerWidth - 10) {
            tooltip.style.left = (window.innerWidth - tooltipRect.width - 10) + 'px';
        }
        if (tooltipRect.bottom > window.innerHeight - 10) {
            tooltip.style.top = (rect.top - tooltipRect.height - 8) + 'px';
        }
    });

    // Fetch or use cache
    if (whoisCache[baseDomain]) {
        renderWhoisTooltip(tooltip, whoisCache[baseDomain]);
        return;
    }

    try {
        const resp = await apiFetch(`/api/whois?domain=${encodeURIComponent(baseDomain)}`);
        if (!resp.ok) throw new Error('WHOIS lookup failed');
        const data = await resp.json();
        whoisCache[baseDomain] = data;

        // Tooltip might have been removed already
        if (activeWhoisTooltip === tooltip) {
            renderWhoisTooltip(tooltip, data);
        }
    } catch (e) {
        if (activeWhoisTooltip === tooltip) {
            tooltip.innerHTML = '<div class="whois-tooltip-error"><i class="fas fa-exclamation-triangle"></i> WHOIS lookup failed</div>';
        }
    }
}

function renderWhoisTooltip(tooltip, data) {
    if (data.error) {
        tooltip.innerHTML = `<div class="whois-tooltip-error"><i class="fas fa-exclamation-triangle"></i> ${escapeHtml(data.error)}</div>`;
        return;
    }

    const rows = [];
    if (data.domain) rows.push(['Domain', data.domain]);
    if (data.registrar) rows.push(['Registrar', data.registrar]);
    if (data.organization) rows.push(['Organization', data.organization]);
    if (data.country) rows.push(['Country', data.country]);
    if (data.created) rows.push(['Created', data.created]);
    if (data.expires) rows.push(['Expires', data.expires]);
    if (data.dnssec) rows.push(['DNSSEC', data.dnssec]);
    if (data.name_servers?.length) rows.push(['NS', data.name_servers.slice(0, 3).join(', ')]);

    if (rows.length === 0) {
        tooltip.innerHTML = '<div class="whois-tooltip-error">No WHOIS data available</div>';
        return;
    }

    tooltip.innerHTML = `
        <div class="whois-tooltip-header"><i class="fas fa-globe-americas"></i> WHOIS Info</div>
        <div class="whois-tooltip-body">
            ${rows.map(([label, value]) => `
                <div class="whois-tooltip-row">
                    <span class="whois-tooltip-label">${escapeHtml(label)}</span>
                    <span class="whois-tooltip-value">${escapeHtml(value)}</span>
                </div>
            `).join('')}
        </div>
        <div class="whois-tooltip-footer">
            <a href="#" onclick="event.preventDefault();document.getElementById('whoisDomain').value='${jsArg(data.domain || '')}';navigateToPage('filters');lookupWhois('${jsArg(data.domain || '')}');">
                <i class="fas fa-external-link-alt"></i> Full WHOIS
            </a>
        </div>
    `;
}

function hideWhoisTooltip() {
    whoisTooltipTimeout = setTimeout(() => {
        removeWhoisTooltip();
    }, 200);
}

function removeWhoisTooltip() {
    if (activeWhoisTooltip) {
        activeWhoisTooltip.remove();
        activeWhoisTooltip = null;
    }
}

// ==================== Theme Toggle ====================

function initTheme() {
    const saved = localStorage.getItem('sowa_theme') || 'dark';
    applyTheme(saved);

    document.getElementById('themeToggle')?.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        applyTheme(next);
        localStorage.setItem('sowa_theme', next);
    });
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
    }
    if (label) {
        label.textContent = theme === 'dark' ? 'Night Mode' : 'Light Mode';
    }
    // Charts must pick up the new theme's colors
    restyleCharts();
}

// ==================== Keyboard Shortcuts ====================

function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Don't trigger shortcuts when typing in inputs
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
        if (e.ctrlKey || e.altKey || e.metaKey) return;

        const modal = document.getElementById('shortcutsModal');
        switch (e.key.toLowerCase()) {
            case 'd': navigateToPage('dashboard'); break;
            case 'q': navigateToPage('querylog'); break;
            case 's': navigateToPage('settings'); break;
            case 'f': navigateToPage('filters'); break;
            case 'h': navigateToPage('health'); break;
            case 'g': navigateToPage('guide'); break;
            case 'b': navigateToPage('blocklists'); break;
            case 'c': navigateToPage('parental'); break;
            case 'p':
                e.preventDefault();
                toggleProtection();
                break;
            case '?':
                if (modal) modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
                break;
            case 'escape':
                if (modal) modal.style.display = 'none';
                break;
        }
    });
}

function navigateToPage(page) {
    const navItem = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (navItem) navItem.click();
}

// ==================== Sessions Management ====================

async function loadSessions() {
    const container = document.getElementById('sessionsList');
    if (!container) return;

    try {
        const resp = await apiFetch('/api/auth/sessions');
        if (!resp.ok) throw new Error('Failed to load sessions');
        const data = await resp.json();
        const sessions = data.sessions || [];
        const currentToken = authToken;

        if (sessions.length === 0) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-key"></i><p>No active sessions</p></div>';
            return;
        }

        container.innerHTML = sessions.map(s => {
            const isCurrent = s.token === currentToken;
            const created = s.created_at ? new Date(s.created_at).toLocaleString() : 'Unknown';
            const expires = s.expires_at ? new Date(s.expires_at).toLocaleString() : 'Unknown';
            return `
                <div class="session-item${isCurrent ? ' current' : ''}">
                    <div class="session-info">
                        <div class="session-ip"><i class="fas fa-globe"></i> ${escapeHtml(s.ip || 'Unknown')}</div>
                        <div class="session-agent"><i class="fas fa-desktop"></i> ${escapeHtml(s.user_agent || 'Unknown')}</div>
                        <div class="session-time"><i class="fas fa-clock"></i> Created: ${created}</div>
                        <div class="session-time"><i class="fas fa-hourglass-half"></i> Expires: ${expires}</div>
                        ${isCurrent ? '<span class="badge badge-success">Current Session</span>' : ''}
                    </div>
                    ${!isCurrent ? `<button class="btn btn-danger btn-sm" onclick="revokeSession('${jsArg(s.token)}')"><i class="fas fa-times"></i> Revoke</button>` : ''}
                </div>
            `;
        }).join('');
    } catch (e) {
        container.innerHTML = '<div class="error-message">Failed to load sessions</div>';
    }
}

async function revokeSession(token) {
    try {
        const resp = await apiFetch('/api/auth/sessions/revoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });
        if (resp.ok) {
            showToast('Session revoked', 'success');
            loadSessions();
        } else {
            showToast('Failed to revoke session', 'error');
        }
    } catch (e) {
        showToast('Failed to revoke session', 'error');
    }
}

// ==================== System Health ====================

async function loadSystemHealth() {
    loadHealthMetrics();
    loadUpstreamStats();
}

async function loadHealthMetrics() {
    const grid = document.getElementById('healthGrid');
    if (!grid) return;

    try {
        const resp = await apiFetch('/api/health');
        if (!resp.ok) throw new Error('Failed to load health');
        const h = await resp.json();

        const mem = h.memory || {};
        const memMB = (mem.alloc_mb || 0).toFixed(1);
        const sysMB = (mem.sys_mb || 0).toFixed(1);
        const numGC = mem.num_gc || 0;

        grid.innerHTML = `
            <div class="health-item">
                <div class="health-value">${escapeHtml(h.uptime_human || formatUptime(h.uptime || 0))}</div>
                <div class="health-label">Uptime</div>
            </div>
            <div class="health-item">
                <div class="health-value">${memMB} MB</div>
                <div class="health-label">Memory Used</div>
            </div>
            <div class="health-item">
                <div class="health-value">${sysMB} MB</div>
                <div class="health-label">System Memory</div>
            </div>
            <div class="health-item">
                <div class="health-value">${h.goroutines || 0}</div>
                <div class="health-label">Goroutines</div>
            </div>
            <div class="health-item">
                <div class="health-value">${numGC}</div>
                <div class="health-label">GC Cycles</div>
            </div>
            <div class="health-item">
                <div class="health-value">${escapeHtml(h.go_version || 'N/A')}</div>
                <div class="health-label">Go Version</div>
            </div>
            <div class="health-item">
                <div class="health-value">${escapeHtml((h.os || '') + ' / ' + (h.arch || ''))}</div>
                <div class="health-label">Platform</div>
            </div>
            <div class="health-item">
                <div class="health-value">${h.dns_running ? '<span style="color:var(--accent-color)">Running</span>' : '<span style="color:var(--danger-color)">Stopped</span>'}</div>
                <div class="health-label">DNS Server</div>
            </div>
            <div class="health-item">
                <div class="health-value">${h.dhcp_running ? '<span style="color:var(--accent-color)">Running</span>' : '<span style="color:var(--text-muted)">Disabled</span>'}</div>
                <div class="health-label">DHCP Server</div>
            </div>
            <div class="health-item">
                <div class="health-value">${h.protection ? '<span style="color:var(--accent-color)">Active</span>' : '<span style="color:var(--danger-color)">Disabled</span>'}</div>
                <div class="health-label">Protection</div>
            </div>
            <div class="health-item">
                <div class="health-value">${h.cache_size || 0}</div>
                <div class="health-label">Cache Entries</div>
            </div>
            <div class="health-item">
                <div class="health-value">${h.auto_update_hrs || 0}h</div>
                <div class="health-label">Auto-Update Interval</div>
            </div>
            <div class="health-item">
                <div class="health-value">v${escapeHtml(h.version || '?')}</div>
                <div class="health-label">Version</div>
            </div>
        `;
    } catch (e) {
        grid.innerHTML = '<div class="error-message">Failed to load health metrics</div>';
    }
}

async function loadUpstreamStats() {
    const container = document.getElementById('upstreamStats');
    if (!container) return;

    try {
        const resp = await apiFetch('/api/upstream/stats');
        if (!resp.ok) throw new Error('Failed to load upstream stats');
        const data = await resp.json();
        const servers = data.servers || {};
        const keys = Object.keys(servers);

        if (keys.length === 0) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-server"></i><p>No upstream data yet. Make some DNS queries first.</p></div>';
            return;
        }

        container.innerHTML = keys.map(name => {
            const s = servers[name];
            const avgMs = typeof s.avg_ms === 'number' ? s.avg_ms.toFixed(1) : parseFloat(s.avg_ms || 0).toFixed(1);
            const lastMs = typeof s.last_ms === 'number' ? s.last_ms.toFixed(1) : parseFloat(s.last_ms || 0).toFixed(1);
            return `
                <div class="upstream-item">
                    <div class="upstream-name"><i class="fas fa-server"></i> ${escapeHtml(name)}</div>
                    <div class="upstream-stats">
                        <span class="latency"><i class="fas fa-tachometer-alt"></i> Avg: ${avgMs}ms</span>
                        <span class="latency"><i class="fas fa-clock"></i> Last: ${lastMs}ms</span>
                        <span><i class="fas fa-exchange-alt"></i> ${s.count} queries</span>
                        <span class="errors"><i class="fas fa-exclamation-triangle"></i> ${s.errors} errors</span>
                    </div>
                </div>
            `;
        }).join('');
    } catch (e) {
        container.innerHTML = '<div class="error-message">Failed to load upstream stats</div>';
    }
}

// ==================== Upstream DNS Test ====================

async function testUpstreamServers() {
    const btn = document.getElementById('testUpstreams');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
    }

    try {
        const resp = await apiFetch('/api/upstream/test', { method: 'POST' });
        if (!resp.ok) throw new Error('Test failed');
        const data = await resp.json();
        const results = data.results || [];

        let html = `<div class="test-results-header"><strong>Test Domain:</strong> ${escapeHtml(data.test_domain)}</div>`;
        html += results.map(r => {
            const statusClass = r.status === 'ok' ? 'success' : 'error';
            const statusIcon = r.status === 'ok' ? 'check-circle' : 'times-circle';
            return `
                <div class="upstream-test-result ${statusClass}">
                    <div class="upstream-name"><i class="fas fa-server"></i> ${escapeHtml(r.server)}</div>
                    <div class="upstream-test-info">
                        <span class="status"><i class="fas fa-${statusIcon}"></i> ${r.status.toUpperCase()}</span>
                        <span class="latency"><i class="fas fa-tachometer-alt"></i> ${r.latency_ms.toFixed(1)}ms</span>
                        ${r.error ? `<span class="error-msg">${escapeHtml(r.error)}</span>` : ''}
                    </div>
                </div>
            `;
        }).join('');

        const container = document.getElementById('upstreamTestResults');
        if (container) {
            container.innerHTML = html;
            container.style.display = 'block';
        } else {
            showModal('Upstream DNS Test Results', html);
        }

        showToast('Upstream test completed', 'success');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error testing upstreams', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-vial"></i> Test Upstream Servers';
        }
    }
}

async function pingUpstreamsDashboard() {
    const btn = document.getElementById('pingUpstreams');
    const container = document.getElementById('upstreamLatencyList');
    if (!container) return;

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
    }

    try {
        const resp = await apiFetch('/api/upstream/test', { method: 'POST' });
        if (!resp.ok) throw new Error('Test failed');
        const data = await resp.json();
        const results = data.results || [];

        container.innerHTML = results.map(r => {
            const isOk = r.status === 'ok';
            const latColor = r.latency_ms < 50 ? 'var(--success)' : r.latency_ms < 150 ? 'var(--warning, #ffaa00)' : 'var(--danger)';
            return `
                <div class="upstream-latency-item">
                    <div class="upstream-latency-server">
                        <i class="fas fa-${isOk ? 'check-circle' : 'times-circle'}" style="color:${isOk ? 'var(--success)' : 'var(--danger)'}"></i>
                        <span>${escapeHtml(r.server)}</span>
                    </div>
                    <div class="upstream-latency-bar-wrap">
                        <div class="upstream-latency-bar" style="width:${Math.min(r.latency_ms / 3, 100)}%;background:${latColor}"></div>
                    </div>
                    <span class="upstream-latency-ms" style="color:${latColor}">${r.latency_ms.toFixed(1)}ms</span>
                </div>
            `;
        }).join('');
    } catch (e) {
        if (e.message !== 'Unauthorized') {
            container.innerHTML = '<p class="text-muted">Failed to test upstream servers</p>';
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync-alt"></i> Test';
        }
    }
}

// ==================== WHOIS Lookup ====================

async function lookupWhois(domain) {
    const resultEl = document.getElementById('whoisResult');
    if (resultEl) {
        resultEl.style.display = 'block';
        resultEl.innerHTML = '<div class="loading-placeholder"><i class="fas fa-spinner fa-spin"></i> Looking up WHOIS data...</div>';
    }

    try {
        const resp = await apiFetch(`/api/whois?domain=${encodeURIComponent(domain)}`);
        if (!resp.ok) throw new Error('WHOIS lookup failed');
        const data = await resp.json();

        if (data.error) {
            if (resultEl) resultEl.innerHTML = `<div class="error-message"><i class="fas fa-exclamation-triangle"></i> ${escapeHtml(data.error)}</div>`;
            return;
        }

        let html = `<div class="whois-info">`;
        html += `<h4><i class="fas fa-globe"></i> ${escapeHtml(data.domain || domain)}</h4>`;
        
        const fields = [
            { key: 'registrar', label: 'Registrar', icon: 'fa-building' },
            { key: 'registrar_url', label: 'Registrar URL', icon: 'fa-link' },
            { key: 'organization', label: 'Organization', icon: 'fa-users' },
            { key: 'country', label: 'Country', icon: 'fa-flag' },
            { key: 'created', label: 'Created', icon: 'fa-calendar-plus' },
            { key: 'updated', label: 'Updated', icon: 'fa-calendar-check' },
            { key: 'expires', label: 'Expires', icon: 'fa-calendar-times' },
            { key: 'dnssec', label: 'DNSSEC', icon: 'fa-shield-alt' },
        ];

        for (const f of fields) {
            if (data[f.key]) {
                html += `<div class="whois-field"><i class="fas ${f.icon}"></i><span class="whois-label">${f.label}:</span><span class="whois-value">${escapeHtml(data[f.key])}</span></div>`;
            }
        }

        if (data.name_servers && data.name_servers.length > 0) {
            html += `<div class="whois-field"><i class="fas fa-server"></i><span class="whois-label">Name Servers:</span><span class="whois-value">${data.name_servers.map(ns => escapeHtml(ns)).join(', ')}</span></div>`;
        }

        if (data.status && data.status.length > 0) {
            html += `<div class="whois-field"><i class="fas fa-info-circle"></i><span class="whois-label">Status:</span><span class="whois-value">${data.status.map(s => `<span class="badge active" style="font-size:0.75em;margin:2px;">${escapeHtml(s)}</span>`).join(' ')}</span></div>`;
        }

        html += `</div>`;

        // Add raw data toggle
        if (data.raw) {
            html += `<details class="whois-raw"><summary><i class="fas fa-code"></i> Raw WHOIS Data</summary><pre>${escapeHtml(data.raw)}</pre></details>`;
        }

        if (resultEl) resultEl.innerHTML = html;
    } catch (e) {
        if (resultEl) resultEl.innerHTML = '<div class="error-message">Failed to perform WHOIS lookup</div>';
        if (e.message !== 'Unauthorized') showToast('Error performing WHOIS lookup', 'error');
    }
}

// ==================== Parental Controls ====================

async function loadParentalControls() {
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();
        const p = cfg.filtering?.parental || {};

        setChecked('parentalEnabled', p.enabled);
        setChecked('parentalForceSafeSearch', p.force_safe_search);
        setChecked('parentalBlockAdult', p.block_adult);
        setChecked('parentalBlockGambling', p.block_gambling);
        setChecked('parentalBlockDating', p.block_dating);
        setChecked('parentalBlockDrugs', p.block_drugs);
        setChecked('parentalBlockSocialMedia', p.block_social_media);
        setChecked('parentalBlockGaming', p.block_gaming);
        setChecked('parentalBlockVideo', p.block_video);
        setChecked('parentalScheduleEnabled', p.schedule_enabled);

        const fromEl = document.getElementById('parentalScheduleFrom');
        const toEl = document.getElementById('parentalScheduleTo');
        const weFromEl = document.getElementById('parentalWeekendFrom');
        const weToEl = document.getElementById('parentalWeekendTo');
        if (fromEl) fromEl.value = p.schedule_from || '07:00';
        if (toEl) toEl.value = p.schedule_to || '21:00';
        if (weFromEl) weFromEl.value = p.weekend_from || '08:00';
        if (weToEl) weToEl.value = p.weekend_to || '23:00';
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading parental controls:', e);
    }

    // Attach save handler once
    const saveBtn = document.getElementById('saveParentalControls');
    if (saveBtn && !saveBtn._bound) {
        saveBtn._bound = true;
        saveBtn.addEventListener('click', saveParentalControls);
    }
}

async function saveParentalControls() {
    await saveConfig({
        filtering: {
            parental: {
                enabled: getChecked('parentalEnabled'),
                force_safe_search: getChecked('parentalForceSafeSearch'),
                block_adult: getChecked('parentalBlockAdult'),
                block_gambling: getChecked('parentalBlockGambling'),
                block_dating: getChecked('parentalBlockDating'),
                block_drugs: getChecked('parentalBlockDrugs'),
                block_social_media: getChecked('parentalBlockSocialMedia'),
                block_gaming: getChecked('parentalBlockGaming'),
                block_video: getChecked('parentalBlockVideo'),
                schedule_enabled: getChecked('parentalScheduleEnabled'),
                schedule_from: document.getElementById('parentalScheduleFrom')?.value || '07:00',
                schedule_to: document.getElementById('parentalScheduleTo')?.value || '21:00',
                weekend_from: document.getElementById('parentalWeekendFrom')?.value || '08:00',
                weekend_to: document.getElementById('parentalWeekendTo')?.value || '23:00'
            }
        }
    });
}

// ==================== Quick Block/Allow from Query Log ====================

async function quickBlockDomain(domain) {
    if (!confirm(`Block "${domain}"? This will add it to custom filtering rules.`)) return;
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();
        const rules = cfg.filtering?.custom_rules || [];
        const rule = `||${domain}^`;
        // Remove any existing allow rule for this domain
        const filtered = rules.filter(r => r !== `@@||${domain}^`);
        if (!filtered.includes(rule)) {
            filtered.push(rule);
        }
        await saveConfig({ filtering: { custom_rules: filtered } });
        showToast(`${domain} blocked`, 'success');
        loadQueryLog();
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error blocking domain', 'error');
    }
}

async function quickAllowDomain(domain) {
    if (!confirm(`Allow "${domain}"? This will add an exception to custom filtering rules.`)) return;
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();
        const rules = cfg.filtering?.custom_rules || [];
        const rule = `@@||${domain}^`;
        if (!rules.includes(rule)) {
            rules.push(rule);
        }
        await saveConfig({ filtering: { custom_rules: rules } });
        showToast(`${domain} allowed`, 'success');
        loadQueryLog();
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error allowing domain', 'error');
    }
}

// ==================== Config Backup / Restore ====================

function initBackupRestore() {
    document.getElementById('btnBackupConfig')?.addEventListener('click', async () => {
        try {
            const resp = await apiFetch('/api/config/backup');
            if (!resp.ok) throw new Error('Backup failed');
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `sowa-config-backup-${new Date().toISOString().slice(0, 10)}.json`;
            a.click();
            URL.revokeObjectURL(url);
            showToast('Configuration backup downloaded', 'success');
        } catch (e) {
            showToast('Failed to download backup', 'error');
        }
    });

    document.getElementById('restoreConfigFile')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        if (!confirm('Are you sure you want to restore this configuration? This will overwrite your current settings.')) {
            e.target.value = '';
            return;
        }

        try {
            const text = await file.text();
            JSON.parse(text); // Validate JSON
            const resp = await apiFetch('/api/config/restore', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: text
            });
            if (resp.ok) {
                showToast('Configuration restored! Reload recommended.', 'success');
                document.getElementById('backupStatus').innerHTML = '<span style="color:var(--accent-color)">Configuration restored successfully. Reload recommended.</span>';
            } else {
                throw new Error('Restore failed');
            }
        } catch (err) {
            showToast('Failed to restore configuration: ' + err.message, 'error');
        }
        e.target.value = '';
    });
}
