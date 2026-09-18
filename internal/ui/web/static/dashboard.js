let currentHostFetchController = null;
let currentCountryFetchController = null;
let currentScansFetchController = null;
let currentCredsFetchController = null;
let isHostSwitching = false;
let isCountrySwitching = false;
let lastRenderedHostIp = null;
let lastRenderedCountryCode = null;
let scanFilterDebounceTimeout = null;
let credFilterDebounceTimeout = null;
let cmdFilterDebounceTimeout = null;
let icsFilterDebounceTimeout = null;

let lastICSData = null;
let lastSensorsData = null;
let lastSystemLogsData = null;
let lastMISPData = null;

try {
    const savedICS = sessionStorage.getItem('honeygo_cached_ics');
    if (savedICS) lastICSData = JSON.parse(savedICS);
    const savedSensors = sessionStorage.getItem('honeygo_cached_sensors');
    if (savedSensors) lastSensorsData = JSON.parse(savedSensors);
    const savedLogs = sessionStorage.getItem('honeygo_cached_syslogs');
    if (savedLogs) lastSystemLogsData = JSON.parse(savedLogs);
    const savedMISP = sessionStorage.getItem('honeygo_cached_misp');
    if (savedMISP) lastMISPData = JSON.parse(savedMISP);
} catch (e) {}

document.addEventListener('DOMContentLoaded', () => {
    applySavedTheme();
    initTabs();
    initCharts();
    initFilters();
    initCountryFilters();
    initPagination();
    initSensorSelector();
    initCSSConfig();
    initMISP();

    fetchWorldGeoJson();
    fetchData();
    fetchCorrelationsData();
    fetchCredsServerSide(1, true);
    fetchScansServerSide(1, true);
    // Do not automatically refresh or rearrange tiles in the background
    // Data is loaded on demand when tabs are opened or filters change
    
    // Initial routing
    handleRoute();
});

window.addEventListener('hashchange', handleRoute);

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/`/g, '&#96;');
}

let protocolChart, passwordChart, countryChart, asnCompanyTypeChart;
let allCreds = [];
let allScans = [];
let allCommands = [];
let latestCountriesList = [];
let allCountryAttempts = [];
let allICSEvents = [];
let currentSensor = 'all';
let currentHostIp = null;
let currentHostData = null;
let currentCountryCode = null;

let pagination = {
    creds: {
        page: 1,
        pageSize: 25,
        filteredData: []
    },
    scans: {
        page: 1,
        pageSize: 25,
        filteredData: []
    },
    commands: {
        page: 1,
        pageSize: 25,
        filteredData: []
    },
    ics: {
        page: 1,
        pageSize: 25,
        filteredData: []
    },
    hostSecondary: {
        page: 1,
        pageSize: 10,
        filteredData: []
    },
    hostCreds: {
        page: 1,
        pageSize: 10,
        filteredData: []
    },
    hostCommands: {
        page: 1,
        pageSize: 10,
        filteredData: []
    },
    hostWeb: {
        page: 1,
        pageSize: 10,
        filteredData: []
    },
    countryAttempts: {
        page: 1,
        pageSize: 25,
        filteredData: []
    },
    reconTargets: {
        page: 1,
        pageSize: 25,
        filteredData: []
    }
};

let activeSubTab = 'credentials';

function switchSubTab(subTabId) {
    activeSubTab = subTabId;
    const subBtns = document.querySelectorAll('.sub-nav-btn');
    const subPanes = document.querySelectorAll('.sub-tab-pane');

    subBtns.forEach(b => {
        if (b.getAttribute('data-subtab') === subTabId) b.classList.add('active');
        else b.classList.remove('active');
    });

    subPanes.forEach(p => {
        if (p.id === 'subtab-' + subTabId) p.classList.add('active');
        else p.classList.remove('active');
    });
}

function applySavedTheme() {
    const theme = localStorage.getItem('honeygo-theme') || 'green';
    setAppTheme(theme, false);
}

function setAppTheme(themeName, save = true) {
    if (!['green', 'red', 'blue'].includes(themeName)) {
        themeName = 'green';
    }
    
    document.documentElement.setAttribute('data-theme', themeName);
    if (save) {
        localStorage.setItem('honeygo-theme', themeName);
    }

    const themes = ['green', 'red', 'blue'];
    const themeColors = { green: '#33ff33', red: '#ff1744', blue: '#00e5ff' };

    themes.forEach(t => {
        const badge = document.getElementById(`theme-active-${t}`);
        const card = document.querySelector(`.theme-card[data-theme-val="${t}"]`);
        
        if (badge) {
            badge.style.display = (t === themeName) ? 'inline-block' : 'none';
        }
        if (card) {
            if (t === themeName) {
                card.style.border = `2px solid ${themeColors[t]}`;
                card.style.background = `rgba(${t === 'green' ? '51,255,51' : t === 'red' ? '255,23,68' : '0,229,255'}, 0.12)`;
            } else {
                card.style.border = `1px solid var(--grey-border)`;
                card.style.background = `rgba(255,255,255,0.02)`;
            }
        }
    });
}

function handleRoute() {
    const hash = window.location.hash || '#overview';
    const [tabId, query] = hash.substring(1).split('?');
    
    if (tabId === 'settings') {
        switchTab('css-config', false);
        applySavedTheme();
        return;
    }

    if (tabId === 'host-details') {
        const params = new URLSearchParams(query);
        const ip = params.get('ip');
        if (ip) {
            currentHostIp = ip;
            showHostDetails(ip, false);
        } else if (currentHostIp) {
            showHostDetails(currentHostIp, false);
        } else {
            window.location.hash = '#overview';
        }
    } else if (tabId === 'country-details') {
        const params = new URLSearchParams(query);
        const code = params.get('code');
        if (code) {
            currentCountryCode = code;
            showCountryDetails(code, false);
        } else if (currentCountryCode) {
            showCountryDetails(currentCountryCode, false);
        } else {
            window.location.hash = '#overview';
        }
    } else {
        switchTab(tabId, false);
    }
}

function initTabs() {
    const btns = document.querySelectorAll('.nav-btn[data-tab], .dropdown-item[data-tab]');

    btns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tabId = btn.getAttribute('data-tab');
            if (tabId) {
                if (tabId === 'host-details') {
                    if (currentHostIp) {
                        navigateToHost(currentHostIp);
                    }
                } else if (tabId === 'country-details') {
                    if (currentCountryCode) {
                        showCountryDetails(currentCountryCode, true);
                    }
                } else {
                    window.location.hash = tabId;
                }
            }
            document.querySelectorAll('.nav-dropdown').forEach(d => d.classList.remove('open'));
        });
    });

    const dropdownToggles = document.querySelectorAll('.dropdown-toggle');
    dropdownToggles.forEach(toggle => {
        toggle.addEventListener('click', (e) => {
            e.stopPropagation();
            const parent = toggle.closest('.nav-dropdown');
            if (parent) {
                const isOpen = parent.classList.contains('open');
                document.querySelectorAll('.nav-dropdown').forEach(d => d.classList.remove('open'));
                if (!isOpen) {
                    parent.classList.add('open');
                }
            }
        });
    });

    document.addEventListener('click', () => {
        document.querySelectorAll('.nav-dropdown').forEach(d => d.classList.remove('open'));
    });
}

function switchTab(tabId, updateHash = true) {
    const navBtns = document.querySelectorAll('.nav-btn');
    const dropdownItems = document.querySelectorAll('.dropdown-item');
    const dropdowns = document.querySelectorAll('.nav-dropdown');
    const panes = document.querySelectorAll('.tab-pane');

    navBtns.forEach(b => b.classList.remove('active'));
    dropdownItems.forEach(i => i.classList.remove('active'));
    dropdowns.forEach(d => d.classList.remove('active'));

    panes.forEach(p => {
        if (p.id === tabId) p.classList.add('active');
        else p.classList.remove('active');
    });

    dropdownItems.forEach(item => {
        if (item.getAttribute('data-tab') === tabId) {
            item.classList.add('active');
            const parentDropdown = item.closest('.nav-dropdown');
            if (parentDropdown) {
                parentDropdown.classList.add('active');
                const toggle = parentDropdown.querySelector('.dropdown-toggle');
                if (toggle) toggle.classList.add('active');
            }
        }
    });

    navBtns.forEach(b => {
        if (b.getAttribute('data-tab') === tabId) {
            b.classList.add('active');
        }
    });

    const navHost = document.getElementById('nav-host-details');
    if (navHost) {
        if (tabId === 'host-details') {
            navHost.style.display = 'inline-block';
            navHost.classList.add('active');
        } else if (currentHostIp) {
            navHost.style.display = 'inline-block';
        } else {
            navHost.style.display = 'none';
        }
    }

    const navCountry = document.getElementById('nav-country-details');
    if (navCountry) {
        if (tabId === 'country-details') {
            navCountry.style.display = 'inline-block';
            navCountry.classList.add('active');
        } else if (currentCountryCode) {
            navCountry.style.display = 'inline-block';
        } else {
            navCountry.style.display = 'none';
        }
    }

    if (tabId === 'overview') {
        renderPersistedAnalytics();
    }
    if (tabId === 'host-details' && currentHostIp && !isHostSwitching) {
        showHostDetails(currentHostIp, false);
    }
    if (tabId === 'country-details' && currentCountryCode && !isCountrySwitching) {
        showCountryDetails(currentCountryCode, false);
    }

    if (tabId === 'credentials') {
        const credBody = document.getElementById('creds-body');
        const hasExisting = credBody && credBody.children.length > 0;
        fetchCredsServerSide(pagination.creds.page || 1, hasExisting);
    }
    if (tabId === 'scans') {
        const scanBody = document.getElementById('scans-body');
        const hasExisting = scanBody && scanBody.children.length > 0;
        fetchScansServerSide(pagination.scans.page || 1, hasExisting);
    }
    if (tabId === 'commands') {
        if (!allCommands || allCommands.length === 0) {
            const queryParam = currentSensor !== 'all' ? `?sensor=${encodeURIComponent(currentSensor)}` : '';
            fetch(`/api/commands${queryParam}`)
                .then(r => r.ok ? r.json() : null)
                .then(commandsData => {
                    if (commandsData) {
                        allCommands = commandsData.recent || [];
                        applyCommandFilters(false);
                        renderPopularCommands(commandsData.popular || []);
                    }
                });
        } else {
            applyCommandFilters(false);
        }
    }

    if (tabId === 'css-config') {
        loadCSSConfig();
        applySavedTheme();
    }
    if (tabId === 'misp-config') {
        renderPersistedMISP();
        fetchMISPStatus();
    }
    if (tabId === 'css-feeds') {
        updateFeedURLs();
    }
    if (tabId === 'css-sensors-logs') {
        renderPersistedSensorsAndLogs();
        fetchSensors();
        fetchSystemLogs();
    }

    if (tabId === 'correlations') {
        renderPersistedCorrelations();
        fetchCorrelationsData(false);
        if (leafletMap) {
            setTimeout(() => leafletMap.invalidateSize(), 150);
        }
    }

    if (tabId === 'threat-analytics') {
        renderPersistedAnalytics();
        if (lastAnalyticsData) {
            updateAnalyticsLists(lastAnalyticsData);
        }
        fetchData();
    }

    if (tabId === 'ics') {
        renderPersistedICS();
        fetchICSData();
    }

    if (tabId === 'recon-intel') {
        renderPersistedReconTargets();
        loadReconTargets();
    }

    if (updateHash) {
        if (tabId === 'host-details' && currentHostIp) {
            window.location.hash = `host-details?ip=${encodeURIComponent(currentHostIp)}`;
        } else if (tabId === 'country-details' && currentCountryCode) {
            window.location.hash = `country-details?code=${encodeURIComponent(currentCountryCode)}`;
        } else {
            window.location.hash = tabId;
        }
    }
}

function syncSubHeaderSensorBar() {
    const infoStatus = document.getElementById('sensor-info-status');
    const resetBtn = document.getElementById('btn-reset-sensor-filter');
    
    if (currentSensor === 'all') {
        if (infoStatus) infoStatus.textContent = 'Showing aggregated cluster-wide telemetry across all connected honeypots';
        if (resetBtn) resetBtn.style.display = 'none';
    } else {
        const found = cachedSensorsList.find(s => s.sensor_id === currentSensor);
        const label = (found && found.display_name) ? `${found.display_name} (${currentSensor})` : currentSensor;
        if (infoStatus) infoStatus.innerHTML = `Showing filtered telemetry for sensor: <strong style="color:#00e5ff;">🎯 ${escapeHtml(label)}</strong>`;
        if (resetBtn) resetBtn.style.display = 'inline-flex';
    }
}

function initSensorSelector() {
    const select = document.getElementById('filter-sensor-global');
    if (select) {
        select.addEventListener('change', (e) => {
            currentSensor = e.target.value;
            syncSubHeaderSensorBar();
            fetchData();
            fetchCorrelationsData(true);
            fetchCredsServerSide(1, true);
            fetchScansServerSide(1, true);
            const activeTab = document.querySelector('.tab-pane.active');
            if (activeTab && activeTab.id) {
                switchTab(activeTab.id, false);
            }
        });
    }
}

function initCharts() {
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#33ff33', '#00ff66', '#80ff80', '#00cc44', '#00ffcc', '#00aa33'],
                borderWidth: 1,
                borderColor: '#050e07'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#d4ffd4', font: { family: "'JetBrains Mono', monospace" } } }
            }
        }
    });

    const passwordCtx = document.getElementById('passwordChart').getContext('2d');
    passwordChart = new Chart(passwordCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Frequency',
                data: [],
                backgroundColor: 'rgba(51, 255, 51, 0.45)',
                borderColor: '#33ff33',
                borderWidth: 1.5
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            scales: {
                x: { ticks: { color: '#d4ffd4', font: { family: "'JetBrains Mono', monospace" } }, grid: { color: 'rgba(51, 255, 51, 0.1)' } },
                y: { ticks: { color: '#d4ffd4', font: { family: "'JetBrains Mono', monospace" } }, grid: { display: false } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });

    const countryCtx = document.getElementById('countryChart').getContext('2d');
    countryChart = new Chart(countryCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Attempts',
                    data: [],
                    backgroundColor: 'rgba(51, 255, 51, 0.4)',
                    borderColor: '#33ff33',
                    borderWidth: 1.5
                },
                {
                    label: 'Credentials Captured',
                    data: [],
                    backgroundColor: 'rgba(0, 255, 204, 0.4)',
                    borderColor: '#00ffcc',
                    borderWidth: 1.5
                }
            ]
        },
        options: {
            responsive: true,
            onClick: (event, activeElements) => {
                if (activeElements.length > 0 && latestCountriesList.length > 0) {
                    const idx = activeElements[0].index;
                    const country = latestCountriesList[idx];
                    if (country) {
                        showCountryDetails(country.country_code);
                    }
                }
            },
            onHover: (event, activeElements) => {
                event.native.target.style.cursor = activeElements.length > 0 ? 'pointer' : 'default';
            },
            scales: {
                x: { ticks: { color: '#d4ffd4', font: { family: "'JetBrains Mono', monospace" } }, grid: { display: false } },
                y: { ticks: { color: '#d4ffd4', font: { family: "'JetBrains Mono', monospace" } }, grid: { color: 'rgba(51, 255, 51, 0.1)' } }
            },
            plugins: {
                legend: { display: true, labels: { color: '#d4ffd4', font: { family: "'JetBrains Mono', monospace" } } }
            }
        }
    });

    const asnCompanyElem = document.getElementById('asnCompanyTypeChart');
    if (asnCompanyElem) {
        const asnCompanyCtx = asnCompanyElem.getContext('2d');
        asnCompanyTypeChart = new Chart(asnCompanyCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#33ff33', '#00ff66', '#ffb000', '#00ffcc', '#80ff80', '#00aa33', '#4d9959'],
                    borderWidth: 1,
                    borderColor: '#050e07'
                }]
            },
            options: {
                responsive: true,
                onClick: (event, activeElements) => {
                    if (activeElements.length > 0 && asnCompanyTypeChart.data.labels.length > 0) {
                        const idx = activeElements[0].index;
                        const category = asnCompanyTypeChart.data.labels[idx];
                        if (category) {
                            openASNCategoryModal(category);
                        }
                    }
                },
                onHover: (event, activeElements) => {
                    event.native.target.style.cursor = activeElements.length > 0 ? 'pointer' : 'default';
                },
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#d4ffd4', font: { family: "'JetBrains Mono', monospace" } } }
                }
            }
        });
    }
}

async function fetchCredsServerSide(page = 1, isSilent = false) {
    const credFilter = document.getElementById('filter-creds');
    const pageSizeCreds = document.getElementById('pageSize-creds');
    const body = document.getElementById('creds-body');
    const infoCreds = document.getElementById('info-creds');
    const btnPrevCreds = document.getElementById('btn-prev-creds');
    const btnNextCreds = document.getElementById('btn-next-creds');

    if (!body) return;

    if (page < 1) page = 1;
    pagination.creds.page = page;

    const credVal = credFilter ? credFilter.value.trim() : '';
    const pageSizeVal = pageSizeCreds ? pageSizeCreds.value : '25';
    pagination.creds.pageSize = pageSizeVal;

    updateCredsExportBtnState();

    if (currentCredsFetchController) {
        currentCredsFetchController.abort();
    }
    currentCredsFetchController = new AbortController();

    if (!isSilent && body.children.length === 0) {
        body.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:18px; color:var(--cyan-glow);">⏳ Loading credentials from server...</td></tr>';
        if (infoCreds) infoCreds.textContent = `Loading page ${page}...`;
    }

    try {
        const params = new URLSearchParams();
        params.set('page', page);
        params.set('limit', pageSizeVal);
        if (currentSensor && currentSensor !== 'all') {
            params.set('sensor', currentSensor);
        }
        if (credVal) params.set('q', credVal);

        const res = await fetch(`/api/credentials?${params.toString()}`, {
            signal: currentCredsFetchController.signal
        });
        if (!res.ok) {
            throw new Error(`Server returned HTTP ${res.status}`);
        }
        const result = await res.json();

        let creds = [];
        let total = 0;
        let totalPages = 1;

        if (result && Array.isArray(result.credentials)) {
            creds = result.credentials;
            total = result.total || 0;
            totalPages = result.total_pages || 1;
        } else if (Array.isArray(result)) {
            creds = result;
            total = result.length;
            totalPages = 1;
        }

        pagination.creds.page = page;
        pagination.creds.totalPages = totalPages;
        pagination.creds.total = total;
        pagination.creds.filteredData = creds;

        if (infoCreds) {
            infoCreds.textContent = `Page ${page} of ${totalPages} (${total.toLocaleString()} total)`;
        }
        if (btnPrevCreds) {
            btnPrevCreds.disabled = page <= 1;
        }
        if (btnNextCreds) {
            btnNextCreds.disabled = pageSizeVal === 'all' || page >= totalPages;
        }

        const hasActiveFilter = Boolean(credVal);

        renderCredsTable(creds);
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Failed to fetch credentials from server:', err);
        if (!isSilent) {
            body.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--accent-red); padding:18px;">⚠️ Error loading credentials: ${escapeHtml(err.message)}</td></tr>`;
            if (infoCreds) infoCreds.textContent = 'Error';
        }
    }
}

function applyCredFilters(resetPage = true) {
    fetchCredsServerSide(resetPage ? 1 : (pagination.creds.page || 1), false);
}

async function fetchScansServerSide(page = 1, isSilent = false) {
    const scanFilter = document.getElementById('filter-scans');
    const pageSizeScans = document.getElementById('pageSize-scans');
    const body = document.getElementById('scans-body');
    const infoScans = document.getElementById('info-scans');
    const btnPrevScans = document.getElementById('btn-prev-scans');
    const btnNextScans = document.getElementById('btn-next-scans');

    if (!body) return;

    if (page < 1) page = 1;
    pagination.scans.page = page;

    const scanVal = scanFilter ? scanFilter.value.trim() : '';
    const pageSizeVal = pageSizeScans ? pageSizeScans.value : '25';
    pagination.scans.pageSize = pageSizeVal;

    updateScansExportBtnState();

    if (currentScansFetchController) {
        currentScansFetchController.abort();
    }
    currentScansFetchController = new AbortController();

    if (!isSilent && body.children.length === 0) {
        body.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:18px; color:var(--cyan-glow);">⏳ Loading web scans from server...</td></tr>';
        if (infoScans) infoScans.textContent = `Loading page ${page}...`;
    }

    try {
        const params = new URLSearchParams();
        params.set('page', page);
        params.set('limit', pageSizeVal);
        if (currentSensor && currentSensor !== 'all') {
            params.set('sensor', currentSensor);
        }
        if (scanVal) {
            params.set('q', scanVal);
        }

        const res = await fetch(`/api/scans?${params.toString()}`, {
            signal: currentScansFetchController.signal
        });
        if (!res.ok) {
            throw new Error(`Server returned HTTP ${res.status}`);
        }
        const result = await res.json();

        let scans = [];
        let total = 0;
        let totalPages = 1;

        if (result && Array.isArray(result.scans)) {
            scans = result.scans;
            total = result.total || 0;
            totalPages = result.total_pages || 1;
        } else if (Array.isArray(result)) {
            scans = result;
            total = result.length;
            totalPages = 1;
        }

        pagination.scans.page = page;
        pagination.scans.totalPages = totalPages;
        pagination.scans.total = total;
        pagination.scans.filteredData = scans;

        if (infoScans) {
            infoScans.textContent = `Page ${page} of ${totalPages} (${total.toLocaleString()} total)`;
        }
        if (btnPrevScans) {
            btnPrevScans.disabled = page <= 1;
        }
        if (btnNextScans) {
            btnNextScans.disabled = pageSizeVal === 'all' || page >= totalPages;
        }

        const hasActiveFilter = Boolean(scanVal);

        renderScansTable(scans);
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Failed to fetch scans from server:', err);
        if (!isSilent) {
            body.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--accent-red); padding:18px;">⚠️ Error loading web scans: ${escapeHtml(err.message)}</td></tr>`;
            if (infoScans) infoScans.textContent = 'Error';
        }
    }
}

function applyScanFilters(resetPage = true) {
    fetchScansServerSide(resetPage ? 1 : (pagination.scans.page || 1), false);
}

function applyCommandFilters(resetPage = true, isSilent = false) {
    const cmdFilter = document.getElementById('filter-commands');

    if (resetPage) pagination.commands.page = 1;

    const qVal = cmdFilter ? cmdFilter.value.toLowerCase().trim() : '';
    const hasActiveFilter = qVal !== '';

    const filtered = (allCommands || []).filter(c => {
        if (!qVal) return true;
        const matchesCmd = (c.command || '').toLowerCase().includes(qVal);
        const matchesIp = (c.remote_ip || '').toLowerCase().includes(qVal);
        const matchesUser = (c.username || '').toLowerCase().includes(qVal);
        const matchesProto = (c.protocol || '').toLowerCase().includes(qVal);
        const matchesCountry = (c.country_name || '').toLowerCase().includes(qVal) || (c.country_code || '').toLowerCase().includes(qVal);
        const matchesAsn = (c.asn || '').toLowerCase().includes(qVal) || (c.as_name || '').toLowerCase().includes(qVal);
        return matchesCmd || matchesIp || matchesUser || matchesProto || matchesCountry || matchesAsn;
    });

    updateCommandsExportBtnState();
    renderCommandsTable(filtered, isSilent, hasActiveFilter);
}

function initFilters() {
    const credFilter = document.getElementById('filter-creds');
    if (credFilter) {
        credFilter.addEventListener('input', () => {
            clearTimeout(credFilterDebounceTimeout);
            credFilterDebounceTimeout = setTimeout(() => {
                fetchCredsServerSide(1, false);
            }, 300);
        });
    }

    const scanFilter = document.getElementById('filter-scans');
    if (scanFilter) {
        scanFilter.addEventListener('input', () => {
            clearTimeout(scanFilterDebounceTimeout);
            scanFilterDebounceTimeout = setTimeout(() => {
                fetchScansServerSide(1, false);
            }, 300);
        });
    }

    const cmdFilter = document.getElementById('filter-commands');
    if (cmdFilter) {
        cmdFilter.addEventListener('input', () => {
            clearTimeout(cmdFilterDebounceTimeout);
            cmdFilterDebounceTimeout = setTimeout(() => {
                applyCommandFilters(true, false);
            }, 150);
        });
    }

    const icsIpFilter = document.getElementById('filter-ics-ip');
    const icsProtoFilter = document.getElementById('filter-ics-proto');
    const onICSFilterInput = () => {
        clearTimeout(icsFilterDebounceTimeout);
        icsFilterDebounceTimeout = setTimeout(() => {
            applyICSFilters(true, false);
        }, 150);
    };
    if (icsIpFilter) icsIpFilter.addEventListener('input', onICSFilterInput);
    if (icsProtoFilter) icsProtoFilter.addEventListener('change', () => applyICSFilters(true, false));

    updateCredsExportBtnState();
    updateScansExportBtnState();
    updateCommandsExportBtnState();

    const sysCatFilter = document.getElementById('filter-syslog-cat');
    const sysLvlFilter = document.getElementById('filter-syslog-lvl');
    if (sysCatFilter) sysCatFilter.addEventListener('change', () => fetchSystemLogs(false));
    if (sysLvlFilter) sysLvlFilter.addEventListener('change', () => fetchSystemLogs(false));
}

function initPagination() {
    // Credentials
    const pageSizeCreds = document.getElementById('pageSize-creds');
    const btnPrevCreds = document.getElementById('btn-prev-creds');
    const btnNextCreds = document.getElementById('btn-next-creds');

    if (pageSizeCreds && btnPrevCreds && btnNextCreds) {
        pageSizeCreds.addEventListener('change', (e) => {
            pagination.creds.pageSize = e.target.value;
            fetchCredsServerSide(1);
        });
        btnPrevCreds.addEventListener('click', () => {
            if (pagination.creds.page > 1) {
                fetchCredsServerSide(pagination.creds.page - 1);
            }
        });
        btnNextCreds.addEventListener('click', () => {
            if (pagination.creds.page < (pagination.creds.totalPages || 1)) {
                fetchCredsServerSide(pagination.creds.page + 1);
            }
        });
    }

    // Web Scans
    const pageSizeScans = document.getElementById('pageSize-scans');
    const btnPrevScans = document.getElementById('btn-prev-scans');
    const btnNextScans = document.getElementById('btn-next-scans');

    if (pageSizeScans && btnPrevScans && btnNextScans) {
        pageSizeScans.addEventListener('change', (e) => {
            pagination.scans.pageSize = e.target.value;
            fetchScansServerSide(1);
        });
        btnPrevScans.addEventListener('click', () => {
            if (pagination.scans.page > 1) {
                fetchScansServerSide(pagination.scans.page - 1);
            }
        });
        btnNextScans.addEventListener('click', () => {
            if (pagination.scans.page < (pagination.scans.totalPages || 1)) {
                fetchScansServerSide(pagination.scans.page + 1);
            }
        });
    }

    // Commands
    const pageSizeCommands = document.getElementById('pageSize-commands');
    const btnPrevCommands = document.getElementById('btn-prev-commands');
    const btnNextCommands = document.getElementById('btn-next-commands');

    if (pageSizeCommands && btnPrevCommands && btnNextCommands) {
        pageSizeCommands.addEventListener('change', (e) => {
            pagination.commands.pageSize = e.target.value;
            pagination.commands.page = 1;
            applyCommandFilters(false);
        });
        btnPrevCommands.addEventListener('click', () => {
            if (pagination.commands.page > 1) {
                pagination.commands.page--;
                applyCommandFilters(false);
            }
        });
        btnNextCommands.addEventListener('click', () => {
            const sizeVal = pagination.commands.pageSize;
            if (sizeVal !== 'all') {
                const size = parseInt(sizeVal, 10);
                const totalPages = Math.ceil(pagination.commands.filteredData.length / size) || 1;
                if (pagination.commands.page < totalPages) {
                    pagination.commands.page++;
                    applyCommandFilters(false);
                }
            }
        });
    }

    // ICS / SCADA Attack Log
    const pageSizeICS = document.getElementById('pageSize-ics');
    const btnPrevICS = document.getElementById('btn-prev-ics');
    const btnNextICS = document.getElementById('btn-next-ics');

    if (pageSizeICS && btnPrevICS && btnNextICS) {
        pageSizeICS.addEventListener('change', (e) => {
            pagination.ics.pageSize = e.target.value;
            pagination.ics.page = 1;
            applyICSFilters(false);
        });
        btnPrevICS.addEventListener('click', () => {
            if (pagination.ics.page > 1) {
                pagination.ics.page--;
                applyICSFilters(false);
            }
        });
        btnNextICS.addEventListener('click', () => {
            const sizeVal = pagination.ics.pageSize;
            if (sizeVal !== 'all') {
                const size = parseInt(sizeVal, 10);
                const totalPages = Math.ceil(pagination.ics.filteredData.length / size) || 1;
                if (pagination.ics.page < totalPages) {
                    pagination.ics.page++;
                    applyICSFilters(false);
                }
            }
        });
    }

    // Host Details: Secondary Attack Mentions
    const pageSizeHostSec = document.getElementById('pageSize-host-secondary');
    const btnPrevHostSec = document.getElementById('btn-prev-host-secondary');
    const btnNextHostSec = document.getElementById('btn-next-host-secondary');
    if (pageSizeHostSec && btnPrevHostSec && btnNextHostSec) {
        pageSizeHostSec.addEventListener('change', (e) => {
            pagination.hostSecondary.pageSize = e.target.value;
            pagination.hostSecondary.page = 1;
            renderHostSecondaryTable();
        });
        btnPrevHostSec.addEventListener('click', () => {
            if (pagination.hostSecondary.page > 1) {
                pagination.hostSecondary.page--;
                renderHostSecondaryTable();
            }
        });
        btnNextHostSec.addEventListener('click', () => {
            const sizeVal = pagination.hostSecondary.pageSize;
            if (sizeVal !== 'all') {
                const size = parseInt(sizeVal, 10);
                const totalPages = Math.ceil(pagination.hostSecondary.filteredData.length / size) || 1;
                if (pagination.hostSecondary.page < totalPages) {
                    pagination.hostSecondary.page++;
                    renderHostSecondaryTable();
                }
            }
        });
    }

    // Host Details: Captured Credentials
    const pageSizeHostCreds = document.getElementById('pageSize-host-creds');
    const btnPrevHostCreds = document.getElementById('btn-prev-host-creds');
    const btnNextHostCreds = document.getElementById('btn-next-host-creds');
    if (pageSizeHostCreds && btnPrevHostCreds && btnNextHostCreds) {
        pageSizeHostCreds.addEventListener('change', (e) => {
            pagination.hostCreds.pageSize = e.target.value;
            pagination.hostCreds.page = 1;
            renderHostCredsTable();
        });
        btnPrevHostCreds.addEventListener('click', () => {
            if (pagination.hostCreds.page > 1) {
                pagination.hostCreds.page--;
                renderHostCredsTable();
            }
        });
        btnNextHostCreds.addEventListener('click', () => {
            const sizeVal = pagination.hostCreds.pageSize;
            if (sizeVal !== 'all') {
                const size = parseInt(sizeVal, 10);
                const totalPages = Math.ceil(pagination.hostCreds.filteredData.length / size) || 1;
                if (pagination.hostCreds.page < totalPages) {
                    pagination.hostCreds.page++;
                    renderHostCredsTable();
                }
            }
        });
    }

    // Host Details: Commands
    const pageSizeHostCmd = document.getElementById('pageSize-host-commands');
    const btnPrevHostCmd = document.getElementById('btn-prev-host-commands');
    const btnNextHostCmd = document.getElementById('btn-next-host-commands');
    if (pageSizeHostCmd && btnPrevHostCmd && btnNextHostCmd) {
        pageSizeHostCmd.addEventListener('change', (e) => {
            pagination.hostCommands.pageSize = e.target.value;
            pagination.hostCommands.page = 1;
            renderHostCommandsTable();
        });
        btnPrevHostCmd.addEventListener('click', () => {
            if (pagination.hostCommands.page > 1) {
                pagination.hostCommands.page--;
                renderHostCommandsTable();
            }
        });
        btnNextHostCmd.addEventListener('click', () => {
            const sizeVal = pagination.hostCommands.pageSize;
            if (sizeVal !== 'all') {
                const size = parseInt(sizeVal, 10);
                const totalPages = Math.ceil(pagination.hostCommands.filteredData.length / size) || 1;
                if (pagination.hostCommands.page < totalPages) {
                    pagination.hostCommands.page++;
                    renderHostCommandsTable();
                }
            }
        });
    }

    // Host Details: Web Requests
    const pageSizeHostWeb = document.getElementById('pageSize-host-web');
    const btnPrevHostWeb = document.getElementById('btn-prev-host-web');
    const btnNextHostWeb = document.getElementById('btn-next-host-web');
    if (pageSizeHostWeb && btnPrevHostWeb && btnNextHostWeb) {
        pageSizeHostWeb.addEventListener('change', (e) => {
            pagination.hostWeb.pageSize = e.target.value;
            pagination.hostWeb.page = 1;
            renderHostWebTable();
        });
        btnPrevHostWeb.addEventListener('click', () => {
            if (pagination.hostWeb.page > 1) {
                pagination.hostWeb.page--;
                renderHostWebTable();
            }
        });
        btnNextHostWeb.addEventListener('click', () => {
            const sizeVal = pagination.hostWeb.pageSize;
            if (sizeVal !== 'all') {
                const size = parseInt(sizeVal, 10);
                const totalPages = Math.ceil(pagination.hostWeb.filteredData.length / size) || 1;
                if (pagination.hostWeb.page < totalPages) {
                    pagination.hostWeb.page++;
                    renderHostWebTable();
                }
            }
        });
    }

    // Country Details: Attempts
    const pageSizeCountry = document.getElementById('pageSize-country');
    const btnPrevCountry = document.getElementById('btn-prev-country');
    const btnNextCountry = document.getElementById('btn-next-country');
    if (pageSizeCountry && btnPrevCountry && btnNextCountry) {
        pageSizeCountry.addEventListener('change', (e) => {
            pagination.countryAttempts.pageSize = e.target.value;
            pagination.countryAttempts.page = 1;
            renderCountryAttemptsTable(allCountryAttempts);
        });
        btnPrevCountry.addEventListener('click', () => {
            if (pagination.countryAttempts.page > 1) {
                pagination.countryAttempts.page--;
                renderCountryAttemptsTable(allCountryAttempts);
            }
        });
        btnNextCountry.addEventListener('click', () => {
            const sizeVal = pagination.countryAttempts.pageSize;
            if (sizeVal !== 'all') {
                const size = parseInt(sizeVal, 10);
                const totalPages = Math.ceil(pagination.countryAttempts.filteredData.length / size) || 1;
                if (pagination.countryAttempts.page < totalPages) {
                    pagination.countryAttempts.page++;
                    renderCountryAttemptsTable(allCountryAttempts);
                }
            }
        });
    }

    // Recon Targets
    const pageSizeRecon = document.getElementById('pageSize-recon');
    const btnPrevRecon = document.getElementById('btn-prev-recon');
    const btnNextRecon = document.getElementById('btn-next-recon');
    if (pageSizeRecon && btnPrevRecon && btnNextRecon) {
        pageSizeRecon.addEventListener('change', (e) => {
            pagination.reconTargets.pageSize = e.target.value;
            pagination.reconTargets.page = 1;
            if (cachedReconData) renderReconData(cachedReconData);
        });
        btnPrevRecon.addEventListener('click', () => {
            if (pagination.reconTargets.page > 1) {
                pagination.reconTargets.page--;
                if (cachedReconData) renderReconData(cachedReconData);
            }
        });
        btnNextRecon.addEventListener('click', () => {
            const sizeVal = pagination.reconTargets.pageSize;
            if (sizeVal !== 'all') {
                const size = parseInt(sizeVal, 10);
                const totalPages = Math.ceil(pagination.reconTargets.filteredData.length / size) || 1;
                if (pagination.reconTargets.page < totalPages) {
                    pagination.reconTargets.page++;
                    if (cachedReconData) renderReconData(cachedReconData);
                }
            }
        });
    }
}

let lastAnalyticsData = null;

function renderPersistedAnalytics() {
    if (!lastAnalyticsData) {
        try {
            const saved = sessionStorage.getItem('honeygo_cached_analytics');
            if (saved) {
                lastAnalyticsData = JSON.parse(saved);
            }
        } catch (e) {}
    }
    if (lastAnalyticsData) {
        updateCharts(lastAnalyticsData);
        updateAnalyticsLists(lastAnalyticsData);
    }
}

async function fetchData() {
    const queryParam = currentSensor !== 'all' ? `?sensor=${encodeURIComponent(currentSensor)}` : '';

    // Fetch core telemetry metrics for overview
    await Promise.allSettled([
        fetch(`/api/stats${queryParam}`)
            .then(r => r.ok ? r.json() : null)
            .then(stats => { if (stats) updateStats(stats); })
            .catch(e => console.error('Error fetching stats:', e)),

        fetch(`/api/analytics${queryParam}`)
            .then(r => r.ok ? r.json() : null)
            .then(analytics => {
                if (analytics) {
                    lastAnalyticsData = analytics;
                    try {
                        sessionStorage.setItem('honeygo_cached_analytics', JSON.stringify(analytics));
                    } catch (e) {}
                    updateCharts(analytics);
                    updateAnalyticsLists(analytics);
                }
            })
            .catch(e => console.error('Error fetching analytics:', e)),

        fetch(`/api/commands${queryParam}`)
            .then(r => r.ok ? r.json() : null)
            .then(commandsData => {
                if (commandsData) {
                    allCommands = commandsData.recent || [];
                    applyCommandFilters(false, true);
                    renderPopularCommands(commandsData.popular || []);
                }
            })
            .catch(e => console.error('Error fetching commands:', e))
    ]);

    try { fetchSensors(); } catch (e) {}
}

async function fetchSensors() {
    try {
        const res = await fetch('/api/css/sensors');
        if (!res.ok) return;
        const sensors = await res.json();
        lastSensorsData = sensors;
        try { sessionStorage.setItem('honeygo_cached_sensors', JSON.stringify(sensors)); } catch (e) {}
        updateSensorSelectorOptions(sensors);
        renderSensorsTable(sensors);
    } catch (err) {
        // Silently handle if CSS server endpoints are disabled
    }
}

let cachedSensorsList = [];

function updateSensorSelectorOptions(sensors) {
    const select = document.getElementById('filter-sensor-global');
    if (!select) return;

    // Always sort sensors in alphabetical order
    const sortedSensors = (sensors && Array.isArray(sensors)) ? 
        [...sensors].sort((a, b) => (a.sensor_id || '').localeCompare(b.sensor_id || '', undefined, { sensitivity: 'base' })) : [];
    
    cachedSensorsList = sortedSensors;

    let html = `<option value="all" ${currentSensor === 'all' ? 'selected' : ''}>⚡ All Sensors</option>`;
    sortedSensors.forEach(s => {
        const selected = s.sensor_id === currentSensor ? 'selected' : '';
        const statusBadge = s.status === 'Active' ? '🟢' : '⚪';
        const label = s.display_name ? `${s.display_name} (${s.sensor_id})` : s.sensor_id;
        html += `<option value="${s.sensor_id}" ${selected}>${statusBadge} ${escapeHtml(label)} (${s.event_count} events)</option>`;
    });
    select.innerHTML = html;
    select.value = currentSensor;
    syncSubHeaderSensorBar();
}

const KNOWN_PROTOCOLS = [
    { id: 'ssh', name: 'SSH', defaultPort: 2222, icon: '🔒' },
    { id: 'telnet', name: 'TELNET', defaultPort: 2323, icon: '📟' },
    { id: 'web', name: 'WEB', defaultPort: 8080, icon: '🌐' },
    { id: 'modbus', name: 'MODBUS', defaultPort: 502, icon: '⚡' },
    { id: 's7comm', name: 'S7COMM', defaultPort: 102, icon: '🏭' },
    { id: 'vnc', name: 'VNC', defaultPort: 5900, icon: '🖥️' }
];

function renderProtocolRibbon(services, selectedSensor) {
    const container = document.getElementById('ribbon-protocol-list');
    if (!container) return;

    const ribbonLabel = document.querySelector('#protocol-status-ribbon .ribbon-label');
    if (ribbonLabel) {
        if (selectedSensor && selectedSensor !== 'all') {
            ribbonLabel.textContent = `Honeypot Protocols (${selectedSensor})`;
        } else {
            ribbonLabel.textContent = 'Honeypot Protocols (All Sensors Combined)';
        }
    }

    // Build service map from API data
    const svcMap = {};
    if (services && Array.isArray(services)) {
        services.forEach(s => {
            const protoKey = (s.protocol || '').toLowerCase();
            svcMap[protoKey] = s;
        });
    }

    const html = KNOWN_PROTOCOLS.map(p => {
        const liveSvc = svcMap[p.id];
        const isActive = liveSvc ? (liveSvc.status === 'Running' || liveSvc.status === 'active') : false;
        const port = liveSvc ? liveSvc.port : p.defaultPort;
        const isIsolated = liveSvc ? !!liveSvc.isolated : false;

        let badgeHtml = '';
        if (isIsolated) {
            badgeHtml = '<span class="proto-mode-badge isolated">SANDBOX</span>';
        } else if (isActive) {
            badgeHtml = '<span class="proto-mode-badge native">ACTIVE</span>';
        } else {
            badgeHtml = '<span class="proto-mode-badge" style="opacity:0.4; border:1px solid #444;">OFF</span>';
        }

        return `
            <div class="protocol-ribbon-item ${isActive ? 'active' : 'inactive'}" title="${p.name} Honeypot - ${isActive ? 'Running on port ' + port : 'Stopped / Standby'}">
                <span class="proto-dot ${isActive ? 'active' : 'inactive'}"></span>
                <span class="proto-name">${p.icon} ${p.name}</span>
                <span class="proto-port">:${port}</span>
                ${badgeHtml}
            </div>
        `;
    }).join('');

    container.innerHTML = html;
}

function updateStats(stats) {
    if (stats.version) {
        const vEl = document.querySelector('.logo .version');
        if (vEl) vEl.textContent = stats.version;
    }

    const totalAttempts = document.getElementById('total-attempts');
    const totalCreds = document.getElementById('total-creds');
    const connectedSensors = document.getElementById('connected-sensors');
    const connectedSensorsTitle = document.getElementById('connected-sensors-card-title');
    const sensorBanner = document.getElementById('overview-sensor-banner');
    const sensorBadge = document.getElementById('overview-sensor-badge');

    if (totalAttempts) totalAttempts.textContent = stats.total_attempts || 0;
    if (totalCreds) totalCreds.textContent = stats.total_credentials || 0;

    const isFiltered = stats.selected_sensor && stats.selected_sensor !== 'all';

    if (connectedSensorsTitle) {
        connectedSensorsTitle.textContent = isFiltered ? 'Selected Honeypot' : 'Connected Sensors';
    }

    if (connectedSensors) {
        if (isFiltered) {
            if (stats.connected_sensors_count > 0) {
                connectedSensors.innerHTML = `<span style="color: #00e5ff;">1</span> <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: normal;">(${escapeHtml(stats.selected_sensor)})</span>`;
            } else {
                connectedSensors.innerHTML = `<span style="color: var(--text-muted);">0</span> <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: normal;">(${escapeHtml(stats.selected_sensor)} - offline)</span>`;
            }
        } else {
            connectedSensors.textContent = stats.connected_sensors_count !== undefined ? stats.connected_sensors_count : 0;
        }
    }

    if (sensorBanner && sensorBadge) {
        if (isFiltered) {
            sensorBanner.style.display = 'flex';
            sensorBadge.textContent = stats.selected_sensor;
        } else {
            sensorBanner.style.display = 'none';
        }
    }

    renderProtocolRibbon(stats.services, stats.selected_sensor);
}

function resetGlobalSensorFilter() {
    const select = document.getElementById('filter-sensor-global');
    if (select) {
        select.value = 'all';
        currentSensor = 'all';
        syncSubHeaderSensorBar();
        fetchData();
        const activeTab = document.querySelector('.tab-pane.active');
        if (activeTab && activeTab.id) {
            switchTab(activeTab.id, false);
        }
    }
}

function updateCharts(analytics) {
    if (analytics.protocols) {
        analytics.protocols.sort((a, b) => (b.count || 0) - (a.count || 0));
        protocolChart.data.labels = analytics.protocols.map(p => (p.protocol || '').toUpperCase());
        protocolChart.data.datasets[0].data = analytics.protocols.map(p => p.count);
        protocolChart.update();
    }

    passwordChart.data.labels = analytics.passwords.slice(0, 5).map(p => p.password);
    passwordChart.data.datasets[0].data = analytics.passwords.slice(0, 5).map(p => p.count);
    passwordChart.update();

    latestCountriesList = analytics.countries.slice(0, 10);
    countryChart.data.labels = latestCountriesList.map(c => c.country_name || 'Unknown');
    countryChart.data.datasets[0].data = latestCountriesList.map(c => c.attempts);
    countryChart.data.datasets[1].data = latestCountriesList.map(c => c.credentials);
    countryChart.update();

    if (asnCompanyTypeChart && analytics.asn_company_types) {
        asnCompanyTypeChart.data.labels = analytics.asn_company_types.map(c => c.category);
        asnCompanyTypeChart.data.datasets[0].data = analytics.asn_company_types.map(c => c.attack_count);
        asnCompanyTypeChart.update();
    }
}

function navigateToHost(ip) {
    if (!ip) return;
    const cleanIp = String(ip).trim();
    currentHostIp = cleanIp;
    const targetHash = `host-details?ip=${encodeURIComponent(cleanIp)}`;
    if (window.location.hash === `#${targetHash}`) {
        showHostDetails(cleanIp, false);
    } else {
        window.location.hash = targetHash;
    }
}

function updateAnalyticsLists(analytics) {
    const updateListIfChanged = (elemId, newHtml) => {
        const el = document.getElementById(elemId);
        if (el && el.innerHTML !== newHtml) {
            el.innerHTML = newHtml;
        }
    };

    if (analytics.hosts) {
        const html = analytics.hosts.map(h => `
            <div class="list-item">
                <div>
                    <span class="country-badge" style="margin-right: 5px;" title="${escapeHtml(h.country_name || '')}">${getFlagEmoji(h.country_code)}</span>
                    <span class="host-link" onclick="navigateToHost('${escapeHtml(h.remote_ip)}')">${escapeHtml(h.remote_ip)}</span>
                    <span style="font-size: 0.8rem; color: rgba(255,255,255,0.4); margin-left: 8px;">(${escapeHtml(h.asn || 'No ASN')} - ${escapeHtml(h.as_name || 'Unknown')})</span>
                </div>
                <span class="highlight">${escapeHtml(h.count)} hits</span>
            </div>
        `).join('');
        updateListIfChanged('top-hosts-list', html);
    }

    if (analytics.passwords) {
        const html = analytics.passwords.map(p => `
            <div class="list-item">
                <span>${escapeHtml(p.password)}</span>
                <span class="highlight">${escapeHtml(p.count)} hits</span>
            </div>
        `).join('');
        updateListIfChanged('top-passwords-list', html);
    }

    if (analytics.countries) {
        const html = analytics.countries.map(c => `
            <div class="list-item" style="cursor:pointer;" onclick="showCountryDetails('${escapeHtml(c.country_code)}')">
                <span>${getFlagEmoji(c.country_code)} ${escapeHtml(c.country_code)} - ${escapeHtml(c.country_name || 'Unknown')}</span>
                <span class="highlight">${escapeHtml(c.attempts)} attempts / ${escapeHtml(c.credentials)} creds</span>
            </div>
        `).join('');
        updateListIfChanged('top-countries-list', html);
    }

    if (analytics.protocols) {
        const sortedProtocols = [...analytics.protocols].sort((a, b) => (b.count || 0) - (a.count || 0));
        const html = sortedProtocols.map(p => `
            <div class="list-item">
                <span><span class="badge ${escapeHtml((p.protocol || '').toLowerCase())}">${escapeHtml((p.protocol || '').toUpperCase())}</span></span>
                <span class="highlight">${escapeHtml(p.count)} ${p.count === 1 ? 'hit' : 'hits'}</span>
            </div>
        `).join('');
        updateListIfChanged('protocol-activity-list', html);
    }

    if (analytics.top_protocol_by_country) {
        const html = analytics.top_protocol_by_country.map(c => `
            <div class="list-item" style="cursor:pointer;" onclick="showCountryDetails('${escapeHtml(c.country_code)}')">
                <span>${getFlagEmoji(c.country_code)} <strong>${escapeHtml(c.country_name)}</strong></span>
                <span>
                    <span class="badge ${escapeHtml(c.protocol)}">${escapeHtml((c.protocol || '').toUpperCase())}</span>
                    <span class="highlight">${escapeHtml(c.count)} hits</span>
                </span>
            </div>
        `).join('');
        updateListIfChanged('top-protocol-country-list', html);
    }

    if (analytics.usernames) {
        const html = analytics.usernames.map(u => `
            <div class="list-item">
                <span><code>${escapeHtml(u.username)}</code> on <span class="badge ${escapeHtml(u.protocol)}">${escapeHtml((u.protocol || '').toUpperCase())}</span></span>
                <span class="highlight">${escapeHtml(u.count)} hits</span>
            </div>
        `).join('');
        updateListIfChanged('top-usernames-list', html);
    }

    if (analytics.netblocks) {
        const html = analytics.netblocks.map(n => `
            <div class="list-item">
                <span>${escapeHtml(n.as_name)}</span>
                <span class="highlight">${escapeHtml(n.count)} hits</span>
            </div>
        `).join('');
        updateListIfChanged('top-netblocks-list', html);
    }

    if (analytics.asn_company_types) {
        let html = '';
        if (analytics.asn_company_types.length === 0) {
            html = '<div class="list-item" style="color:var(--grey-text);">No ASN company classification data available yet.</div>';
        } else {
            html = analytics.asn_company_types.map(c => {
                let icon = '🏢';
                if (c.category.includes('Cloud')) icon = '☁️';
                if (c.category.includes('ISP')) icon = '🌐';
                if (c.category.includes('Crawler')) icon = '🕷️';
                if (c.category.includes('VPN')) icon = '🔒';
                if (c.category.includes('Education')) icon = '🎓';
                if (c.category.includes('Private')) icon = '🏠';

                const topASNsStr = c.top_asns && c.top_asns.length > 0 ? `(${c.top_asns.join(', ')})` : '';

                return `
                    <div class="list-item clickable-row" style="cursor:pointer;" onclick="openASNCategoryModal('${escapeHtml(c.category)}')">
                        <div>
                            <span style="font-weight:bold; color:#fff;">${icon} ${escapeHtml(c.category)}</span>
                            <span style="font-size:0.8rem; color:var(--grey-text); margin-left:6px;">${escapeHtml(topASNsStr)}</span>
                        </div>
                        <div>
                            <span class="highlight" style="margin-right:8px;">${escapeHtml(c.attack_count)} attacks</span>
                            <span class="badge" style="background:rgba(0,210,255,0.1); color:#00d2ff;">${escapeHtml(c.unique_ips)} IPs (${escapeHtml(c.percentage)}%) &rsaquo;</span>
                        </div>
                    </div>
                `;
            }).join('');
        }
        updateListIfChanged('asn-company-type-list', html);
    }
}

function renderCredRow(c) {
    const tooltip = escapeHtml(`${c.as_name || 'Unknown Owner'}\n${c.asn || 'No ASN'}`);
    const proto = escapeHtml((c.protocol || '').toUpperCase());
    const ip = escapeHtml(c.remote_ip || '-');
    const user = escapeHtml(c.username || '-');
    const pass = escapeHtml(c.password || '-');
    const dateStr = formatDate(c.created_at);
    return `
        <tr data-cred-id="${escapeHtml(c.id)}">
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${dateStr}</td>
            <td><span class="sensor-tag">${escapeHtml(c.sensor_id || 'local')}</span></td>
            <td><span class="badge ${escapeHtml((c.protocol || '').toLowerCase())}">${proto}</span></td>
            <td><span class="country-badge" title="${escapeHtml(c.country_name || '')}">${getFlagEmoji(c.country_code)} ${escapeHtml(c.country_code || '??')}</span></td>
            <td><span class="host-link" data-tooltip="${tooltip}" onclick="navigateToHost('${ip}')">${ip}</span></td>
            <td><code>${user}</code></td>
            <td><code>${pass}</code></td>
        </tr>
    `;
}

function renderCredsTable(creds) {
    const body = document.getElementById('creds-body');
    if (!body) return;

    if (creds && creds.length > 0) {
        body.innerHTML = creds.map(renderCredRow).join('');
    } else {
        body.innerHTML = '<tr><td colspan="7" style="text-align:center;">No credentials captured</td></tr>';
    }
}

function renderScanRow(s) {
    const ip = escapeHtml(s.remote_ip || '-');
    const sensor = escapeHtml(s.sensor_id || 'local');
    const methodPath = escapeHtml(s.method_path || 'UNKNOWN');
    const userAgent = escapeHtml(s.user_agent || 'Unknown');
    const dateStr = formatDate(s.created_at);
    const sId = encodeURIComponent(s.id);
    const sIdAttr = escapeHtml(s.id);
    return `
        <tr data-scan-id="${sIdAttr}">
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${dateStr}</td>
            <td><span class="sensor-tag">${sensor}</span></td>
            <td><span class="host-link" onclick="navigateToHost('${ip}')">${ip}</span></td>
            <td><span class="badge web"><code>${methodPath}</code></span></td>
            <td style="font-size:0.85rem;color:rgba(255,255,255,0.7);word-break:break-word;">${userAgent}</td>
            <td class="action-cell">
                <div class="table-actions-group">
                    <button type="button" class="action-btn inspect-btn" onclick="openRequestInspector(${sId})" title="Inspect Raw Payload, Hex Dump & ASCII">🔍</button>
                    <div class="dropdown-download">
                        <button type="button" class="action-btn download-btn" onclick="toggleDownloadMenu(event, 'scan-${sIdAttr}')" title="Download Request Payload">📥</button>
                        <div id="dl-menu-scan-${sIdAttr}" class="download-dropdown-content" style="display:none;">
                            <a href="javascript:void(0)" onclick="downloadRequest(${sId}, 'raw')">💾 Raw Binary (.bin)</a>
                            <a href="javascript:void(0)" onclick="downloadRequest(${sId}, 'hex')">🔢 Hex Dump (.hex)</a>
                            <a href="javascript:void(0)" onclick="downloadRequest(${sId}, 'ascii')">🔤 Safe ASCII (.txt)</a>
                            <a href="javascript:void(0)" onclick="downloadRequest(${sId}, 'base64')">📦 Base64 (.b64)</a>
                        </div>
                    </div>
                </div>
            </td>
        </tr>
    `;
}

function renderScansTable(scans) {
    const body = document.getElementById('scans-body');
    if (!body) return;

    if (scans && scans.length > 0) {
        body.innerHTML = scans.map(renderScanRow).join('');
    } else {
        body.innerHTML = '<tr><td colspan="6" style="text-align:center;">No web activity captured</td></tr>';
    }
}

function resetHostDOMToLoading(ip) {
    lastRenderedHostIp = ip;
    currentHostData = null;

    const ipElem = document.getElementById('detail-ip');
    if (ipElem) ipElem.textContent = ip;

    const badge = document.getElementById('detail-country-badge');
    if (badge) {
        badge.textContent = '🌐 Resolving geolocation...';
        badge.title = '';
    }

    const countElem = document.getElementById('detail-count');
    if (countElem) countElem.textContent = '...';

    const netElem = document.getElementById('detail-network');
    if (netElem) netElem.textContent = 'Resolving ASN...';

    const ownerElem = document.getElementById('detail-owner');
    if (ownerElem) ownerElem.textContent = 'Resolving organization...';

    const typeElem = document.getElementById('detail-company-type');
    if (typeElem) typeElem.style.display = 'none';

    // Clear all 5 table bodies with loading indicators for this host
    const secBody = document.getElementById('detail-secondary-body');
    if (secBody) secBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:18px; color:var(--cyan-glow);">⏳ Loading secondary attack payload mentions for ${escapeHtml(ip)}...</td></tr>`;

    const credsBody = document.getElementById('detail-creds-body');
    if (credsBody) credsBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:18px; color:var(--cyan-glow);">⏳ Loading captured credentials for ${escapeHtml(ip)}...</td></tr>`;

    const cmdBody = document.getElementById('detail-commands-body');
    if (cmdBody) cmdBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:18px; color:var(--cyan-glow);">⏳ Loading executed commands for ${escapeHtml(ip)}...</td></tr>`;

    const webBody = document.getElementById('detail-web-body');
    if (webBody) webBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:18px; color:var(--cyan-glow);">⏳ Loading web scans for ${escapeHtml(ip)}...</td></tr>`;

    // Reset pagination counters
    ['secondary', 'creds', 'commands', 'web'].forEach(sec => {
        const info = document.getElementById(`info-host-${sec}`);
        if (info) info.textContent = 'Loading...';
        const prev = document.getElementById(`btn-prev-host-${sec}`);
        if (prev) prev.disabled = true;
        const next = document.getElementById(`btn-next-host-${sec}`);
        if (next) next.disabled = true;
    });

    pagination.hostSecondary.page = 1;
    pagination.hostSecondary.filteredData = [];
    pagination.hostCreds.page = 1;
    pagination.hostCreds.filteredData = [];
    pagination.hostCommands.page = 1;
    pagination.hostCommands.filteredData = [];
    pagination.hostWeb.page = 1;
    pagination.hostWeb.filteredData = [];
}

async function showHostDetails(ip, updateHash = true, isSilent = false) {
    if (!ip) return;
    const cleanIp = String(ip).trim();
    currentHostIp = cleanIp;

    if (currentHostFetchController) {
        currentHostFetchController.abort();
    }
    currentHostFetchController = new AbortController();

    const navBtn = document.getElementById('nav-host-details');
    if (navBtn) {
        navBtn.style.display = 'inline-block';
        navBtn.textContent = `🎯 Host: ${cleanIp}`;
        navBtn.classList.add('active');
    }

    if (!isSilent && lastRenderedHostIp !== cleanIp) {
        resetHostDOMToLoading(cleanIp);
    }

    isHostSwitching = true;
    switchTab('host-details', false);
    isHostSwitching = false;

    if (updateHash) {
        const targetHash = `host-details?ip=${encodeURIComponent(cleanIp)}`;
        if (window.location.hash !== `#${targetHash}`) {
            history.pushState(null, '', `#${targetHash}`);
        }
    }

    try {
        const queryParam = currentSensor !== 'all' ? `?sensor=${encodeURIComponent(currentSensor)}` : '';
        const res = await fetch(`/api/host/${encodeURIComponent(cleanIp)}${queryParam}`, {
            signal: currentHostFetchController.signal
        });
        if (!res.ok) {
            throw new Error(`Server returned HTTP ${res.status}`);
        }
        const data = await res.json();
        if (currentHostIp !== cleanIp) return;
        currentHostData = data;
        renderHostPage(data);
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Failed to fetch host details for', cleanIp, err);
        if (currentHostIp === cleanIp) {
            const badge = document.getElementById('detail-country-badge');
            if (badge) badge.textContent = '⚠️ Error loading host data';
            ['detail-secondary-body', 'detail-creds-body', 'detail-commands-body', 'detail-web-body'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--accent-red); padding:15px;">⚠️ Failed to load records for ${escapeHtml(cleanIp)}: ${escapeHtml(err.message || 'Network error')}</td></tr>`;
            });
        }
    }
}

function renderHostSecondaryRow(m) {
    const attLink = (m.attacker_ip && m.attacker_ip !== 'Secondary Target') ?
        `<span class="host-link" onclick="navigateToHost('${escapeHtml(m.attacker_ip)}')" title="Click to view primary attacker host">${escapeHtml(m.attacker_ip)}</span>` :
        `<span style="color:var(--grey-text); font-style:italic;">${escapeHtml(m.attacker_ip || '-')}</span>`;
    const secKey = `${m.created_at}_${m.attacker_ip}`;

    return `
        <tr data-sec-key="${escapeHtml(secKey)}">
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${formatDate(m.created_at)}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.05); color:#fff;">${escapeHtml(m.sensor_id || 'local')}</span></td>
            <td><span class="badge ${escapeHtml(m.protocol || 'ssh')}">${escapeHtml((m.protocol || 'SHELL').toUpperCase())}</span></td>
            <td>${attLink}</td>
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.84rem; color:#fff; word-break:break-all; white-space:pre-wrap;">${escapeHtml(m.full_command)}</td>
        </tr>
    `;
}

function renderHostSecondaryTable(isSilent = false) {
    const secBody = document.getElementById('detail-secondary-body');
    const infoSec = document.getElementById('info-host-secondary');
    const btnPrevSec = document.getElementById('btn-prev-host-secondary');
    const btnNextSec = document.getElementById('btn-next-host-secondary');
    if (!secBody) return;

    const data = pagination.hostSecondary.filteredData || [];
    const pageSize = pagination.hostSecondary.pageSize;
    let pageItems = data;
    let totalPages = 1;

    if (pageSize !== 'all') {
        const size = parseInt(pageSize, 10) || 10;
        totalPages = Math.ceil(data.length / size) || 1;
        if (pagination.hostSecondary.page > totalPages) {
            pagination.hostSecondary.page = totalPages;
        }
        const start = (pagination.hostSecondary.page - 1) * size;
        pageItems = data.slice(start, start + size);
    }

    if (infoSec) infoSec.textContent = `Page ${pagination.hostSecondary.page} of ${totalPages} (${data.length} total)`;
    if (btnPrevSec) btnPrevSec.disabled = pagination.hostSecondary.page <= 1;
    if (btnNextSec) btnNextSec.disabled = pageSize === 'all' || pagination.hostSecondary.page >= totalPages;

    if (pageItems.length > 0) {
        secBody.innerHTML = pageItems.map(renderHostSecondaryRow).join('');
    } else {
        secBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--grey-text);">No secondary attack infrastructure payload mentions recorded for this host.</td></tr>';
    }
}

function renderHostCredRow(c) {
    return `
        <tr data-cred-id="${escapeHtml(c.id)}">
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${formatDate(c.created_at)}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.05); color:#fff;">${escapeHtml(c.sensor_id || 'local')}</span></td>
            <td><span class="badge ${escapeHtml(c.protocol)}">${escapeHtml((c.protocol || '').toUpperCase())}</span></td>
            <td><code style="color:#2ecc71; font-weight:bold;">${escapeHtml(c.username)}</code></td>
            <td><code style="color:#ff7800;">${escapeHtml(c.password)}</code></td>
        </tr>
    `;
}

function renderHostCredsTable(isSilent = false) {
    const credsBody = document.getElementById('detail-creds-body');
    const infoCreds = document.getElementById('info-host-creds');
    const btnPrevCreds = document.getElementById('btn-prev-host-creds');
    const btnNextCreds = document.getElementById('btn-next-host-creds');
    if (!credsBody) return;

    const data = pagination.hostCreds.filteredData || [];
    const pageSize = pagination.hostCreds.pageSize;
    let pageItems = data;
    let totalPages = 1;

    if (pageSize !== 'all') {
        const size = parseInt(pageSize, 10) || 10;
        totalPages = Math.ceil(data.length / size) || 1;
        if (pagination.hostCreds.page > totalPages) {
            pagination.hostCreds.page = totalPages;
        }
        const start = (pagination.hostCreds.page - 1) * size;
        pageItems = data.slice(start, start + size);
    }

    if (infoCreds) infoCreds.textContent = `Page ${pagination.hostCreds.page} of ${totalPages} (${data.length} total)`;
    if (btnPrevCreds) btnPrevCreds.disabled = pagination.hostCreds.page <= 1;
    if (btnNextCreds) btnNextCreds.disabled = pageSize === 'all' || pagination.hostCreds.page >= totalPages;

    if (pageItems.length > 0) {
        credsBody.innerHTML = pageItems.map(renderHostCredRow).join('');
    } else {
        credsBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--grey-text);">No credentials captured from this IP.</td></tr>';
    }
}

function renderHostCommandRow(cmd) {
    return `
        <tr data-cmd-id="${escapeHtml(cmd.id)}">
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${formatDate(cmd.created_at)}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.05); color:#fff;">${escapeHtml(cmd.sensor_id || 'local')}</span></td>
            <td><span class="badge ${escapeHtml(cmd.protocol)}">${escapeHtml((cmd.protocol || '').toUpperCase())}</span></td>
            <td><code style="color:#2ecc71;">${escapeHtml(cmd.username || '-')}</code></td>
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:#fff; word-break:break-all; white-space:pre-wrap;">${escapeHtml(cmd.command)}</td>
        </tr>
    `;
}

function renderHostCommandsTable(isSilent = false) {
    const commandsBody = document.getElementById('detail-commands-body');
    const infoCmd = document.getElementById('info-host-commands');
    const btnPrevCmd = document.getElementById('btn-prev-host-commands');
    const btnNextCmd = document.getElementById('btn-next-host-commands');
    if (!commandsBody) return;

    const data = pagination.hostCommands.filteredData || [];
    const pageSize = pagination.hostCommands.pageSize;
    let pageItems = data;
    let totalPages = 1;

    if (pageSize !== 'all') {
        const size = parseInt(pageSize, 10) || 10;
        totalPages = Math.ceil(data.length / size) || 1;
        if (pagination.hostCommands.page > totalPages) {
            pagination.hostCommands.page = totalPages;
        }
        const start = (pagination.hostCommands.page - 1) * size;
        pageItems = data.slice(start, start + size);
    }

    if (infoCmd) infoCmd.textContent = `Page ${pagination.hostCommands.page} of ${totalPages} (${data.length} total)`;
    if (btnPrevCmd) btnPrevCmd.disabled = pagination.hostCommands.page <= 1;
    if (btnNextCmd) btnNextCmd.disabled = pageSize === 'all' || pagination.hostCommands.page >= totalPages;

    if (pageItems.length > 0) {
        commandsBody.innerHTML = pageItems.map(renderHostCommandRow).join('');
    } else {
        commandsBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--grey-text);">No executed shell or PLC commands from this IP.</td></tr>';
    }
}

function renderHostWebRow(w) {
    const wId = encodeURIComponent(w.id);
    const wIdAttr = escapeHtml(w.id);
    return `
        <tr data-web-id="${wIdAttr}">
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${formatDate(w.created_at)}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.05); color:#fff;">${escapeHtml(w.sensor_id || 'local')}</span></td>
            <td><span class="badge web"><code>${escapeHtml(w.method_path)}</code></span></td>
            <td style="font-size:0.8rem; color:var(--grey-text); word-break:break-word;">${escapeHtml(w.user_agent || '-')}</td>
            <td class="action-cell">
                <div class="table-actions-group">
                    <button type="button" class="action-btn inspect-btn" onclick="openRequestInspector(${wId})" title="Inspect Raw Payload, Hex Dump & ASCII">🔍</button>
                    <div class="dropdown-download">
                        <button type="button" class="action-btn download-btn" onclick="toggleDownloadMenu(event, 'host-web-${wIdAttr}')" title="Download Request Payload">📥</button>
                        <div id="dl-menu-host-web-${wIdAttr}" class="download-dropdown-content" style="display:none;">
                            <a href="javascript:void(0)" onclick="downloadRequest(${wId}, 'raw')">💾 Raw Binary (.bin)</a>
                            <a href="javascript:void(0)" onclick="downloadRequest(${wId}, 'hex')">🔢 Hex Dump (.hex)</a>
                            <a href="javascript:void(0)" onclick="downloadRequest(${wId}, 'ascii')">🔤 Safe ASCII (.txt)</a>
                            <a href="javascript:void(0)" onclick="downloadRequest(${wId}, 'base64')">📦 Base64 (.b64)</a>
                        </div>
                    </div>
                </div>
            </td>
        </tr>
    `;
}

function renderHostWebTable(isSilent = false) {
    const webBody = document.getElementById('detail-web-body');
    const infoWeb = document.getElementById('info-host-web');
    const btnPrevWeb = document.getElementById('btn-prev-host-web');
    const btnNextWeb = document.getElementById('btn-next-host-web');
    if (!webBody) return;

    const data = pagination.hostWeb.filteredData || [];
    const pageSize = pagination.hostWeb.pageSize;
    let pageItems = data;
    let totalPages = 1;

    if (pageSize !== 'all') {
        const size = parseInt(pageSize, 10) || 10;
        totalPages = Math.ceil(data.length / size) || 1;
        if (pagination.hostWeb.page > totalPages) {
            pagination.hostWeb.page = totalPages;
        }
        const start = (pagination.hostWeb.page - 1) * size;
        pageItems = data.slice(start, start + size);
    }

    if (infoWeb) infoWeb.textContent = `Page ${pagination.hostWeb.page} of ${totalPages} (${data.length} total)`;
    if (btnPrevWeb) btnPrevWeb.disabled = pagination.hostWeb.page <= 1;
    if (btnNextWeb) btnNextWeb.disabled = pageSize === 'all' || pagination.hostWeb.page >= totalPages;

    if (pageItems.length > 0) {
        webBody.innerHTML = pageItems.map(renderHostWebRow).join('');
    } else {
        webBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--grey-text);">No HTTP web scans from this IP.</td></tr>';
    }
}

function renderHostPage(data, isSilent = false) {
    document.getElementById('detail-ip').textContent = data.ip || '-';
    const badge = document.getElementById('detail-country-badge');
    if (badge) {
        badge.textContent = `${getFlagEmoji(data.country_code)} ${data.country_name || 'Unknown'}`;
        badge.title = data.country_code || '';
    }

    const countElem = document.getElementById('detail-count');
    if (countElem) countElem.textContent = data.attempts_count || 0;
    const netElem = document.getElementById('detail-network');
    if (netElem) netElem.textContent = data.asn || 'Unknown ASN';
    const ownerElem = document.getElementById('detail-owner');
    if (ownerElem) ownerElem.textContent = data.as_name || 'Unknown Organization';
    const typeElem = document.getElementById('detail-company-type');
    if (typeElem) {
        if (data.asn_type) {
            let icon = '🏢';
            if (data.asn_type.includes('Cloud')) icon = '☁️';
            if (data.asn_type.includes('ISP')) icon = '🌐';
            if (data.asn_type.includes('VPN')) icon = '🔒';
            if (data.asn_type.includes('Education')) icon = '🎓';
            if (data.asn_type.includes('Private')) icon = '🏠';
            typeElem.textContent = `${icon} ${data.asn_type}`;
            typeElem.style.display = 'inline-block';
        } else {
            typeElem.style.display = 'none';
        }
    }

    if (lastRenderedHostIp !== data.ip) {
        lastRenderedHostIp = data.ip;
        pagination.hostSecondary.page = 1;
        pagination.hostCreds.page = 1;
        pagination.hostCommands.page = 1;
        pagination.hostWeb.page = 1;
    }

    pagination.hostSecondary.filteredData = data.secondary_attack_mentions || [];
    pagination.hostCreds.filteredData = data.credentials || [];
    pagination.hostCommands.filteredData = data.commands || [];
    pagination.hostWeb.filteredData = data.web_requests || [];

    renderHostSecondaryTable(isSilent);
    renderHostCredsTable(isSilent);
    renderHostCommandsTable(isSilent);
    renderHostWebTable(isSilent);
}

function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode === '??' || countryCode === 'LCL' || countryCode === 'UN') {
        return '🏴‍☠️';
    }
    return countryCode.toUpperCase().replace(/./g, char => 
        String.fromCodePoint(char.charCodeAt(0) + 127397)
    );
}

function exportLogs() {
    const service = document.getElementById('export-service-select').value;
    const queryParam = currentSensor !== 'all' ? `&sensor=${encodeURIComponent(currentSensor)}` : '';
    window.open(`/api/logs/export?service=${service}${queryParam}`, '_blank');
}

// --- Activity Log CSV Export Utilities ---
function downloadCSV(filename, headers, rows) {
    const escapeCSV = (val) => {
        if (val === null || val === undefined) return '""';
        let str = String(val);
        if (/^[=+\-@\t\r]/.test(str)) {
            str = "'" + str;
        }
        if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
            str = '"' + str.replace(/"/g, '""') + '"';
        }
        return str;
    };

    const csvContent = [
        headers.map(escapeCSV).join(','),
        ...rows.map(row => row.map(escapeCSV).join(','))
    ].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function downloadRawCSV(filename, csvContent) {
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function downloadJSON(filename, dataObj) {
    const jsonStr = JSON.stringify(dataObj, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// --- Host Details Export Handlers ---

function exportHostAllJSON() {
    if (!currentHostData) {
        alert('No host data loaded to export.');
        return;
    }
    const ip = currentHostData.ip || currentHostIp || 'unknown';
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const sensorTag = currentSensor !== 'all' ? `_${currentSensor}` : '';
    const filename = `honeygo_host_${ip}_full_profile${sensorTag}_${ts}.json`;
    downloadJSON(filename, currentHostData);
}

function exportHostAllCSV() {
    if (!currentHostData) {
        alert('No host data loaded to export.');
        return;
    }
    const d = currentHostData;
    const ip = d.ip || currentHostIp || 'unknown';
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const sensorTag = currentSensor !== 'all' ? `_${currentSensor}` : '';
    const filename = `honeygo_host_${ip}_full_profile${sensorTag}_${ts}.csv`;

    const escapeCSV = (val) => {
        if (val === null || val === undefined) return '""';
        let str = String(val);
        if (/^[=+\-@\t\r]/.test(str)) {
            str = "'" + str;
        }
        if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
            str = '"' + str.replace(/"/g, '""') + '"';
        }
        return str;
    };

    const lines = [];
    lines.push(['=== HONEYGO HOST THREAT PROFILE ==='].map(escapeCSV).join(','));
    lines.push(['Target IP', ip].map(escapeCSV).join(','));
    lines.push(['Country', `${d.country_name || 'Unknown'} (${d.country_code || '??'})`].map(escapeCSV).join(','));
    lines.push(['Network / ASN', d.asn || 'Unknown ASN'].map(escapeCSV).join(','));
    lines.push(['Netblock Owner', d.as_name || 'Unknown Organization'].map(escapeCSV).join(','));
    lines.push(['Infrastructure Type', d.asn_type || 'Unknown'].map(escapeCSV).join(','));
    lines.push(['Total Interactions', d.attempts_count || (d.attempts ? d.attempts.length : 0)].map(escapeCSV).join(','));
    lines.push(['Sensor Scope', currentSensor].map(escapeCSV).join(','));
    lines.push(['Generated At', new Date().toISOString()].map(escapeCSV).join(','));
    lines.push('');

    // 1. Secondary Attack Infrastructure
    lines.push(['=== 1. SECONDARY ATTACK INFRASTRUCTURE & PAYLOAD MENTIONS ==='].map(escapeCSV).join(','));
    const secHeaders = ['Timestamp', 'Sensor', 'Protocol', 'Primary Attacker Host', 'Full Command Payload', 'Source Type'];
    lines.push(secHeaders.map(escapeCSV).join(','));
    (d.secondary_attack_mentions || []).forEach(m => {
        lines.push([
            formatDate(m.created_at),
            m.sensor_id || 'local',
            (m.protocol || 'SHELL').toUpperCase(),
            m.attacker_ip || '-',
            m.full_command || '',
            m.source_type || ''
        ].map(escapeCSV).join(','));
    });
    lines.push('');

    // 2. Captured Credentials
    lines.push(['=== 2. CAPTURED CREDENTIALS ==='].map(escapeCSV).join(','));
    const credHeaders = ['Timestamp', 'Sensor', 'Protocol', 'Remote IP', 'Username', 'Password'];
    lines.push(credHeaders.map(escapeCSV).join(','));
    (d.credentials || []).forEach(c => {
        lines.push([
            formatDate(c.created_at),
            c.sensor_id || 'local',
            (c.protocol || '').toUpperCase(),
            ip,
            c.username || '',
            c.password || ''
        ].map(escapeCSV).join(','));
    });
    // 3. Executed Shell & PLC Commands
    lines.push(['=== 3. EXECUTED SHELL & PLC COMMANDS ==='].map(escapeCSV).join(','));
    const cmdHeaders = ['Timestamp', 'Sensor', 'Protocol', 'Remote IP', 'User', 'Executed Command / Function Code'];
    lines.push(cmdHeaders.map(escapeCSV).join(','));
    (d.commands || []).forEach(cmd => {
        lines.push([
            formatDate(cmd.created_at),
            cmd.sensor_id || 'local',
            (cmd.protocol || '').toUpperCase(),
            ip,
            cmd.username || '-',
            cmd.command || ''
        ].map(escapeCSV).join(','));
    });
    lines.push('');

    // 4. Web Requests & HTTP Scans
    lines.push(['=== 4. WEB REQUESTS & HTTP SCANS ==='].map(escapeCSV).join(','));
    const webHeaders = ['Timestamp', 'Sensor', 'Remote IP', 'Port', 'Method & Path', 'User-Agent', 'Custom Headers', 'Payload Size (Bytes)'];
    lines.push(webHeaders.map(escapeCSV).join(','));
    (d.web_requests || []).forEach(w => {
        lines.push([
            formatDate(w.created_at),
            w.sensor_id || 'local',
            ip,
            w.port || 80,
            w.method_path || '',
            w.user_agent || '',
            w.custom_headers || '',
            w.size_bytes || 0
        ].map(escapeCSV).join(','));
    });

    downloadRawCSV(filename, lines.join('\r\n'));
}

function exportHostSecondaryMentionsCSV() {
    if (!currentHostData) {
        alert('No host data loaded to export.');
        return;
    }
    const ip = currentHostData.ip || currentHostIp || 'unknown';
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const sensorTag = currentSensor !== 'all' ? `_${currentSensor}` : '';
    const filename = `honeygo_host_${ip}_secondary_mentions${sensorTag}_${ts}.csv`;
    const headers = ['Timestamp', 'Sensor', 'Protocol', 'Primary Attacker Host', 'Full Command Payload', 'Source Type'];
    const rows = (currentHostData.secondary_attack_mentions || []).map(m => [
        formatDate(m.created_at),
        m.sensor_id || 'local',
        (m.protocol || 'SHELL').toUpperCase(),
        m.attacker_ip || '-',
        m.full_command || '',
        m.source_type || ''
    ]);
    downloadCSV(filename, headers, rows);
}

function exportHostCredentialsCSV() {
    if (!currentHostData) {
        alert('No host data loaded to export.');
        return;
    }
    const ip = currentHostData.ip || currentHostIp || 'unknown';
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const sensorTag = currentSensor !== 'all' ? `_${currentSensor}` : '';
    const filename = `honeygo_host_${ip}_credentials${sensorTag}_${ts}.csv`;
    const headers = ['Timestamp', 'Sensor', 'Protocol', 'Remote IP', 'Username', 'Password'];
    const rows = (currentHostData.credentials || []).map(c => [
        formatDate(c.created_at),
        c.sensor_id || 'local',
        (c.protocol || '').toUpperCase(),
        ip,
        c.username || '',
        c.password || ''
    ]);
    downloadCSV(filename, headers, rows);
}

function exportHostCommandsCSV() {
    if (!currentHostData) {
        alert('No host data loaded to export.');
        return;
    }
    const ip = currentHostData.ip || currentHostIp || 'unknown';
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const sensorTag = currentSensor !== 'all' ? `_${currentSensor}` : '';
    const filename = `honeygo_host_${ip}_commands${sensorTag}_${ts}.csv`;
    const headers = ['Timestamp', 'Sensor', 'Protocol', 'Remote IP', 'Username', 'Command / Function Code'];
    const rows = (currentHostData.commands || []).map(cmd => [
        formatDate(cmd.created_at),
        cmd.sensor_id || 'local',
        (cmd.protocol || '').toUpperCase(),
        ip,
        cmd.username || '-',
        cmd.command || ''
    ]);
    downloadCSV(filename, headers, rows);
}

function exportHostWebRequestsCSV() {
    if (!currentHostData) {
        alert('No host data loaded to export.');
        return;
    }
    const ip = currentHostData.ip || currentHostIp || 'unknown';
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const sensorTag = currentSensor !== 'all' ? `_${currentSensor}` : '';
    const filename = `honeygo_host_${ip}_web_requests${sensorTag}_${ts}.csv`;
    const headers = ['Timestamp', 'Sensor', 'Remote IP', 'Port', 'Method & Path', 'User-Agent', 'Custom Headers', 'Payload Size (Bytes)'];
    const rows = (currentHostData.web_requests || []).map(w => [
        formatDate(w.created_at),
        w.sensor_id || 'local',
        ip,
        w.port || 80,
        w.method_path || '',
        w.user_agent || '',
        w.custom_headers || '',
        w.size_bytes || 0
    ]);
    downloadCSV(filename, headers, rows);
}

function hasCredsFilter() {
    const credFilter = document.getElementById('filter-creds');
    return Boolean(credFilter && credFilter.value.trim() !== '');
}

function updateCredsExportBtnState() {
    const btn = document.getElementById('export-creds-filter-btn');
    if (!btn) return;
    const hasFilter = hasCredsFilter();
    btn.disabled = !hasFilter;
    if (hasFilter) {
        btn.classList.remove('disabled');
        btn.title = "Export filtered credentials matching search criteria to CSV";
    } else {
        btn.classList.add('disabled');
        btn.title = "Enter search criteria to enable filtered export";
    }
}

function hasScansFilter() {
    const scanFilter = document.getElementById('filter-scans');
    return Boolean(scanFilter && scanFilter.value.trim() !== '');
}

function updateScansExportBtnState() {
    const btn = document.getElementById('export-scans-filter-btn');
    if (!btn) return;
    const hasFilter = hasScansFilter();
    btn.disabled = !hasFilter;
    if (hasFilter) {
        btn.classList.remove('disabled');
        btn.title = "Export filtered web scans matching search criteria to CSV";
    } else {
        btn.classList.add('disabled');
        btn.title = "Enter search criteria to enable filtered export";
    }
}

function hasCommandsFilter() {
    const cmdFilter = document.getElementById('filter-commands');
    return Boolean(cmdFilter && cmdFilter.value.trim() !== '');
}

function updateCommandsExportBtnState() {
    const btn = document.getElementById('export-commands-filter-btn');
    if (!btn) return;
    const hasFilter = hasCommandsFilter();
    btn.disabled = !hasFilter;
    if (hasFilter) {
        btn.classList.remove('disabled');
        btn.title = "Export filtered commands matching search criteria to CSV";
    } else {
        btn.classList.add('disabled');
        btn.title = "Enter search criteria to enable filtered export";
    }
}

function getCredsExportRows(credsList) {
    return (credsList || []).map(c => [
        formatDate(c.created_at),
        c.sensor_id || 'local',
        (c.protocol || '').toUpperCase(),
        c.country_code || '',
        c.country_name || '',
        c.asn || '',
        c.as_name || '',
        c.remote_ip || '',
        c.username || '',
        c.password || ''
    ]);
}

const CREDS_EXPORT_HEADERS = [
    'Timestamp', 'Sensor', 'Protocol', 'Country Code', 'Country Name', 'ASN', 'AS Name', 'Remote IP', 'Username', 'Password'
];

function exportCredsAll() {
    const sensorParam = currentSensor !== 'all' ? `&sensor=${encodeURIComponent(currentSensor)}` : '';
    window.open(`/api/credentials?format=csv${sensorParam}`, '_blank');
}

function exportCredsFiltered() {
    const qVal = document.getElementById('filter-creds')?.value.trim() || '';
    if (!qVal) {
        alert('Export Filter requires search criteria to be entered.');
        return;
    }
    const sensorParam = currentSensor !== 'all' ? `&sensor=${encodeURIComponent(currentSensor)}` : '';
    const qParam = `&q=${encodeURIComponent(qVal)}`;
    window.open(`/api/credentials?format=csv${sensorParam}${qParam}`, '_blank');
}

function getScansExportRows(scansList) {
    return (scansList || []).map(s => [
        formatDate(s.created_at),
        s.sensor_id || 'local',
        s.remote_ip || '',
        s.method_path || '',
        s.user_agent || '',
        s.custom_headers || ''
    ]);
}

const SCANS_EXPORT_HEADERS = [
    'Timestamp', 'Sensor', 'Remote IP', 'Method & Path', 'User-Agent', 'Custom Headers'
];

function exportScansAll() {
    const sensorParam = currentSensor !== 'all' ? `&sensor=${encodeURIComponent(currentSensor)}` : '';
    window.open(`/api/scans?format=csv${sensorParam}`, '_blank');
}

function exportScansFiltered() {
    const qVal = document.getElementById('filter-scans')?.value.trim() || '';
    if (!qVal) {
        alert('Export Filter requires search criteria to be entered.');
        return;
    }
    const sensorParam = currentSensor !== 'all' ? `&sensor=${encodeURIComponent(currentSensor)}` : '';
    const qParam = `&q=${encodeURIComponent(qVal)}`;
    window.open(`/api/scans?format=csv${sensorParam}${qParam}`, '_blank');
}

function getCommandsExportRows(commandsList) {
    return (commandsList || []).map(cmd => [
        formatDate(cmd.created_at),
        cmd.sensor_id || 'local',
        (cmd.protocol || '').toUpperCase(),
        cmd.country_code || '',
        cmd.country_name || '',
        cmd.asn || '',
        cmd.as_name || '',
        cmd.remote_ip || '',
        cmd.username || '',
        cmd.command || ''
    ]);
}

const COMMANDS_EXPORT_HEADERS = [
    'Timestamp', 'Sensor', 'Protocol', 'Country Code', 'Country Name', 'ASN', 'AS Name', 'Remote IP', 'Username', 'Command'
];

function exportCommandsAll() {
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const sensorTag = currentSensor !== 'all' ? `_${currentSensor}` : '';
    const filename = `honeygo_commands_all${sensorTag}_${ts}.csv`;
    const rows = getCommandsExportRows(allCommands);
    downloadCSV(filename, COMMANDS_EXPORT_HEADERS, rows);
}

function exportCommandsFiltered() {
    if (!hasCommandsFilter()) {
        alert('Export Filter requires search criteria to be entered.');
        return;
    }
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const sensorTag = currentSensor !== 'all' ? `_${currentSensor}` : '';
    const filename = `honeygo_commands_filtered${sensorTag}_${ts}.csv`;
    const filtered = pagination.commands.filteredData || [];
    const rows = getCommandsExportRows(filtered);
    downloadCSV(filename, COMMANDS_EXPORT_HEADERS, rows);
}

function renderCountryPage(data, isSilent = false) {
    if (!data) return;
    const nameElem = document.getElementById('country-detail-name');
    if (nameElem) nameElem.textContent = data.country_name || 'Unknown Country';
    const flagElem = document.getElementById('country-detail-flag');
    if (flagElem) flagElem.textContent = getFlagEmoji(data.country_code);
    const countElem = document.getElementById('country-detail-count');
    if (countElem) countElem.textContent = data.total || 0;

    let primaryService = 'None';
    if (data.protocols && data.protocols.length > 0) {
        const sorted = [...data.protocols].sort((a, b) => b.count - a.count);
        primaryService = `${sorted[0].protocol.toUpperCase()} (${sorted[0].count} hits)`;
    }
    const primElem = document.getElementById('country-detail-primary');
    if (primElem) primElem.textContent = primaryService;

    allCountryAttempts = data.attempts || [];

    if (!isSilent) {
        const ipFilter = document.getElementById('filter-country-ip');
        const protoFilter = document.getElementById('filter-country-protocol');
        if (ipFilter) ipFilter.value = "";
        if (protoFilter) protoFilter.value = "";
    }

    renderCountryAttemptsTable(allCountryAttempts, isSilent);
}

function resetCountryDOMToLoading(code) {
    lastRenderedCountryCode = code;
    currentCountryCode = code;
    const nameElem = document.getElementById('country-detail-name');
    if (nameElem) nameElem.textContent = `Loading ${code}...`;
    const flagElem = document.getElementById('country-detail-flag');
    if (flagElem) flagElem.textContent = getFlagEmoji(code);
    const countElem = document.getElementById('country-detail-count');
    if (countElem) countElem.textContent = '...';
    const primElem = document.getElementById('country-detail-primary');
    if (primElem) primElem.textContent = '...';

    const body = document.getElementById('country-attempts-body');
    if (body) body.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:18px; color:var(--cyan-glow);">⏳ Loading attempts for ${escapeHtml(code)}...</td></tr>`;

    const infoElem = document.getElementById('info-country');
    if (infoElem) infoElem.textContent = 'Loading...';
    const prevBtn = document.getElementById('btn-prev-country');
    if (prevBtn) prevBtn.disabled = true;
    const nextBtn = document.getElementById('btn-next-country');
    if (nextBtn) nextBtn.disabled = true;

    allCountryAttempts = [];
    pagination.countryAttempts.page = 1;
    pagination.countryAttempts.filteredData = [];
}

async function showCountryDetails(code, updateHash = true, isSilent = false) {
    if (!code) return;
    const cleanCode = String(code).trim();
    currentCountryCode = cleanCode;

    if (currentCountryFetchController) {
        currentCountryFetchController.abort();
    }
    currentCountryFetchController = new AbortController();

    const navBtn = document.getElementById('nav-country-details');
    if (navBtn) {
        navBtn.style.display = 'inline-block';
        navBtn.textContent = `🌐 Country: ${cleanCode}`;
        navBtn.classList.add('active');
    }

    if (!isSilent && lastRenderedCountryCode !== cleanCode) {
        resetCountryDOMToLoading(cleanCode);
    }

    isCountrySwitching = true;
    switchTab('country-details', false);
    isCountrySwitching = false;

    if (updateHash) {
        const targetHash = `country-details?code=${encodeURIComponent(cleanCode)}`;
        if (window.location.hash !== `#${targetHash}`) {
            history.pushState(null, '', `#${targetHash}`);
        }
    }

    try {
        const queryParam = currentSensor !== 'all' ? `?sensor=${encodeURIComponent(currentSensor)}` : '';
        const res = await fetch(`/api/country/${encodeURIComponent(cleanCode)}${queryParam}`, {
            signal: currentCountryFetchController.signal
        });
        if (!res.ok) {
            throw new Error(`Server returned HTTP ${res.status}`);
        }
        const data = await res.json();
        if (currentCountryCode === cleanCode) {
            renderCountryPage(data, isSilent);
        }
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error("Error fetching country details:", err);
        if (!isSilent) {
            const body = document.getElementById('country-attempts-body');
            if (body && currentCountryCode === cleanCode) {
                body.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--accent-red); padding:15px;">⚠️ Failed to load country data: ${escapeHtml(err.message)}</td></tr>`;
            }
        }
    }
}

function renderCountryAttemptRow(a) {
    const ip = escapeHtml(a.remote_ip || '-');
    const proto = escapeHtml((a.protocol || '').toUpperCase());
    const protoClass = escapeHtml((a.protocol || '').toLowerCase());
    return `
        <tr data-att-id="${escapeHtml(a.id)}">
            <td>${formatDate(a.created_at)}</td>
            <td><span class="host-link" onclick="navigateToHost('${ip}')">${ip}</span></td>
            <td><span class="badge ${protoClass}">${proto}</span></td>
            <td>${escapeHtml(a.port)}</td>
            <td><code>${escapeHtml(a.extra_info || '-')}</code></td>
        </tr>
    `;
}

function renderCountryAttemptsTable(attempts, isSilent = false) {
    const body = document.getElementById('country-attempts-body');
    const infoCountry = document.getElementById('info-country');
    const btnPrevCountry = document.getElementById('btn-prev-country');
    const btnNextCountry = document.getElementById('btn-next-country');
    if (!body) return;

    pagination.countryAttempts.filteredData = attempts || [];
    const data = pagination.countryAttempts.filteredData;
    const pageSize = pagination.countryAttempts.pageSize;
    let pageItems = data;
    let totalPages = 1;

    if (pageSize !== 'all') {
        const size = parseInt(pageSize, 10) || 25;
        totalPages = Math.ceil(data.length / size) || 1;
        if (pagination.countryAttempts.page > totalPages) {
            pagination.countryAttempts.page = totalPages;
        }
        const start = (pagination.countryAttempts.page - 1) * size;
        pageItems = data.slice(start, start + size);
    }

    if (infoCountry) infoCountry.textContent = `Page ${pagination.countryAttempts.page} of ${totalPages} (${data.length} total)`;
    if (btnPrevCountry) btnPrevCountry.disabled = pagination.countryAttempts.page <= 1;
    if (btnNextCountry) btnNextCountry.disabled = pageSize === 'all' || pagination.countryAttempts.page >= totalPages;

    if (pageItems.length > 0) {
        body.innerHTML = pageItems.map(renderCountryAttemptRow).join('');
    } else {
        body.innerHTML = '<tr><td colspan="5" style="text-align:center;">No attempts found</td></tr>';
    }
}

function initCountryFilters() {
    const ipFilter = document.getElementById('filter-country-ip');
    const protoFilter = document.getElementById('filter-country-protocol');

    const applyFilters = () => {
        const ipVal = ipFilter.value.toLowerCase().trim();
        const protoVal = protoFilter.value.toLowerCase().trim();

        const filtered = allCountryAttempts.filter(a => {
            const matchesIP = a.remote_ip.toLowerCase().includes(ipVal);
            const matchesProto = protoVal === "" || a.protocol.toLowerCase() === protoVal;
            return matchesIP && matchesProto;
        });

        renderCountryAttemptsTable(filtered);
    };

    if (ipFilter && protoFilter) {
        ipFilter.addEventListener('input', applyFilters);
        protoFilter.addEventListener('change', applyFilters);
    }
}


function renderCommandRow(c) {
    const proto = escapeHtml((c.protocol || 'shell').toUpperCase());
    const protoClass = escapeHtml((c.protocol || '').toLowerCase());
    const ip = escapeHtml(c.remote_ip || '-');
    const user = escapeHtml(c.username || '-');
    const cmd = escapeHtml(c.command || '-');
    const dateStr = c.created_at ? formatDate(c.created_at) : '-';
    return `
        <tr data-cmd-id="${escapeHtml(c.id)}">
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${dateStr}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.05); color:#fff;">${escapeHtml(c.sensor_id || 'local')}</span></td>
            <td><span class="badge ${protoClass}">${proto}</span></td>
            <td>
                <span class="host-link" onclick="navigateToHost('${ip}')">${ip}</span>
                <div style="font-size:0.75rem;color:rgba(255,255,255,0.5);margin-top:2px;">
                    ${getFlagEmoji(c.country_code)} ${escapeHtml(c.country_name || '')}
                </div>
            </td>
            <td><code style="color:#2ecc71;">${user}</code></td>
            <td><code class="terminal-cmd">${cmd}</code></td>
        </tr>
    `;
}

function renderCommandsTable(commands, isSilent = false, hasActiveFilter = false) {
    pagination.commands.filteredData = commands;
    const pageSize = pagination.commands.pageSize;
    let totalPages = 1;
    let paginated = commands;
    
    if (pageSize !== 'all') {
        const size = parseInt(pageSize, 10);
        totalPages = Math.ceil(commands.length / size) || 1;
        if (pagination.commands.page > totalPages) {
            pagination.commands.page = totalPages;
        }
        if (pagination.commands.page < 1) {
            pagination.commands.page = 1;
        }
        const start = (pagination.commands.page - 1) * size;
        paginated = commands.slice(start, start + size);
    }
    
    const infoCmd = document.getElementById('info-commands');
    if (infoCmd) infoCmd.textContent = `Page ${pagination.commands.page} of ${totalPages} (${commands.length} total)`;
    const btnPrev = document.getElementById('btn-prev-commands');
    if (btnPrev) btnPrev.disabled = pagination.commands.page <= 1;
    const btnNext = document.getElementById('btn-next-commands');
    if (btnNext) btnNext.disabled = pageSize === 'all' || pagination.commands.page >= totalPages;

    const body = document.getElementById('commands-body');
    if (!body) return;

    if (paginated && paginated.length > 0) {
        body.innerHTML = paginated.map(renderCommandRow).join('');
    } else {
        body.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:rgba(255,255,255,0.4);">No executed commands captured</td></tr>';
    }
}

function renderPopularCommands(popular) {
    const list = document.getElementById('popular-commands-list');
    if (!list) return;
    if (popular && popular.length > 0) {
        const html = popular.map(item => `
            <div class="list-item">
                <code class="terminal-cmd highlighted-cmd" title="${escapeHtml(item.command)}">${escapeHtml(item.command)}</code>
                <span class="highlight">${item.count} exec${item.count === 1 ? '' : 's'}</span>
            </div>
        `).join('');
        if (list.innerHTML !== html) {
            list.innerHTML = html;
        }
    } else {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:rgba(255,255,255,0.4);grid-column: 1 / -1;">No commands captured yet</div>';
    }
}

// CSS Configuration Panel Logic
let cartoTileLayer = null;
let currentCartoKey = localStorage.getItem('honeygo_carto_api_key') || '';

function getCartoTileUrl(key) {
    const trimmed = (key || '').trim();
    if (trimmed) {
        return `https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png?key=${encodeURIComponent(trimmed)}`;
    }
    return 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
}

function updateMapAPIKeyBadge(key) {
    const badge = document.getElementById('map-carto-key-badge');
    if (!badge) return;
    const trimmed = (key || '').trim();
    if (trimmed) {
        badge.style.background = 'rgba(51, 255, 51, 0.15)';
        badge.style.color = '#33ff33';
        badge.style.borderColor = '#33ff33';
        badge.textContent = '🔑 CARTO Key: Active';
        badge.title = 'CARTO Basemaps API key is active. Click to manage in CSS Configuration.';
    } else {
        badge.style.background = 'rgba(255, 145, 0, 0.15)';
        badge.style.color = '#ff9100';
        badge.style.borderColor = '#ff9100';
        badge.textContent = '🔑 CARTO Key: Not Configured';
        badge.title = 'Click to add CARTO Map API Key under CSS Configuration.';
    }
}

function updateCartoTileLayer(key) {
    currentCartoKey = (key || '').trim();
    updateMapAPIKeyBadge(currentCartoKey);
    const tileUrl = getCartoTileUrl(currentCartoKey);
    if (cartoTileLayer) {
        cartoTileLayer.setUrl(tileUrl);
    } else if (leafletMap && typeof L !== 'undefined') {
        cartoTileLayer = L.tileLayer(tileUrl, {
            attribution: '&copy; <a href="https://carto.com/">CARTO</a> | Honeygo Threat Intelligence Engine',
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(leafletMap);
    }
}

function navigateToCSSConfig() {
    switchTab('css-config');
    const input = document.getElementById('css-carto-key-input');
    if (input) {
        setTimeout(() => {
            input.focus();
            input.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 150);
    }
}

async function testCartoKey() {
    const input = document.getElementById('css-carto-key-input');
    const key = input ? input.value.trim() : '';
    const msg = document.getElementById('css-save-msg');
    const testBtn = document.getElementById('carto-test-btn');
    if (!key) {
        if (msg) {
            msg.textContent = '✗ Please enter a CARTO API key to test';
            msg.className = 'save-toast error';
            setTimeout(() => { if (msg.textContent.includes('CARTO')) msg.textContent = ''; }, 3000);
        }
        return;
    }

    if (testBtn) {
        testBtn.disabled = true;
        testBtn.textContent = 'Testing...';
    }

    try {
        const testUrl = `https://a.basemaps.cartocdn.com/dark_all/0/0/0.png?key=${encodeURIComponent(key)}`;
        const img = new Image();
        const testPromise = new Promise((resolve, reject) => {
            img.onload = () => resolve(true);
            img.onerror = () => reject(new Error('Failed to load tile with key'));
            setTimeout(() => reject(new Error('Timeout verifying tile')), 8000);
        });
        img.src = testUrl;
        await testPromise;

        if (msg) {
            msg.textContent = '✓ CARTO API Key Verified Successfully';
            msg.className = 'save-toast success';
            setTimeout(() => { if (msg.textContent.includes('CARTO')) msg.textContent = ''; }, 4000);
        }
    } catch (e) {
        if (msg) {
            msg.textContent = '✗ CARTO Key Verification Failed (Check key or network)';
            msg.className = 'save-toast error';
            setTimeout(() => { if (msg.textContent.includes('CARTO')) msg.textContent = ''; }, 4000);
        }
    } finally {
        if (testBtn) {
            testBtn.disabled = false;
            testBtn.textContent = 'Test Key';
        }
    }
}

function initCSSConfig() {
    updateMapAPIKeyBadge(currentCartoKey);
    loadCSSConfig();

    const toggle = document.getElementById('css-token-toggle');
    if (toggle) {
        toggle.addEventListener('change', () => {
            const tokenInput = document.getElementById('css-token-input');
            if (toggle.checked && !tokenInput.value) {
                generateToken();
            }
        });
    }
}

async function loadCSSConfig() {
    try {
        const res = await fetch('/api/css/config');
        if (!res.ok) return;
        const cfg = await res.json();
        
        const toggle = document.getElementById('css-token-toggle');
        const tokenInput = document.getElementById('css-token-input');
        const checkinTtlInput = document.getElementById('css-checkin-ttl-input');
        const cartoKeyInput = document.getElementById('css-carto-key-input');
        if (toggle) toggle.checked = cfg.token_auth_enabled;
        if (tokenInput) tokenInput.value = cfg.auth_token || '';
        if (checkinTtlInput) checkinTtlInput.value = cfg.sensor_checkin_ttl || 15;

        if (cfg.carto_api_key !== undefined) {
            const serverKey = (cfg.carto_api_key || '').trim();
            if (serverKey) {
                currentCartoKey = serverKey;
                localStorage.setItem('honeygo_carto_api_key', serverKey);
            }
        }
        if (cartoKeyInput) cartoKeyInput.value = currentCartoKey;
        updateCartoTileLayer(currentCartoKey);

        updateFeedURLs();
    } catch (err) {
        console.error('Failed to load CSS config:', err);
    }
}

async function saveCSSConfig() {
    const toggle = document.getElementById('css-token-toggle');
    const tokenInput = document.getElementById('css-token-input');
    const checkinTtlInput = document.getElementById('css-checkin-ttl-input');
    const cartoKeyInput = document.getElementById('css-carto-key-input');
    const msg = document.getElementById('css-save-msg');

    const ttlVal = checkinTtlInput ? parseInt(checkinTtlInput.value, 10) : 15;
    const cartoVal = cartoKeyInput ? cartoKeyInput.value.trim() : '';

    const payload = {
        token_auth_enabled: toggle ? toggle.checked : false,
        auth_token: tokenInput ? tokenInput.value.trim() : '',
        sensor_checkin_ttl: !isNaN(ttlVal) && ttlVal > 0 ? ttlVal : 15,
        carto_api_key: cartoVal
    };

    try {
        const res = await fetch('/api/css/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            currentCartoKey = cartoVal;
            localStorage.setItem('honeygo_carto_api_key', cartoVal);
            updateCartoTileLayer(cartoVal);

            msg.textContent = '✓ CSS Configuration Saved';
            msg.className = 'save-toast success';
            updateFeedURLs();
            setTimeout(() => { msg.textContent = ''; }, 3000);
        } else {
            msg.textContent = '✗ Error saving configuration';
            msg.className = 'save-toast error';
        }
    } catch (err) {
        msg.textContent = '✗ Connection Error';
        msg.className = 'save-toast error';
    }
}

function generateToken() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let token = '';
    for (let i = 0; i < 32; i++) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const tokenInput = document.getElementById('css-token-input');
    if (tokenInput) tokenInput.value = token;
}

function updateFeedURLs() {
    const origin = window.location.origin;
    const tokenInput = document.getElementById('css-token-input');
    const toggle = document.getElementById('css-token-toggle');
    
    let tokenParam = '';
    if (toggle && toggle.checked && tokenInput && tokenInput.value) {
        tokenParam = `?token=${encodeURIComponent(tokenInput.value.trim())}`;
    }

    const sensorParam = currentSensor !== 'all' ? (tokenParam ? `&sensor=${encodeURIComponent(currentSensor)}` : `?sensor=${encodeURIComponent(currentSensor)}`) : '';

    document.getElementById('url-json-feed').value = `${origin}/feed/json${tokenParam}${sensorParam}`;
    document.getElementById('url-taxii-feed').value = `${origin}/taxii2/${tokenParam}${sensorParam}`;
    document.getElementById('url-rss-feed').value = `${origin}/feed/rss${tokenParam}${sensorParam}`;
    document.getElementById('url-csv-feed').value = `${origin}/feed/csv${tokenParam}${sensorParam}`;
}

function copyURL(elementId) {
    const input = document.getElementById(elementId);
    if (!input) return;
    input.select();
    navigator.clipboard.writeText(input.value).then(() => {
        const btn = input.nextElementSibling;
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.background = '#2ecc71';
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '';
        }, 2000);
    });
}

let isMISPKeyVisible = false;
let mispUserEditing = false;
let mispInitialized = false;

function initMISP() {
    const urlInput = document.getElementById('misp-url-input');
    const keyInput = document.getElementById('misp-key-input');
    const enabledToggle = document.getElementById('misp-enabled-toggle');
    const skipVerify = document.getElementById('misp-skip-verify');

    if (urlInput) {
        urlInput.addEventListener('input', () => { mispUserEditing = true; });
    }
    if (keyInput) {
        keyInput.addEventListener('input', () => { mispUserEditing = true; });
    }
    if (enabledToggle) {
        enabledToggle.addEventListener('change', () => { mispUserEditing = true; });
    }
    if (skipVerify) {
        skipVerify.addEventListener('change', () => { mispUserEditing = true; });
    }
}

function toggleMISPKeyVisibility() {
    const keyInput = document.getElementById('misp-key-input');
    const btn = document.getElementById('misp-toggle-key-btn');
    if (!keyInput || !btn) return;

    isMISPKeyVisible = !isMISPKeyVisible;
    if (isMISPKeyVisible) {
        keyInput.type = 'text';
        btn.textContent = '🙈 Hide';
    } else {
        keyInput.type = 'password';
        btn.textContent = '👁️ Show';
    }
}

function renderMISPStatus(data, force = false) {
    if (!data) return;
    // Update form fields
    const enabledToggle = document.getElementById('misp-enabled-toggle');
    const urlInput = document.getElementById('misp-url-input');
    const keyInput = document.getElementById('misp-key-input');
    const skipVerify = document.getElementById('misp-skip-verify');

    if (!mispInitialized || force || !mispUserEditing) {
        if (enabledToggle) enabledToggle.checked = !!data.enabled;
        if (urlInput) urlInput.value = data.url || '';
        if (keyInput && data.api_key_masked) {
            keyInput.value = data.api_key_masked;
        }
        if (skipVerify) skipVerify.checked = !!data.skip_verify;
        mispInitialized = true;
    }

    // Update status badge
    const pill = document.getElementById('misp-status-pill');
    if (pill) {
        if (!data.enabled) {
            pill.className = 'status-badge idle';
            pill.textContent = 'DISABLED';
        } else if (data.last_error) {
            pill.className = 'status-badge risk-high';
            pill.textContent = 'RETRYING / ERROR';
        } else {
            pill.className = 'status-badge active';
            pill.textContent = 'ACTIVE & CONNECTED';
        }
    }

    // Update monitoring metrics
    const totalPushed = document.getElementById('misp-total-pushed');
    const totalFailed = document.getElementById('misp-total-failed');
    const monServer = document.getElementById('misp-mon-server');
    const monKey = document.getElementById('misp-mon-key');
    const monLastTime = document.getElementById('misp-mon-last-time');

    if (totalPushed) totalPushed.textContent = data.total_pushed || 0;
    if (totalFailed) totalFailed.textContent = data.total_failed || 0;
    if (monServer) monServer.textContent = data.url ? data.url : 'Not Configured';
    if (monKey) monKey.textContent = data.api_key_masked ? data.api_key_masked : '-';
    if (monLastTime) monLastTime.textContent = data.last_pushed_at ? formatDate(data.last_pushed_at) : 'Never';

    // Render event audit trail
    renderMISPEventsTable(data.recent_events);
}

function renderPersistedMISP() {
    if (lastMISPData) {
        renderMISPStatus(lastMISPData);
    }
}

async function fetchMISPStatus(force = false) {
    try {
        const res = await fetch('/api/misp/status');
        if (!res.ok) return;
        const data = await res.json();
        lastMISPData = data;
        try { sessionStorage.setItem('honeygo_cached_misp', JSON.stringify(data)); } catch (e) {}
        renderMISPStatus(data, force);
    } catch (err) {
        console.error('Failed to fetch MISP status:', err);
    }
}

async function saveMISPConfig() {
    const enabledToggle = document.getElementById('misp-enabled-toggle');
    const urlInput = document.getElementById('misp-url-input');
    const keyInput = document.getElementById('misp-key-input');
    const skipVerify = document.getElementById('misp-skip-verify');
    const msg = document.getElementById('misp-save-msg');

    const payload = {
        enabled: enabledToggle ? enabledToggle.checked : false,
        url: urlInput ? urlInput.value.trim() : '',
        api_key: keyInput ? keyInput.value.trim() : '',
        skip_verify: skipVerify ? skipVerify.checked : false
    };

    try {
        const res = await fetch('/api/misp/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            mispUserEditing = false;
            if (msg) {
                msg.textContent = payload.enabled ? '✓ MISP Integration Enabled & Saved' : '✓ MISP Settings Saved (Disabled)';
                msg.className = 'save-toast success';
                setTimeout(() => { msg.textContent = ''; }, 3500);
            }
            await fetchMISPStatus(true);
        } else {
            const errText = await res.text();
            if (msg) {
                msg.textContent = `✗ ${errText || 'Error saving configuration'}`;
                msg.className = 'save-toast error';
            }
        }
    } catch (err) {
        if (msg) {
            msg.textContent = '✗ Connection Error';
            msg.className = 'save-toast error';
        }
    }
}

async function testMISPConnection() {
    const btn = document.getElementById('misp-test-btn');
    const msg = document.getElementById('misp-save-msg');
    const urlInput = document.getElementById('misp-url-input');
    const keyInput = document.getElementById('misp-key-input');
    const skipVerify = document.getElementById('misp-skip-verify');

    const origText = btn ? btn.textContent : '';
    if (btn) btn.textContent = '⏳ Testing...';

    const payload = {
        url: urlInput ? urlInput.value.trim() : '',
        api_key: keyInput ? keyInput.value.trim() : '',
        skip_verify: skipVerify ? skipVerify.checked : false
    };

    try {
        const res = await fetch('/api/misp/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (data.success) {
            if (msg) {
                msg.textContent = `✓ Connected: Version ${data.version || 'OK'} (${data.latency_ms}ms)`;
                msg.className = 'save-toast success';
            }
            const pill = document.getElementById('misp-status-pill');
            if (pill) {
                pill.className = 'status-badge active';
                pill.textContent = 'AUTHENTICATED';
            }
        } else {
            if (msg) {
                msg.textContent = `✗ Test Failed: ${data.error || 'Connection Refused'}`;
                msg.className = 'save-toast error';
            }
        }
    } catch (err) {
        if (msg) {
            msg.textContent = `✗ Network Error: ${err.message}`;
            msg.className = 'save-toast error';
        }
    } finally {
        if (btn) {
            setTimeout(() => { btn.textContent = origText; }, 2500);
        }
    }
}

async function pushMISPCanary() {
    const btn = document.getElementById('misp-canary-btn');
    const msg = document.getElementById('misp-save-msg');
    const urlInput = document.getElementById('misp-url-input');
    const keyInput = document.getElementById('misp-key-input');
    const skipVerify = document.getElementById('misp-skip-verify');

    const origText = btn ? btn.textContent : '';
    if (btn) btn.textContent = '🚀 Sending...';

    const payload = {
        url: urlInput ? urlInput.value.trim() : '',
        api_key: keyInput ? keyInput.value.trim() : '',
        skip_verify: skipVerify ? skipVerify.checked : false
    };

    try {
        const res = await fetch('/api/misp/canary', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
            if (msg) {
                msg.textContent = `✓ ${data.message || 'Canary Event Created'}`;
                msg.className = 'save-toast success';
                setTimeout(() => { msg.textContent = ''; }, 3500);
            }
            fetchMISPStatus(true);
        } else {
            if (msg) {
                msg.textContent = `✗ Canary Failed: ${data.error || 'Error'}`;
                msg.className = 'save-toast error';
            }
        }
    } catch (err) {
        if (msg) {
            msg.textContent = `✗ Canary Request Error: ${err.message}`;
            msg.className = 'save-toast error';
        }
    } finally {
        if (btn) {
            setTimeout(() => { btn.textContent = origText; }, 2500);
        }
    }
}

function renderMISPEventsTable(events) {
    const body = document.getElementById('misp-events-body');
    if (!body) return;

    if (events && events.length > 0) {
        body.innerHTML = events.map(e => {
            const statusClass = e.status === 'SUCCESS' ? 'status-badge active' : 'status-badge risk-critical';
            const statusLabel = e.status === 'SUCCESS' ? `201 CREATED` : `FAILED`;
            const protoClass = (e.protocol || 'web').toLowerCase();

            return `
                <tr>
                    <td>${formatDate(e.timestamp)}</td>
                    <td><span class="badge ${escapeHtml(protoClass)}">${escapeHtml((e.protocol || 'OTHER').toUpperCase())}</span></td>
                    <td><strong style="color: var(--green-crt-bright);">${escapeHtml(e.event_type || 'Attack Indicator')}</strong></td>
                    <td><span class="host-link" onclick="navigateToHost('${escapeHtml(e.remote_ip)}')">${escapeHtml(e.remote_ip)}</span></td>
                    <td>
                        <div style="font-size: 0.85rem; color: var(--white);">${escapeHtml(e.info || '-')}</div>
                        <span style="font-size: 0.75rem; color: var(--green-text-dim);">${escapeHtml(e.attr_count || 0)} MISP Attributes (IP, credentials, payloads)</span>
                        ${e.error ? `<div style="font-size: 0.75rem; color: #ff5555; margin-top: 2px;">Error: ${escapeHtml(e.error)}</div>` : ''}
                    </td>
                    <td><span style="font-size: 0.8rem; color: var(--green-text-dim);">${escapeHtml(e.latency_ms || 0)}ms</span></td>
                    <td><span class="${escapeHtml(statusClass)}">${escapeHtml(statusLabel)}</span></td>
                </tr>
            `;
        }).join('');
    } else {
        body.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--green-text-dim); padding: 25px;">No MISP events pushed yet. Attacker connections, credential captures, and commands will be logged here in real-time.</td></tr>';
    }
}

function renderSensorsTable(sensors) {
    const body = document.getElementById('sensors-body');
    if (!body) return;

    if (sensors && Array.isArray(sensors) && sensors.length > 0) {
        // Always maintain strict alphabetical order by sensor_id
        const sortedSensors = [...sensors].sort((a, b) => (a.sensor_id || '').localeCompare(b.sensor_id || '', undefined, { sensitivity: 'base' }));
        cachedSensorsList = sortedSensors;

        body.innerHTML = sortedSensors.map(s => {
            let statusClass = 'idle';
            if (s.status === 'Active' || s.status === 'Online') {
                statusClass = 'active';
            } else if (s.status === 'Offline') {
                statusClass = 'offline';
            }
            let svcsHtml = '<span style="color:var(--grey-text);font-style:italic;">None</span>';
            if (s.services && Array.isArray(s.services) && s.services.length > 0) {
                const sortedServices = [...s.services].sort((a, b) => {
                    const p1 = (a.protocol || '').toLowerCase();
                    const p2 = (b.protocol || '').toLowerCase();
                    if (p1 !== p2) return p1.localeCompare(p2, undefined, { sensitivity: 'base' });
                    return (a.port || 0) - (b.port || 0);
                });
                svcsHtml = sortedServices.map(svc => {
                    const isoBadge = svc.isolated ? ' <span class="proto-mode-badge isolated" style="font-size:0.6rem;">SANDBOX</span>' : '';
                    return `<span class="proto-mode-badge native" style="font-size:0.72rem;margin:2px 3px 2px 0;display:inline-block;">${escapeHtml((svc.protocol || '').toUpperCase())}:${escapeHtml(svc.port)}${isoBadge}</span>`;
                }).join(' ');
            }

            const isoBadge = s.isolation 
                ? `<span class="proto-mode-badge isolated" style="font-size:0.7rem;">🛡️ ACTIVE</span>` 
                : `<span class="proto-mode-badge native" style="font-size:0.7rem; color:var(--grey-text); border-color:rgba(255,255,255,0.2);">⚪ DISABLED</span>`;

            const displayNameHtml = s.display_name 
                ? `<div style="font-size:0.78rem; color:#00d2ff; margin-top:2px;">🏷️ ${escapeHtml(s.display_name)}</div>` 
                : '';

            return `
                <tr>
                    <td>
                        <strong style="color:#00d2ff;">📡 ${escapeHtml(s.sensor_id)}</strong>
                        ${displayNameHtml}
                    </td>
                    <td><code style="color:#7ee290;">${escapeHtml(s.remote_ip || '127.0.0.1')}</code></td>
                    <td><span class="status-badge ${escapeHtml(statusClass)}">${escapeHtml(s.status)}</span></td>
                    <td><span class="badge" style="background:rgba(0,229,255,0.08);color:#00e5ff;font-family:monospace;font-size:0.75rem;">${escapeHtml(s.checkin_ttl || 15)}s</span></td>
                    <td>${isoBadge}</td>
                    <td>${svcsHtml}</td>
                    <td><span class="highlight">${escapeHtml(s.event_count)} events</span></td>
                    <td>${formatDate(s.last_seen)}</td>
                    <td>
                        <button class="nav-btn small" onclick="openManageSensorModal('${escapeHtml(s.sensor_id)}')" style="padding: 0.25rem 0.6rem; font-size: 0.75rem; background: rgba(0,210,255,0.15); border: 1px solid rgba(0,210,255,0.4); color: #00d2ff; cursor: pointer;">⚙️ Manage</button>
                    </td>
                </tr>
            `;
        }).join('');
    } else {
        body.innerHTML = '<tr><td colspan="9" style="text-align:center;color:rgba(255,255,255,0.4);">No sensors connected yet. Run sensors with <code>--css-url</code> to send telemetry here.</td></tr>';
    }
}

let leafletMap = null;
let countryGeoJsonLayer = null;
let worldGeoJsonData = null;
let lastHeatmapPoints = null;

const iso2ToIso3Map = {
    "AF":"AFG","AL":"ALB","DZ":"DZA","AS":"ASM","AD":"AND","AO":"AGO","AI":"AIA","AQ":"ATA","AG":"ATG","AR":"ARG",
    "AM":"ARM","AW":"ABW","AU":"AUS","AT":"AUT","AZ":"AZE","BS":"BHS","BH":"BHR","BD":"BGD","BB":"BRB","BY":"BLR",
    "BE":"BEL","BZ":"BLZ","BJ":"BEN","BM":"BMU","BT":"BTN","BO":"BOL","BA":"BIH","BW":"BWA","BR":"BRA","BN":"BRN",
    "BG":"BGR","BF":"BFA","BI":"BDI","KH":"KHM","CM":"CMR","CA":"CAN","CV":"CPV","KY":"CYM","CF":"CAF","TD":"TCD",
    "CL":"CHL","CN":"CHN","CO":"COL","KM":"COM","CG":"COG","CD":"COD","CR":"CRI","CI":"CIV","HR":"HRV","CU":"CUB",
    "CY":"CYP","CZ":"CZE","DK":"DNK","DJ":"DJI","DM":"DMA","DO":"DOM","EC":"ECU","EG":"EGY","SV":"SLV","GQ":"GNQ",
    "ER":"ERI","EE":"EST","ET":"ETH","FJ":"FJI","FI":"FIN","FR":"FRA","GA":"GAB","GM":"GMB","GE":"GEO","DE":"DEU",
    "GH":"GHA","GI":"GIB","GR":"GRC","GL":"GRL","GD":"GRD","GU":"GUM","GT":"GTM","GN":"GIN","GW":"GNB","GY":"GUY",
    "HT":"HTI","HN":"HND","HK":"HKG","HU":"HUN","IS":"ISL","IN":"IND","ID":"IDN","IR":"IRN","IQ":"IRQ","IE":"IRL",
    "IL":"ISR","IT":"ITA","JM":"JAM","JP":"JPN","JO":"JOR","KZ":"KAZ","KE":"KEN","KP":"PRK","KR":"KOR","KW":"KWT",
    "KG":"KGZ","LA":"LAO","LV":"LVA","LB":"LBN","LS":"LSO","LR":"LBR","LY":"LBY","LI":"LIE","LT":"LTU","LU":"LUX",
    "MO":"MAC","MK":"MKD","MG":"MDG","MW":"MWI","MY":"MYS","MV":"MDV","ML":"MLI","MT":"MLT","MH":"MHL","MR":"MRT",
    "MU":"MUS","MX":"MEX","FM":"FSM","MD":"MDA","MC":"MCO","MN":"MNG","ME":"MNE","MA":"MAR","MZ":"MOZ","MM":"MMR",
    "NA":"NAM","NP":"NPL","NL":"NLD","NC":"NCL","NZ":"NZL","NI":"NIC","NE":"NER","NG":"NGA","NO":"NOR","OM":"OMN",
    "PK":"PAK","PW":"PLW","PA":"PAN","PG":"PNG","PY":"PRY","PE":"PER","PH":"PHL","PL":"POL","PT":"PRT","PR":"PRI",
    "QA":"QAT","RO":"ROU","RU":"RUS","RW":"RWA","KN":"KNA","LC":"LCA","VC":"VCT","WS":"WSM","SM":"SMR","ST":"STP",
    "SA":"SAU","SN":"SEN","RS":"SRB","SC":"SYC","SL":"SLE","SG":"SGP","SK":"SVK","SI":"SVN","SB":"SLB","SO":"SOM",
    "ZA":"ZAF","ES":"ESP","LK":"LKA","SD":"SDN","SR":"SUR","SZ":"SWZ","SE":"SWE","CH":"CHE","SY":"SYR","TW":"TWN",
    "TJ":"TJK","TZ":"TZA","TH":"THA","TL":"TLS","TG":"TGO","TO":"TON","TT":"TTO","TN":"TUN","TR":"TUR","TM":"TKM",
    "UG":"UGA","UA":"UKR","AE":"ARE","GB":"GBR","US":"USA","UY":"URY","UZ":"UZB","VU":"VUT","VE":"VEN","VN":"VNM",
    "YE":"YEM","ZM":"ZMB","ZW":"ZWE"
};

const iso3ToIso2Map = {};
Object.keys(iso2ToIso3Map).forEach(k => {
    iso3ToIso2Map[iso2ToIso3Map[k]] = k;
});

function getCountryCodeFromFeature(feature) {
    if (!feature) return '';
    const id = (feature.id || '').toUpperCase();
    const props = feature.properties || {};

    if (props.iso_a2 && props.iso_a2.length === 2 && props.iso_a2 !== '-99') return props.iso_a2.toUpperCase();
    if (props.ISO_A2 && props.ISO_A2.length === 2 && props.ISO_A2 !== '-99') return props.ISO_A2.toUpperCase();
    if (props.wb_a2 && props.wb_a2.length === 2 && props.wb_a2 !== '-99') return props.wb_a2.toUpperCase();

    if (id.length === 2) return id;

    const iso3 = id.length === 3 ? id : (props.iso_a3 || props.ISO_A3 || props.adm0_a3 || '').toUpperCase();
    if (iso3 && iso3ToIso2Map[iso3]) {
        return iso3ToIso2Map[iso3];
    }

    const name = (props.name || props.NAME || '').toLowerCase();
    if (name.includes('germany')) return 'DE';
    if (name.includes('united states') || name.includes('america')) return 'US';
    if (name.includes('russia')) return 'RU';
    if (name.includes('china')) return 'CN';
    if (name.includes('brazil')) return 'BR';
    if (name.includes('united kingdom') || name.includes('britain')) return 'GB';
    if (name.includes('france')) return 'FR';
    if (name.includes('japan')) return 'JP';
    if (name.includes('india')) return 'IN';

    return id;
}

let cachedCorrelationsData = null;
let lastCorrelationsJSON = '';

function renderPersistedCorrelations() {
    if (!cachedCorrelationsData) {
        try {
            const saved = sessionStorage.getItem('honeygo_cached_correlations');
            if (saved) {
                cachedCorrelationsData = JSON.parse(saved);
            }
        } catch (e) {}
    }
    if (cachedCorrelationsData) {
        updateMapData(cachedCorrelationsData.heatmap);
        renderCrossProtocolTable(cachedCorrelationsData.cross_protocol_attackers);
        renderUACorrelationTable(cachedCorrelationsData.user_agent_correlations);
        renderWebPathTable(cachedCorrelationsData.web_path_correlations);
        renderUsernameMatrixTable(cachedCorrelationsData.username_matrix);
    }
}

async function fetchWorldGeoJson() {
    if (worldGeoJsonData) return worldGeoJsonData;
    
    // 1. Instant local persistence (0ms latency, resilient offline)
    try {
        const stored = localStorage.getItem('honeygo_world_geojson');
        if (stored) {
            worldGeoJsonData = JSON.parse(stored);
            return worldGeoJsonData;
        }
    } catch (e) {}

    // 2. Fetch with 5s timeout
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        const res = await fetch('https://cdn.jsdelivr.net/gh/johan/world.geo.json@master/countries.geo.json', {
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (res.ok) {
            worldGeoJsonData = await res.json();
            try {
                localStorage.setItem('honeygo_world_geojson', JSON.stringify(worldGeoJsonData));
            } catch (e) {}
            return worldGeoJsonData;
        }
    } catch (e) {
        console.warn('GeoJSON fetch timed out or offline:', e);
    }
    return null;
}

function initLeafletMap() {
    const mapEl = document.getElementById('leaflet-map');
    if (!mapEl || leafletMap || typeof L === 'undefined') return;

    leafletMap = L.map('leaflet-map', {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 8
    });

    const tileUrl = getCartoTileUrl(currentCartoKey);
    cartoTileLayer = L.tileLayer(tileUrl, {
        attribution: '&copy; <a href="https://carto.com/">CARTO</a> | Honeygo Threat Intelligence Engine',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(leafletMap);

    updateMapAPIKeyBadge(currentCartoKey);

    fetchWorldGeoJson().then(geoJson => {
        if (geoJson && lastHeatmapPoints) {
            updateMapData(lastHeatmapPoints);
        }
    });
}

async function fetchCorrelationsData(force = false) {
    try {
        const query = currentSensor !== 'all' ? `?sensor=${encodeURIComponent(currentSensor)}` : '';
        const res = await fetch(`/api/analytics/correlations${query}`);
        if (!res.ok) return;
        const data = await res.json();
        cachedCorrelationsData = data;
        try {
            sessionStorage.setItem('honeygo_cached_correlations', JSON.stringify(data));
        } catch (e) {}

        const jsonStr = JSON.stringify(data);
        if (!force && jsonStr === lastCorrelationsJSON) return; // Prevent unnecessary DOM re-renders if data has not changed
        lastCorrelationsJSON = jsonStr;

        updateMapData(data.heatmap);
        renderCrossProtocolTable(data.cross_protocol_attackers);
        renderUACorrelationTable(data.user_agent_correlations);
        renderWebPathTable(data.web_path_correlations);
        renderUsernameMatrixTable(data.username_matrix);
    } catch (err) {
        console.error('Failed to fetch correlations data:', err);
    }
}

function getCountryColorAndStyle(eventCount, maxAttacks) {
    if (!eventCount || eventCount <= 0 || !maxAttacks) {
        return {
            color: 'rgba(51, 255, 51, 0.1)',
            fillColor: 'transparent',
            fillOpacity: 0,
            weight: 0.5,
            level: 'Untargeted'
        };
    }
    const ratio = eventCount / maxAttacks;
    if (ratio >= 0.75) {
        // Deepest Dark Blood Crimson Burgundy (Top Attacker, e.g. Germany)
        return {
            color: '#ff1744',
            fillColor: '#3d000c',
            fillOpacity: 0.95,
            weight: 1.6,
            level: 'Critical Dark Crimson'
        };
    } else if (ratio >= 0.45) {
        return {
            color: '#ff4081',
            fillColor: '#6b0014',
            fillOpacity: 0.88,
            weight: 1.3,
            level: 'Severe Attack Density'
        };
    } else if (ratio >= 0.20) {
        return {
            color: '#ff5252',
            fillColor: '#99001e',
            fillOpacity: 0.80,
            weight: 1.1,
            level: 'High Attack Density'
        };
    } else if (ratio >= 0.08) {
        return {
            color: '#ff9100',
            fillColor: '#cc3300',
            fillOpacity: 0.72,
            weight: 1.0,
            level: 'Moderate Attack Density'
        };
    } else {
        return {
            color: '#ffd740',
            fillColor: '#d4a000',
            fillOpacity: 0.60,
            weight: 1.0,
            level: 'Low Attack Volume'
        };
    }
}

function updateMapData(heatmapPoints) {
    if (!leafletMap) initLeafletMap();
    if (!leafletMap) return;

    lastHeatmapPoints = heatmapPoints;

    const statsByCountry = {};
    let maxAttacks = 1;

    function addStat(cc, count, ipCount, name) {
        if (!cc) return;
        cc = cc.toUpperCase();
        if (cc === 'UN' || cc === 'UNKNOWN') return;
        if (cc.length === 3 && iso3ToIso2Map[cc]) {
            cc = iso3ToIso2Map[cc];
        }

        count = parseInt(count || 0, 10);
        ipCount = parseInt(ipCount || 0, 10);

        if (!statsByCountry[cc]) {
            statsByCountry[cc] = { eventCount: count, ipCount: ipCount, name: name || cc };
        } else {
            statsByCountry[cc].eventCount = Math.max(statsByCountry[cc].eventCount, count);
            if (ipCount > 0) statsByCountry[cc].ipCount = Math.max(statsByCountry[cc].ipCount, ipCount);
            if (name) statsByCountry[cc].name = name;
        }
        if (statsByCountry[cc].eventCount > maxAttacks) {
            maxAttacks = statsByCountry[cc].eventCount;
        }
    }

    if (heatmapPoints && Array.isArray(heatmapPoints)) {
        heatmapPoints.forEach(p => {
            addStat(p.country_code || p.CountryCode, p.event_count || p.EventCount || p.weight, p.ip_count || p.IPCount, p.country_name || p.CountryName);
        });
    }

    if (latestCountriesList && Array.isArray(latestCountriesList)) {
        latestCountriesList.forEach(c => {
            addStat(c.country_code, c.attempts, c.credentials || 1, c.country_name);
        });
    }

    if (worldGeoJsonData) {
        if (countryGeoJsonLayer) {
            leafletMap.removeLayer(countryGeoJsonLayer);
        }

        countryGeoJsonLayer = L.geoJSON(worldGeoJsonData, {
            style: function(feature) {
                const cc = getCountryCodeFromFeature(feature);
                const stats = statsByCountry[cc];
                const count = stats ? stats.eventCount : 0;
                const style = getCountryColorAndStyle(count, maxAttacks);

                return {
                    fillColor: style.fillColor,
                    fillOpacity: style.fillOpacity,
                    color: style.color,
                    weight: style.weight
                };
            },
            onEachFeature: function(feature, layer) {
                const cc = getCountryCodeFromFeature(feature);
                const stats = statsByCountry[cc];
                const countryName = (feature.properties && feature.properties.name) || (stats && stats.name) || cc;
                if (stats && stats.eventCount > 0) {
                    const style = getCountryColorAndStyle(stats.eventCount, maxAttacks);
                    const flag = getFlagEmoji(cc);
                    layer.bindPopup(`
                        <div style="font-family:'JetBrains Mono',monospace; padding:4px 6px; color:#fff; min-width:180px;">
                            <strong style="font-size:1.05rem; color:#00e5ff;">${flag} ${escapeHtml(countryName)} (${cc})</strong><br/>
                            <div style="margin-top:6px; font-size:0.85rem; line-height:1.4;">
                                <b>Total Attacks:</b> <span style="color:#ff1744; font-weight:bold;">${stats.eventCount.toLocaleString()}</span><br/>
                                <b>Unique Attacker IPs:</b> <span style="color:#ffe57f; font-weight:bold;">${stats.ipCount}</span><br/>
                                <b>Heat Intensity:</b> <span style="color:${style.color}; font-weight:bold;">${style.level}</span>
                            </div>
                        </div>
                    `);
                    layer.on({
                        mouseover: function(e) {
                            const l = e.target;
                            l.setStyle({ weight: 2.5, color: '#00e5ff' });
                            if (!L.Browser.ie && !L.Browser.opera && !L.Browser.edge) {
                                l.bringToFront();
                            }
                        },
                        mouseout: function(e) {
                            countryGeoJsonLayer.resetStyle(e.target);
                        }
                    });
                }
            }
        }).addTo(leafletMap);
    }
}

function renderCrossProtocolTable(attackers) {
    const tbody = document.getElementById('cross-protocol-body');
    if (!tbody) return;

    if (!attackers || attackers.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:rgba(255,255,255,0.4);">No multi-vector or cross-protocol threat actors detected yet.</td></tr>';
        return;
    }

    tbody.innerHTML = attackers.slice(0, 50).map(a => {
        const portsStr = (a.ports && a.ports.length > 0) ? a.ports.join(', ') : '-';
        const isMultiPort = (a.port_count || (a.ports ? a.ports.length : 0)) > 1;
        const portBadge = isMultiPort ?
            `<span class="badge" style="background:rgba(0,229,255,0.15); color:#00e5ff; border:1px solid rgba(0,229,255,0.4);" title="${escapeHtml(portsStr)}">🔌 ${a.port_count || a.ports.length} Ports (${escapeHtml(portsStr)})</span>` :
            `<span style="font-family:'JetBrains Mono',monospace; font-size:0.82rem; color:var(--grey-text);">${escapeHtml(portsStr)}</span>`;

        const sensorsStr = (a.sensors && a.sensors.length > 0) ? a.sensors.join(', ') : '-';
        const isMultiSensor = (a.sensor_count || (a.sensors ? a.sensors.length : 0)) > 1;
        const sensorBadge = isMultiSensor ?
            `<span class="status-badge active" style="background:rgba(255,176,0,0.15); color:#ffb000; border:1px solid rgba(255,176,0,0.4);" title="${escapeHtml(sensorsStr)}">📡 ${a.sensor_count || a.sensors.length} Honeypots</span>` :
            `<span class="status-badge active">${escapeHtml(sensorsStr)}</span>`;

        const protoBadges = (a.protocols || []).map(p => `<span class="badge badge-${escapeHtml(p)}">${escapeHtml(p.toUpperCase())}</span>`).join(' ');

        return `
            <tr>
                <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:var(--cyan-glow);">${formatDate(a.last_seen)}</td>
                <td>
                    <a href="#host-details?ip=${encodeURIComponent(a.remote_ip)}" class="ip-link" onclick="navigateToHost('${escapeHtml(a.remote_ip)}'); return false;"><code>${escapeHtml(a.remote_ip)}</code></a>
                </td>
                <td title="${escapeHtml(a.country_name || '')}">
                    ${a.country_code ? `${getFlagEmoji(a.country_code)} ${escapeHtml(a.country_code)}` : 'Unknown'}
                </td>
                <td><span class="risk-badge risk-${escapeHtml((a.risk_level || 'low').toLowerCase())}">${escapeHtml(a.risk_level)}</span></td>
                <td><strong style="color:${a.threat_score >= 75 ? '#ff2a6d' : a.threat_score >= 45 ? '#ff7800' : '#f7b733'}">${escapeHtml(a.threat_score)} / 100</strong></td>
                <td>${protoBadges}</td>
                <td>${portBadge}</td>
                <td>${sensorBadge}</td>
                <td><strong>${escapeHtml(a.total_events.toLocaleString())}</strong></td>
            </tr>
        `;
    }).join('');
}

function renderUACorrelationTable(correlations) {
    const tbody = document.getElementById('ua-correlation-body');
    if (!tbody) return;

    if (!correlations || correlations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:rgba(255,255,255,0.4);">No Web User-Agent correlations logged yet.</td></tr>';
        return;
    }

    tbody.innerHTML = correlations.slice(0, 50).map(u => `
        <tr>
            <td title="${escapeHtml(u.user_agent)}">
                <code style="color:#00d2ff; word-break:break-word;">${escapeHtml(u.user_agent)}</code>
            </td>
            <td><strong style="color:var(--cyan-glow); font-size:1.05rem;">${u.request_count.toLocaleString()}</strong></td>
            <td><span class="highlight">${escapeHtml(u.unique_ips)} IPs</span></td>
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:var(--grey-text);">${formatDate(u.last_seen)}</td>
        </tr>
    `).join('');
}

function renderWebPathTable(paths) {
    const tbody = document.getElementById('web-path-body');
    if (!tbody) return;

    if (!paths || paths.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:rgba(255,255,255,0.4);">No Web payload paths logged yet.</td></tr>';
        return;
    }

    tbody.innerHTML = paths.slice(0, 50).map(p => `
        <tr>
            <td title="${escapeHtml(p.method_path)}"><code style="color:#ff7800; word-break:break-word;">${escapeHtml(p.method_path)}</code></td>
            <td><strong style="color:var(--cyan-glow); font-size:1.05rem;">${p.request_count.toLocaleString()}</strong></td>
            <td><span class="highlight">${escapeHtml(p.unique_ips)} IPs</span></td>
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:var(--grey-text);">${formatDate(p.last_seen)}</td>
        </tr>
    `).join('');
}

function renderUsernameMatrixTable(users) {
    const tbody = document.getElementById('username-matrix-body');
    if (!tbody) return;

    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:rgba(255,255,255,0.4);">No credential matrix data available.</td></tr>';
        return;
    }

    tbody.innerHTML = users.slice(0, 50).map(u => `
        <tr>
            <td title="${escapeHtml(u.username)}"><code style="color:#2ecc71; font-weight:bold; word-break:break-word;">${escapeHtml(u.username)}</code></td>
            <td><strong style="color:var(--cyan-glow); font-size:1.05rem;">${u.total_count.toLocaleString()}</strong></td>
            <td><span class="highlight">${escapeHtml(u.unique_ips)} IPs</span></td>
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:var(--grey-text);">${formatDate(u.last_seen)}</td>
            <td>${(u.protocols || []).map(p => `<span class="badge badge-${escapeHtml(p)}">${escapeHtml(p.toUpperCase())}</span>`).join(' ')}</td>
            <td title="${escapeHtml((u.sensors || []).join(', '))}">${(u.sensors || []).map(s => `<span class="status-badge active">${escapeHtml(s)}</span>`).join(' ')}</td>
        </tr>
    `).join('');
}

function formatDate(ts) {
    if (!ts) return '-';
    try {
        return new Date(ts).toLocaleString();
    } catch (e) {
        return String(ts);
    }
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/`/g, '&#96;');
}

function truncate(str, maxLen = 30) {
    if (!str) return '';
    str = String(str);
    if (str.length <= maxLen) return str;
    return str.substring(0, maxLen - 3) + '...';
}

function renderICSEventRow(e) {
    const idVal = e.id ? `data-ics-id="${escapeHtml(e.id)}"` : `data-ics-key="${escapeHtml(e.created_at)}_${escapeHtml(e.remote_ip)}_${escapeHtml(e.port)}"`;
    const ip = escapeHtml(e.remote_ip || '-');
    const proto = escapeHtml((e.protocol || '').toUpperCase());
    const protoClass = escapeHtml((e.protocol || '').toLowerCase());
    return `
        <tr ${idVal}>
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${formatDate(e.created_at)}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.05); color:#fff;">${escapeHtml(e.sensor_id || 'local')}</span></td>
            <td>
                <span class="country-badge" title="${escapeHtml(e.country_name || '')}">${getFlagEmoji(e.country_code)}</span>
                <span class="host-link" onclick="navigateToHost('${ip}')">${ip}</span>
            </td>
            <td><span class="badge ${protoClass}">${proto}</span> <span style="font-size:0.8rem; color:var(--grey-text);">:${escapeHtml(e.port)}</span></td>
            <td style="font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:#fff;">${escapeHtml(e.command || '-')}</td>
            <td><span class="raw-hex-payload">${escapeHtml(e.raw_data || 'N/A')}</span></td>
        </tr>
    `;
}

function applyICSFilters(resetPage = true, isSilent = false) {
    const ipInput = document.getElementById('filter-ics-ip');
    const protoSelect = document.getElementById('filter-ics-proto');

    const ipFilter = ipInput ? ipInput.value.toLowerCase().trim() : '';
    const protoFilter = protoSelect ? protoSelect.value.toLowerCase().trim() : '';
    const hasActiveFilter = Boolean(ipFilter || protoFilter);

    let filtered = (allICSEvents || []).filter(e => {
        const matchesIP = !ipFilter || (e.remote_ip || '').toLowerCase().includes(ipFilter) || (e.sensor_id || '').toLowerCase().includes(ipFilter);
        const matchesProto = !protoFilter || (e.protocol || '').toLowerCase() === protoFilter;
        return matchesIP && matchesProto;
    });

    pagination.ics.filteredData = filtered;
    if (resetPage) pagination.ics.page = 1;

    const sizeVal = pagination.ics.pageSize;
    let displayData = [];
    let totalPages = 1;

    if (sizeVal === 'all') {
        displayData = filtered;
        totalPages = 1;
    } else {
        const size = parseInt(sizeVal, 10);
        totalPages = Math.ceil(filtered.length / size) || 1;

        if (pagination.ics.page > totalPages) pagination.ics.page = totalPages;
        if (pagination.ics.page < 1) pagination.ics.page = 1;

        const start = (pagination.ics.page - 1) * size;
        displayData = filtered.slice(start, start + size);
    }

    // Update Pagination Controls UI
    const info = document.getElementById('info-ics');
    const btnPrev = document.getElementById('btn-prev-ics');
    const btnNext = document.getElementById('btn-next-ics');

    if (info) info.textContent = `Page ${pagination.ics.page} of ${totalPages} (${filtered.length} total events)`;
    if (btnPrev) btnPrev.disabled = pagination.ics.page <= 1;
    if (btnNext) btnNext.disabled = sizeVal === 'all' || pagination.ics.page >= totalPages;

    // Render Events Table
    const eventsTable = document.getElementById('ics-events-table');
    if (!eventsTable) return;

    if (displayData.length === 0) {
        eventsTable.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--grey-text);">No industrial PLC attacks captured matching filters.</td></tr>';
    } else {
        eventsTable.innerHTML = displayData.map(renderICSEventRow).join('');
    }
}

function renderICSData(data, isSilent = false) {
    if (!data) return;
    const summary = data || {};
    const totalElem = document.getElementById('total-ics-attacks');
    if (totalElem) totalElem.textContent = summary.total_attacks || 0;
    
    const modbusElem = document.getElementById('total-modbus-attempts');
    if (modbusElem) modbusElem.textContent = summary.modbus_count || 0;

    const s7Elem = document.getElementById('total-s7comm-attempts');
    if (s7Elem) s7Elem.textContent = summary.s7comm_count || 0;

    const uniqElem = document.getElementById('unique-ics-attackers');
    if (uniqElem) uniqElem.textContent = summary.unique_attackers || 0;

    const fnList = document.getElementById('ics-function-code-list');
    if (fnList) {
        const stats = summary.function_code_stats || [];
        if (stats.length === 0) {
            fnList.innerHTML = '<div class="list-item" style="color:var(--grey-text);">No industrial function codes captured yet.</div>';
        } else {
            const html = stats.map(f => `
                <div class="list-item">
                    <span>⚡ ${escapeHtml(f.function_code)}</span>
                    <span class="highlight">${f.count} hits</span>
                </div>
            `).join('');
            if (fnList.innerHTML !== html) fnList.innerHTML = html;
        }
    }

    const topTable = document.getElementById('ics-top-attackers-table');
    if (topTable) {
        const topAttackers = summary.top_attackers || [];
        if (topAttackers.length === 0) {
            topTable.innerHTML = '<tr><td colspan="4" style="text-align:center;">No industrial threat actors recorded.</td></tr>';
        } else {
            const html = topAttackers.map(a => `
                <tr>
                    <td><span class="host-link" onclick="navigateToHost('${escapeHtml(a.remote_ip)}')">${escapeHtml(a.remote_ip)}</span></td>
                    <td>${getFlagEmoji(a.country_code)} ${escapeHtml(a.country_name || 'Unknown')} (${escapeHtml(a.asn || '-')})</td>
                    <td>${(a.protocols || []).map(p => `<span class="badge ${escapeHtml(p)}">${escapeHtml(p.toUpperCase())}</span>`).join(' ')}</td>
                    <td><span class="highlight">${escapeHtml(a.count)}</span></td>
                </tr>
            `).join('');
            if (topTable.innerHTML !== html) topTable.innerHTML = html;
        }
    }

    allICSEvents = summary.recent_events || [];
    applyICSFilters(false, isSilent);
}

function renderPersistedICS() {
    if (lastICSData) {
        renderICSData(lastICSData);
    }
}

async function fetchICSData(isSilent = false) {
    try {
        const queryParam = currentSensor !== 'all' ? `?sensor=${encodeURIComponent(currentSensor)}` : '';
        const res = await fetch(`/api/ics${queryParam}`);
        if (!res.ok) return;
        const data = await res.json();
        lastICSData = data;
        try { sessionStorage.setItem('honeygo_cached_ics', JSON.stringify(data)); } catch (e) {}
        renderICSData(data, isSilent);
    } catch (err) {
        console.error('Failed to fetch ICS data:', err);
    }
}

function exportICSLogs() {
    const queryParam = currentSensor !== 'all' ? `?sensor=${encodeURIComponent(currentSensor)}` : '';
    const prefix = queryParam ? `${queryParam}&` : '?';
    window.location.href = `/api/logs/export${prefix}service=modbus`;
}

function renderSystemLogsTable(logs, isSilent = false, hasFilter = false) {
    const tbody = document.getElementById('syslog-body');
    if (!tbody) return;

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--grey-text);">No system log entries found matching criteria.</td></tr>';
        return;
    }

    const renderLogItem = l => {
        let lvlColor = '#ffffff';
        if (l.level === 'WARN') lvlColor = '#f39c12';
        if (l.level === 'ERROR') lvlColor = '#e74c3c';
        if (l.level === 'DEBUG') lvlColor = '#95a5a6';

        const rowKey = `${l.timestamp}_${l.category}_${l.message}`;
        return `
            <tr data-log-key="${escapeHtml(rowKey)}">
                <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${formatDate(l.timestamp)}</td>
                <td><span class="badge" style="background:rgba(255,255,255,0.08); color:#00d2ff; font-weight:600;">${escapeHtml(l.category)}</span></td>
                <td><span style="color:${lvlColor}; font-weight:bold; font-size:0.8rem;">${escapeHtml(l.level)}</span></td>
                <td style="font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:#eee;">${escapeHtml(l.message)}</td>
            </tr>
        `;
    };

    tbody.innerHTML = logs.map(renderLogItem).join('');
}

function renderPersistedSensorsAndLogs() {
    if (lastSensorsData) {
        updateSensorSelectorOptions(lastSensorsData);
        renderSensorsTable(lastSensorsData);
    }
    if (lastSystemLogsData) {
        renderSystemLogsTable(lastSystemLogsData);
    }
}

async function fetchSystemLogs(isSilent = false) {
    if (typeof isSilent !== 'boolean') isSilent = false;
    const catSelect = document.getElementById('filter-syslog-cat');
    const lvlSelect = document.getElementById('filter-syslog-lvl');
    const tbody = document.getElementById('syslog-body');
    if (!tbody) return;

    const cat = catSelect ? catSelect.value : 'ALL';
    const lvl = lvlSelect ? lvlSelect.value : 'ALL';
    const hasFilter = cat !== 'ALL' || lvl !== 'ALL';

    try {
        const res = await fetch(`/api/system/logs?category=${encodeURIComponent(cat)}&level=${encodeURIComponent(lvl)}&limit=100`);
        if (!res.ok) return;
        const logs = await res.json();
        lastSystemLogsData = logs;
        try { sessionStorage.setItem('honeygo_cached_syslogs', JSON.stringify(logs)); } catch (e) {}
        renderSystemLogsTable(logs, isSilent, hasFilter);
    } catch (err) {
        console.error('Failed to fetch system logs:', err);
    }
}

let currentASNCategoryHosts = [];

async function openASNCategoryModal(category) {
    const modal = document.getElementById('asn-category-modal');
    if (!modal) return;

    modal.style.display = 'flex';

    let icon = '🏢';
    if (category.includes('Cloud')) icon = '☁️';
    if (category.includes('ISP')) icon = '🌐';
    if (category.includes('Crawler')) icon = '🕷️';
    if (category.includes('VPN')) icon = '🔒';
    if (category.includes('Education')) icon = '🎓';
    if (category.includes('Private')) icon = '🏠';

    document.getElementById('asn-modal-title').textContent = `${icon} ${category} Infrastructure`;
    document.getElementById('asn-modal-subtitle').textContent = `Full set of threat actor IP addresses classified under ${category}.`;
    
    const body = document.getElementById('asn-modal-body');
    if (body) {
        body.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--grey-text);">Loading infrastructure records...</td></tr>';
    }

    try {
        const queryParam = currentSensor !== 'all' ? `&sensor=${encodeURIComponent(currentSensor)}` : '';
        const res = await fetch(`/api/analytics/asncategory?category=${encodeURIComponent(category)}${queryParam}`);
        if (res.ok) {
            const data = await res.json();
            currentASNCategoryHosts = data.hosts || [];
            renderASNCategoryModalTable(currentASNCategoryHosts);
        }
    } catch (err) {
        console.error('Failed to fetch ASN category hosts:', err);
    }
}

function closeASNCategoryModal() {
    const modal = document.getElementById('asn-category-modal');
    if (modal) modal.style.display = 'none';
}

function renderASNCategoryModalTable(hosts) {
    const searchInput = document.getElementById('filter-asn-modal-search');
    const searchVal = searchInput ? searchInput.value.toLowerCase().trim() : '';

    const filtered = hosts.filter(h => {
        if (!searchVal) return true;
        return (h.remote_ip || '').toLowerCase().includes(searchVal) ||
               (h.as_name || '').toLowerCase().includes(searchVal) ||
               (h.asn || '').toLowerCase().includes(searchVal) ||
               (h.country_name || '').toLowerCase().includes(searchVal);
    });

    const badge = document.getElementById('asn-modal-count-badge');
    if (badge) {
        badge.textContent = `${filtered.length} Threat Actors`;
    }

    const body = document.getElementById('asn-modal-body');
    if (body) {
        if (filtered.length === 0) {
            body.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--grey-text);">No threat actor IPs match this infrastructure group.</td></tr>';
        } else {
            body.innerHTML = filtered.map(h => `
                <tr>
                    <td><span class="host-link" onclick="closeASNCategoryModal(); navigateToHost('${escapeHtml(h.remote_ip)}');">${escapeHtml(h.remote_ip)}</span></td>
                    <td><span class="country-badge" title="${escapeHtml(h.country_name || '')}">${getFlagEmoji(h.country_code)} ${escapeHtml(h.country_code)}</span></td>
                    <td>
                        <div style="font-weight:600; color:#fff;">${escapeHtml(h.as_name || 'Unknown')}</div>
                        <div style="font-size:0.75rem; color:var(--grey-text);">${escapeHtml(h.asn || 'No ASN')}</div>
                    </td>
                    <td><span class="highlight">${escapeHtml(h.attack_count)}</span></td>
                    <td>${h.credentials_count > 0 ? `<span class="badge creds">${escapeHtml(h.credentials_count)} creds</span>` : '-'}</td>
                    <td style="font-size:0.8rem; color:var(--grey-text);">${formatDate(h.last_seen)}</td>
                    <td>
                        <button class="sub-nav-btn" style="padding:4px 8px; font-size:0.75rem;" onclick="closeASNCategoryModal(); navigateToHost('${escapeHtml(h.remote_ip)}');">Inspect</button>
                    </td>
                </tr>
            `).join('');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const asnModalSearch = document.getElementById('filter-asn-modal-search');
    if (asnModalSearch) {
        asnModalSearch.addEventListener('input', () => {
            renderASNCategoryModalTable(currentASNCategoryHosts);
        });
    }
});

// ==========================================
// 🎯 Reconnaissance & Attack Infrastructure
// ==========================================

let cachedReconData = null;

function renderPersistedReconTargets() {
    if (!cachedReconData) {
        try {
            const saved = sessionStorage.getItem('honeygo_cached_recon');
            if (saved) {
                cachedReconData = JSON.parse(saved);
            }
        } catch (e) {}
    }
    if (cachedReconData) {
        renderReconData(cachedReconData);
    }
}

function renderReconData(data) {
    const filterEl = document.getElementById('recon-filter-select');
    const filter = filterEl ? filterEl.value : 'all';
    
    const tbody = document.getElementById('recon-targets-tbody');
    const infoRecon = document.getElementById('info-recon');
    const btnPrevRecon = document.getElementById('btn-prev-recon');
    const btnNextRecon = document.getElementById('btn-next-recon');
    if (!tbody) return;

    // Update stats
    if (data.stats) {
        const elTotal = document.getElementById('recon-stat-total');
        const elDroppers = document.getElementById('recon-stat-droppers');
        const elCanary = document.getElementById('recon-stat-canary');
        const elHighRisk = document.getElementById('recon-stat-highrisk');

        if (elTotal) elTotal.textContent = data.stats.total || 0;
        if (elDroppers) elDroppers.textContent = data.stats.c2_droppers || 0;
        if (elCanary) elCanary.textContent = data.stats.canary_hits || 0;
        if (elHighRisk) elHighRisk.textContent = data.stats.high_risk || 0;
    }

    // Auto-recon toggle
    const toggle = document.getElementById('recon-auto-toggle');
    if (toggle && data.auto_recon !== undefined) {
        toggle.checked = data.auto_recon;
    }

    const rawTargets = data.targets || [];
    const targets = [...rawTargets].sort((a, b) => new Date(b.last_seen || b.created_at || 0) - new Date(a.last_seen || a.created_at || 0));
    pagination.reconTargets.filteredData = targets;

    const pageSize = pagination.reconTargets.pageSize;
    let pageItems = targets;
    let totalPages = 1;

    if (pageSize !== 'all') {
        const size = parseInt(pageSize, 10) || 25;
        totalPages = Math.ceil(targets.length / size) || 1;
        if (pagination.reconTargets.page > totalPages) {
            pagination.reconTargets.page = totalPages;
        }
        const start = (pagination.reconTargets.page - 1) * size;
        pageItems = targets.slice(start, start + size);
    }

    if (infoRecon) infoRecon.textContent = `Page ${pagination.reconTargets.page} of ${totalPages} (${targets.length} total)`;
    if (btnPrevRecon) btnPrevRecon.disabled = pagination.reconTargets.page <= 1;
    if (btnNextRecon) btnNextRecon.disabled = pageSize === 'all' || pagination.reconTargets.page >= totalPages;

    if (pageItems.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 30px;">
            No attack targets or C2 droppers tracked under filter "${escapeHtml(filter)}". Run a scan or await incoming attacks.
        </td></tr>`;
        return;
    }

    tbody.innerHTML = pageItems.map(t => {
        let riskColor = '#4caf50';
        if (t.risk_score >= 70) {
            riskColor = '#ff3366';
        } else if (t.risk_score >= 40) {
            riskColor = '#ff9800';
        }

        let typeBadge = '<span class="status-badge active" style="background: rgba(0,229,255,0.15); color: #00e5ff; border: 1px solid rgba(0,229,255,0.4);">🪤 Canary Hit</span>';
        if (t.source_type === 'c2_dropper') {
            typeBadge = '<span class="status-badge active" style="background: rgba(255,152,0,0.15); color: #ff9800; border: 1px solid rgba(255,152,0,0.4);">📦 C2 Dropper</span>';
        }

        let tagsHtml = '';
        if (t.tags) {
            tagsHtml = t.tags.split(',').map(tag => {
                const tagClean = tag.trim();
                if (!tagClean) return '';
                return `<span class="badge" style="background: rgba(255,255,255,0.06); color: #ddd; font-size: 0.7rem; margin-right: 3px; margin-bottom: 2px; display: inline-block;">${escapeHtml(tagClean)}</span>`;
            }).join('');
        }

        const origin = (t.country_name || t.country_code) ? 
            `<span>${getFlagEmoji(t.country_code)} ${escapeHtml(t.as_name || t.country_name || t.country_code)}</span>` : 
            `<span style="color: var(--text-muted);">Unknown</span>`;

        const rdns = t.reverse_dns ? 
            `<span style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #a5d6a7; word-break: break-all;" title="${escapeHtml(t.reverse_dns)}">${escapeHtml(t.reverse_dns)}</span>` : 
            `<span style="color: var(--text-muted); font-size: 0.8rem;">-</span>`;

        return `
            <tr>
                <td>
                    <span class="host-link" onclick="navigateToHost('${escapeHtml(t.ip)}')" title="Click to view host activity">${escapeHtml(t.ip)}</span>
                    ${t.domain ? `<div style="font-size: 0.75rem; color: var(--text-muted); word-break: break-all;">${escapeHtml(t.domain)}</div>` : ''}
                </td>
                <td>
                    ${typeBadge}
                    ${t.source_context ? `<div style="font-size: 0.74rem; font-family: 'JetBrains Mono', monospace; color: #00e5ff; margin-top: 3px; word-break: break-word;" title="${escapeHtml(t.source_context)}">${escapeHtml(t.source_context)}</div>` : ''}
                </td>
                <td style="font-size: 0.82rem; word-break: break-word;">${origin}</td>
                <td>${rdns}</td>
                <td>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <div style="flex: 1; min-width: 45px; background: rgba(255,255,255,0.08); height: 6px; border-radius: 3px; overflow: hidden;">
                            <div style="width: ${t.risk_score}%; background: ${riskColor}; height: 100%;"></div>
                        </div>
                        <span style="font-weight: 700; font-size: 0.82rem; color: ${riskColor}; min-width: 24px;">${t.risk_score}</span>
                    </div>
                </td>
                <td>${tagsHtml}</td>
                <td><span class="badge" style="background: rgba(255,255,255,0.08); color: #fff; font-size: 0.75rem;">${t.hit_count || 1}</span></td>
                <td style="font-size: 0.78rem; color: var(--text-muted);">${formatDate(t.last_seen)}</td>
                <td>
                    <button class="nav-btn small" style="padding: 3px 8px; font-size: 0.75rem;" onclick="triggerScanTarget('${escapeHtml(t.ip)}')">⚡ Resolve</button>
                </td>
            </tr>
        `;
    }).join('');
}

async function loadReconTargets() {
    const filterEl = document.getElementById('recon-filter-select');
    const filter = filterEl ? filterEl.value : 'all';
    
    try {
        const res = await fetch(`/api/recon?filter=${encodeURIComponent(filter)}&limit=150`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        cachedReconData = data;
        try {
            sessionStorage.setItem('honeygo_cached_recon', JSON.stringify(data));
        } catch (e) {}
        renderReconData(data);
    } catch (e) {
        const tbody = document.getElementById('recon-targets-tbody');
        if (tbody && (!cachedReconData || !cachedReconData.targets || cachedReconData.targets.length === 0)) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #ff3366; padding: 25px;">
                Failed to load recon targets: ${escapeHtml(e.message)}
            </td></tr>`;
        }
    }
}

async function toggleAutoReconSetting(enabled) {
    try {
        const res = await fetch('/api/recon/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ auto_recon: enabled })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (e) {
        console.error('Failed to update auto-recon config:', e);
    }
}

async function triggerManualReconScan() {
    const input = document.getElementById('recon-manual-ip-input');
    if (!input || !input.value.trim()) {
        alert('Please enter an IP address or domain to scan.');
        return;
    }
    const ip = input.value.trim();
    input.value = '';
    await triggerScanTarget(ip);
}

async function triggerScanTarget(ip) {
    try {
        const res = await fetch('/api/recon/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const data = await res.json();
        if (!data.success) {
            alert(`Recon scan failed: ${data.error || 'Unknown error'}`);
        }
    } catch (e) {
        alert(`Failed to trigger scan on ${ip}: ${e.message}`);
    } finally {
        loadReconTargets();
    }
}

async function triggerScanAllPending() {
    try {
        const res = await fetch('/api/recon/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ all: true })
        });
        const data = await res.json();
        alert(data.message || `Queued pending targets for scan.`);
        setTimeout(loadReconTargets, 1000);
    } catch (e) {
        alert(`Failed to trigger scan-all: ${e.message}`);
    }
}

function openAddReconTargetModal() {
    const modal = document.getElementById('modal-add-recon-target');
    if (modal) {
        modal.style.display = 'flex';
        const ipInput = document.getElementById('manual-recon-ip');
        if (ipInput) {
            ipInput.value = '';
            ipInput.focus();
        }
    }
}

function closeAddReconTargetModal() {
    const modal = document.getElementById('modal-add-recon-target');
    if (modal) modal.style.display = 'none';
}

async function submitManualReconTarget() {
    const ipInput = document.getElementById('manual-recon-ip');
    const typeInput = document.getElementById('manual-recon-type');
    const contextInput = document.getElementById('manual-recon-context');

    if (!ipInput || !ipInput.value.trim()) {
        alert('Please enter a target IP address.');
        return;
    }

    const ip = ipInput.value.trim();
    const sourceType = typeInput ? typeInput.value : 'canary_hit';
    const context = contextInput ? contextInput.value.trim() : '';

    try {
        const res = await fetch('/api/recon/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, source_type: sourceType, context: context })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            alert(`Failed to track target: ${data.error || 'Unknown error'}`);
            return;
        }
        closeAddReconTargetModal();
        loadReconTargets();
    } catch (err) {
        alert(`Error tracking target: ${err.message}`);
    }
}

function logManualCanaryHit() {
    openAddReconTargetModal();
}

let currentManageSensorId = null;

const AVAILABLE_HONEYPOT_SERVICES = [
    { protocol: 'ssh', name: 'SSH Honeypot', defaultPort: 2222, icon: '🔒', profiles: [] },
    { protocol: 'telnet', name: 'Telnet Honeypot', defaultPort: 2323, icon: '📟', profiles: [] },
    { protocol: 'web', name: 'HTTP Web Honeypot', defaultPort: 8080, icon: '🌐', profiles: ['apache', 'pizzashop', 'aws-canary', 'iis', 'cisco', 'nginx', 'tomcat', 'login-portal', 'router-admin'] },
    { protocol: 'vnc', name: 'VNC RFB Honeypot', defaultPort: 5900, icon: '🖥️', profiles: [] },
    { protocol: 'modbus', name: 'Modbus TCP ICS/SCADA', defaultPort: 502, icon: '⚡', profiles: ['schneider', 'common-q', 'triconex'], requiresIsolation: true },
    { protocol: 's7comm', name: 'Siemens S7comm PLC', defaultPort: 102, icon: '🏭', profiles: [], requiresIsolation: true }
];

async function openManageSensorModal(sensorId) {
    currentManageSensorId = sensorId;
    let sensor = cachedSensorsList.find(s => s.sensor_id === sensorId);
    
    // If not in cache, fetch fresh
    if (!sensor) {
        try {
            const res = await fetch('/api/css/sensors');
            if (res.ok) {
                const list = await res.json();
                cachedSensorsList = list;
                sensor = list.find(s => s.sensor_id === sensorId);
            }
        } catch (e) {}
    }

    if (!sensor) {
        sensor = { sensor_id: sensorId, display_name: '', isolation: false, services: [] };
    }

    const modal = document.getElementById('modal-manage-sensor');
    const subtitle = document.getElementById('manage-sensor-subtitle');
    const nameInput = document.getElementById('manage-sensor-display-name');
    const isoBox = document.getElementById('manage-sensor-isolation-box');
    const isoIcon = document.getElementById('manage-sensor-iso-icon');
    const isoTitle = document.getElementById('manage-sensor-iso-title');
    const isoDesc = document.getElementById('manage-sensor-iso-desc');
    const isoBadge = document.getElementById('manage-sensor-iso-badge');
    const svcsList = document.getElementById('manage-sensor-services-list');

    if (subtitle) subtitle.textContent = `Sensor Node: ${sensor.sensor_id} (${sensor.remote_ip || '127.0.0.1'})`;
    if (nameInput) nameInput.value = sensor.display_name || '';

    // Render Isolation Engine Status
    const isIso = !!sensor.isolation;
    if (isoBox) {
        if (isIso) {
            isoBox.style.background = 'rgba(0,255,100,0.08)';
            isoBox.style.borderColor = 'rgba(0,255,100,0.25)';
            if (isoIcon) isoIcon.textContent = '🛡️';
            if (isoTitle) {
                isoTitle.textContent = 'Container Sandbox Isolation: ACTIVE';
                isoTitle.style.color = '#7ee290';
            }
            if (isoDesc) isoDesc.textContent = 'Ephemeral container sandboxing is fully supported on this host. Services can be started in isolated mode.';
            if (isoBadge) {
                isoBadge.className = 'proto-mode-badge isolated';
                isoBadge.textContent = 'ISOLATION READY';
            }
        } else {
            isoBox.style.background = 'rgba(255,165,0,0.08)';
            isoBox.style.borderColor = 'rgba(255,165,0,0.25)';
            if (isoIcon) isoIcon.textContent = '⚠️';
            if (isoTitle) {
                isoTitle.textContent = 'Container Sandbox Isolation: DISABLED / UNAVAILABLE';
                isoTitle.style.color = '#ffa500';
            }
            if (isoDesc) isoDesc.textContent = 'No Docker/Podman isolation engine detected on this sensor node. Services CANNOT be started in isolated mode.';
            if (isoBadge) {
                isoBadge.className = 'proto-mode-badge native';
                isoBadge.style.color = '#ffa500';
                isoBadge.style.borderColor = '#ffa500';
                isoBadge.textContent = 'NO ISOLATION';
            }
        }
    }

    // Render Services
    if (svcsList) {
        const runningSvcs = sensor.services || [];
        svcsList.innerHTML = AVAILABLE_HONEYPOT_SERVICES.map(svcDef => {
            const activeInstance = runningSvcs.find(s => (s.protocol || '').toLowerCase() === svcDef.protocol);
            const isRunning = !!activeInstance;
            const currentPort = activeInstance ? activeInstance.port : svcDef.defaultPort;
            const isServiceIsolated = activeInstance ? !!activeInstance.isolated : false;

            let profilesHtml = '';
            if (svcDef.profiles && svcDef.profiles.length > 0) {
                profilesHtml = `
                    <div style="display:flex; align-items:center; gap:6px;">
                        <span style="font-size:0.75rem; color:var(--text-muted);">Profile:</span>
                        <select id="svc-profile-${svcDef.protocol}" style="padding: 0.25rem 0.5rem; font-size: 0.78rem; background: rgba(0,0,0,0.6); border: 1px solid var(--grey-border); border-radius: 4px; color: #fff;">
                            ${svcDef.profiles.map(p => `<option value="${p}">${p}</option>`).join('')}
                        </select>
                    </div>
                `;
            }

            let isoCheckboxHtml = '';
            if (isIso) {
                const checked = (svcDef.requiresIsolation || isServiceIsolated) ? 'checked' : '';
                isoCheckboxHtml = `
                    <label style="font-size:0.75rem; color:#7ee290; display:flex; align-items:center; gap:4px; cursor:pointer;" title="Run inside ephemeral container sandbox">
                        <input type="checkbox" id="svc-iso-${svcDef.protocol}" ${checked}>
                        🛡️ Isolated
                    </label>
                `;
            } else {
                isoCheckboxHtml = `
                    <label style="font-size:0.75rem; color:var(--grey-text); display:flex; align-items:center; gap:4px; opacity:0.6; cursor:not-allowed;" title="Container isolation is disabled on this sensor. Services cannot start isolated.">
                        <input type="checkbox" id="svc-iso-${svcDef.protocol}" disabled>
                        🛡️ Isolated (N/A)
                    </label>
                `;
            }

            if (isRunning) {
                const sandboxBadge = isServiceIsolated ? '<span class="proto-mode-badge isolated" style="font-size:0.65rem;">SANDBOX</span>' : '<span class="proto-mode-badge native" style="font-size:0.65rem;">NATIVE</span>';
                return `
                    <div style="background: rgba(0,255,100,0.04); border: 1px solid rgba(0,255,100,0.2); border-radius: 6px; padding: 10px 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 1.2rem;">${svcDef.icon}</span>
                            <div>
                                <div style="font-weight: 600; font-size: 0.88rem; color: #fff;">${svcDef.name}</div>
                                <div style="font-size: 0.76rem; color: #7ee290;">🟢 Running on Port <code style="color:#00d2ff;">${currentPort}</code> ${sandboxBadge}</div>
                            </div>
                        </div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <button class="nav-btn small" onclick="controlSensorService('${escapeHtml(sensor.sensor_id)}', '${svcDef.protocol}', 'stop', ${currentPort})" style="background: rgba(255,50,50,0.2); border: 1px solid #ff3366; color: #ff3366; padding: 0.3rem 0.8rem; font-size: 0.78rem; cursor: pointer;">⏹️ Stop Service</button>
                        </div>
                    </div>
                `;
            } else {
                return `
                    <div style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 6px; padding: 10px 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 1.2rem; opacity: 0.7;">${svcDef.icon}</span>
                            <div>
                                <div style="font-weight: 600; font-size: 0.88rem; color: #ccc;">${svcDef.name}</div>
                                <div style="font-size: 0.76rem; color: var(--text-muted);">⚪ Stopped</div>
                            </div>
                        </div>
                        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                            <div style="display: flex; align-items: center; gap: 4px;">
                                <span style="font-size: 0.75rem; color: var(--text-muted);">Port:</span>
                                <input type="number" id="svc-port-${svcDef.protocol}" value="${currentPort}" style="width: 75px; padding: 0.25rem 0.4rem; font-size: 0.78rem; background: rgba(0,0,0,0.6); border: 1px solid var(--grey-border); border-radius: 4px; color: #fff; text-align: center;">
                            </div>
                            <div style="display: flex; align-items: center; gap: 4px;" title="Container sandbox session TTL in seconds (default: 300s)">
                                <span style="font-size: 0.75rem; color: var(--text-muted);">TTL(s):</span>
                                <input type="number" id="svc-ttl-${svcDef.protocol}" value="300" min="0" max="86400" placeholder="300" style="width: 60px; padding: 0.25rem 0.4rem; font-size: 0.78rem; background: rgba(0,0,0,0.6); border: 1px solid var(--grey-border); border-radius: 4px; color: #fff; text-align: center;">
                            </div>
                            ${profilesHtml}
                            ${isoCheckboxHtml}
                            <button class="nav-btn small" onclick="controlSensorService('${escapeHtml(sensor.sensor_id)}', '${svcDef.protocol}', 'start')" style="background: rgba(0,255,100,0.15); border: 1px solid #7ee290; color: #7ee290; padding: 0.3rem 0.8rem; font-size: 0.78rem; cursor: pointer;">▶️ Start Service</button>
                        </div>
                    </div>
                `;
            }
        }).join('');
    }

    if (modal) modal.style.display = 'flex';
}

function closeManageSensorModal() {
    const modal = document.getElementById('modal-manage-sensor');
    if (modal) modal.style.display = 'none';
    currentManageSensorId = null;
}

async function saveSensorDisplayName() {
    if (!currentManageSensorId) return;
    const nameInput = document.getElementById('manage-sensor-display-name');
    const displayName = nameInput ? nameInput.value.trim() : '';

    try {
        const res = await fetch('/api/css/sensors/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sensor_id: currentManageSensorId, display_name: displayName })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            alert(`Failed to update display name: ${data.error || 'Unknown error'}`);
            return;
        }
        await fetchSensors();
        openManageSensorModal(currentManageSensorId);
    } catch (err) {
        alert(`Error updating sensor name: ${err.message}`);
    }
}

async function controlSensorService(sensorId, protocol, action, runningPort) {
    let port = runningPort;
    let isolated = false;
    let profile = '';
    let ttl = 0;

    if (action === 'start') {
        const portInput = document.getElementById(`svc-port-${protocol}`);
        if (portInput) {
            port = parseInt(portInput.value, 10);
            if (isNaN(port) || port <= 0 || port > 65535) {
                alert('Please enter a valid port number (1-65535).');
                return;
            }
        }
        const isoCheckbox = document.getElementById(`svc-iso-${protocol}`);
        if (isoCheckbox) {
            isolated = isoCheckbox.checked;
        }
        const profileSelect = document.getElementById(`svc-profile-${protocol}`);
        if (profileSelect) {
            profile = profileSelect.value;
        }
        const ttlInput = document.getElementById(`svc-ttl-${protocol}`);
        if (ttlInput) {
            ttl = parseInt(ttlInput.value, 10);
            if (isNaN(ttl) || ttl < 0) {
                ttl = 0;
            }
        }
    }

    try {
        const res = await fetch('/api/css/sensors/service', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sensor_id: sensorId,
                action: action,
                protocol: protocol,
                port: port,
                isolated: isolated,
                profile: profile,
                ttl: ttl
            })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            alert(`Service control error: ${data.error || 'Failed to update service'}`);
            return;
        }
        await fetchSensors();
        openManageSensorModal(sensorId);
    } catch (err) {
        alert(`Error sending service command: ${err.message}`);
    }
}

// --- Raw HTTP Request Inspector & Payload Download Handlers ---
let currentInspectorData = null;
let currentInspectorTab = 'raw';

function toggleDownloadMenu(e, menuKey) {
    if (e) e.stopPropagation();
    const menu = document.getElementById(`dl-menu-${menuKey}`);
    if (!menu) return;
    const isVisible = menu.style.display === 'block';
    closeAllDownloadMenus();
    if (!isVisible) {
        menu.style.display = 'block';
    }
}

function closeAllDownloadMenus() {
    document.querySelectorAll('.download-dropdown-content').forEach(el => {
        el.style.display = 'none';
    });
}

document.addEventListener('click', () => {
    closeAllDownloadMenus();
});

function downloadRequest(id, format) {
    closeAllDownloadMenus();
    window.open(`/api/requests/download?id=${id}&format=${format}`, '_blank');
}

function exportWebPayloadsBulk() {
    const formatSelect = document.getElementById('export-scans-payload-format');
    const format = formatSelect ? formatSelect.value : 'raw';
    const sensorParam = currentSensor !== 'all' ? `&sensor=${encodeURIComponent(currentSensor)}` : '';
    window.open(`/api/logs/export?service=web&format=${format}${sensorParam}`, '_blank');
}

async function openRequestInspector(id) {
    const modal = document.getElementById('modal-request-inspector');
    if (!modal) return;
    modal.style.display = 'flex';

    // Reset UI to loading state
    document.getElementById('inspector-modal-id-badge').textContent = `#${id}`;
    document.getElementById('inspector-meta-ip').textContent = 'Loading...';
    document.getElementById('inspector-meta-port-sensor').textContent = '-';
    document.getElementById('inspector-meta-timestamp').textContent = '-';
    document.getElementById('inspector-meta-geo').textContent = '-';
    document.getElementById('inspector-meta-size').textContent = '-';
    document.getElementById('inspector-content').textContent = 'Fetching request payload...';

    try {
        const res = await fetch(`/api/requests/detail?id=${id}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        currentInspectorData = data;

        document.getElementById('inspector-modal-id-badge').textContent = `#${data.id}`;
        document.getElementById('inspector-meta-ip').textContent = data.remote_ip || '-';
        document.getElementById('inspector-meta-port-sensor').textContent = `Port ${data.port || 80} (${data.sensor_id || 'local'})`;
        document.getElementById('inspector-meta-timestamp').textContent = formatDate(data.created_at);
        const geoParts = [data.country_name, data.asn ? `${data.asn} ${data.as_name || ''}` : ''].filter(Boolean);
        document.getElementById('inspector-meta-geo').textContent = geoParts.length > 0 ? geoParts.join(' | ') : 'Local / Unknown';
        document.getElementById('inspector-meta-size').textContent = `${data.size_bytes || 0} bytes`;

        switchInspectorTab(currentInspectorTab || 'raw');
    } catch (err) {
        console.error('Failed to load request detail:', err);
        document.getElementById('inspector-content').textContent = `Failed to load request payload: ${err.message}`;
    }
}

function closeRequestInspector() {
    const modal = document.getElementById('modal-request-inspector');
    if (modal) modal.style.display = 'none';
    currentInspectorData = null;
    const dlMenu = document.getElementById('inspector-dl-menu');
    if (dlMenu) dlMenu.style.display = 'none';
}

function switchInspectorTab(tab) {
    currentInspectorTab = tab;
    document.querySelectorAll('.inspector-tab').forEach(b => b.classList.remove('active'));
    const activeBtn = document.getElementById(`tab-btn-${tab}`);
    if (activeBtn) activeBtn.classList.add('active');

    const contentEl = document.getElementById('inspector-content');
    if (!contentEl || !currentInspectorData) return;

    switch (tab) {
        case 'hex':
            contentEl.textContent = currentInspectorData.hexdump || 'No hex dump available';
            break;
        case 'ascii':
            contentEl.textContent = currentInspectorData.ascii_escaped || 'No ASCII representation available';
            break;
        case 'base64':
            contentEl.textContent = currentInspectorData.raw_base64 || 'No Base64 representation available';
            break;
        default: // raw
            contentEl.textContent = currentInspectorData.raw_data || 'No raw data available';
            break;
    }
}

function copyInspectorContent() {
    const contentEl = document.getElementById('inspector-content');
    if (!contentEl) return;
    const text = contentEl.textContent;
    navigator.clipboard.writeText(text).then(() => {
        const copyBtn = document.querySelector('#modal-request-inspector .copy-btn');
        if (copyBtn) {
            const orig = copyBtn.textContent;
            copyBtn.textContent = '✅ Copied!';
            setTimeout(() => { copyBtn.textContent = orig; }, 1800);
        }
    }).catch(err => {
        console.error('Clipboard copy failed:', err);
    });
}

function toggleInspectorDownloadMenu(e) {
    if (e) e.stopPropagation();
    const menu = document.getElementById('inspector-dl-menu');
    if (!menu) return;
    menu.style.display = (menu.style.display === 'block') ? 'none' : 'block';
}

function downloadActiveInspector(format) {
    if (!currentInspectorData || !currentInspectorData.id) return;
    const dlMenu = document.getElementById('inspector-dl-menu');
    if (dlMenu) dlMenu.style.display = 'none';
    let url = `/api/requests/download?id=${currentInspectorData.id}&format=${format}`;
    if (format === 'rawhex') {
        url = `/api/requests/download?id=${currentInspectorData.id}&format=hex&type=raw`;
    }
    window.open(url, '_blank');
}

