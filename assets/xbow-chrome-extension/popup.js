document.addEventListener('DOMContentLoaded', async () => {
  const targetUrlEl = document.getElementById('targetUrl');
  const apiKeyEl = document.getElementById('apiKey');
  const launchBtn = document.getElementById('launchBtn');
  const errorMsg = document.getElementById('errorMsg');
  const resultsSection = document.getElementById('resultsSection');
  const logsEl = document.getElementById('logs');

  let activeScanId = null;
  let pollInterval = null;

  // 1. Get current active tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url) {
    targetUrlEl.value = new URL(tab.url).origin; // Base origin
  }

  // 2. Load saved API key
  const { xbowApiKey } = await chrome.storage.local.get(['xbowApiKey']);
  if (xbowApiKey) {
    apiKeyEl.value = xbowApiKey;
  }

  // Helper for logging
  function logMsg(msg, isError = false, isFinding = false) {
    const p = document.createElement('p');
    p.textContent = `> ${msg}`;
    if (isError) p.style.color = '#ff4444';
    if (isFinding) p.className = 'finding';
    logsEl.appendChild(p);
    logsEl.scrollTop = logsEl.scrollHeight;
  }

  // Launch button handler
  launchBtn.addEventListener('click', async () => {
    const key = apiKeyEl.value.trim();
    const url = targetUrlEl.value.trim();

    if (!key) {
      errorMsg.textContent = 'API Key is required';
      errorMsg.style.display = 'block';
      return;
    }

    if (!url.startsWith('http')) {
      errorMsg.textContent = 'Invalid Target URL';
      errorMsg.style.display = 'block';
      return;
    }

    // Save key
    await chrome.storage.local.set({ xbowApiKey: key });

    errorMsg.style.display = 'none';
    resultsSection.style.display = 'block';
    launchBtn.disabled = true;
    launchBtn.textContent = 'Swarm Active...';

    logsEl.innerHTML = '';
    logMsg(`Authenticating to XBOW...`);
    logMsg(`Target: ${url}`);

    // Call API
    try {
      const resp = await fetch('https://api.xbow.com/v1/scans', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${key}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          target: { url: url },
          settings: { mode: "autonomous", confirm_exploits: true }
        })
      });

      if (!resp.ok) {
        const txt = await resp.text();
        throw new Error(`HTTP ${resp.status} - ${txt}`);
      }

      const data = await resp.json();
      activeScanId = data.id;
      logMsg(`Scan ID: ${activeScanId}`, false, true);
      logMsg(`Agents analyzing attack surface...`);

      // Start polling
      pollInterval = setInterval(() => pollStatus(key, activeScanId), 15000);

    } catch (err) {
      logMsg(`Launch Error: ${err.message}`, true);
      launchBtn.disabled = false;
      launchBtn.textContent = 'Launch Autonomous Scan';
    }
  });

  async function pollStatus(key, scanId) {
    try {
      // Check Status
      const stResp = await fetch(`https://api.xbow.com/v1/scans/${scanId}`, {
        headers: { 'Authorization': `Bearer ${key}` }
      });
      const stData = await stResp.json();
      
      const st = (stData.status || '').toLowerCase();
      logMsg(`Status: ${stData.status || 'running'} | Progress: ${stData.progress || '?'}`);

      if (st === 'completed' || st === 'failed') {
        clearInterval(pollInterval);
        logMsg(`Scan finalized! Fetching findings...`);
        fetchFindings(key, scanId);
      }

    } catch (err) {
      logMsg(`Poll Error: ${err.message}`, true);
    }
  }

  async function fetchFindings(key, scanId) {
    try {
      const fdResp = await fetch(`https://api.xbow.com/v1/scans/${scanId}/findings`, {
        headers: { 'Authorization': `Bearer ${key}` }
      });
      const fdData = await fdResp.json();
      
      const items = fdData.findings || [];
      if (items.length === 0) {
        logMsg(`Scan finished. No verified exploits found.`, false, true);
      } else {
        logMsg(`Scan finished. ${items.length} confirmed exploits!`, false, true);
        items.forEach(f => {
          logMsg(`[${f.severity || 'HIGH'}] ${f.title}`, false, true);
        });
      }

      launchBtn.disabled = false;
      launchBtn.textContent = 'Launch New Scan';
    } catch (err) {
      logMsg(`Findings Error: ${err.message}`, true);
    }
  }
});
