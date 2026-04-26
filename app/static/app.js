document.addEventListener('DOMContentLoaded', () => {
    // ==== Navigation ====
    const navBtns = document.querySelectorAll('.nav-btn');
    const panels = document.querySelectorAll('.panel');
  
    // Add global switchPanel function
    window.switchPanel = function(panelId) {
      navBtns.forEach(btn => btn.classList.remove('active'));
      panels.forEach(panel => panel.classList.remove('active'));
      
      const targetBtn = document.getElementById(`nav-${panelId}`);
      const targetPanel = document.getElementById(`panel-${panelId}`);
      if (targetBtn) targetBtn.classList.add('active');
      if (targetPanel) targetPanel.classList.add('active');
  
      if (panelId === 'dashboard') loadDashboard();
      if (panelId === 'history') loadHistory();
      if (panelId === 'rules') loadRules();
    };
  
    navBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        window.switchPanel(btn.dataset.panel);
      });
    });
  
    // ==== Modals ====
    const fixModal = document.getElementById('fix-modal-overlay');
    const fixModalClose = document.getElementById('fix-modal-close');
    
    fixModalClose.addEventListener('click', () => {
      fixModal.classList.remove('active');
    });
    
    // Close modal on outside click
    fixModal.addEventListener('click', (e) => {
      if (e.target === fixModal) {
        fixModal.classList.remove('active');
      }
    });
  
    // ==== Core API logic ====
    
    async function checkHealth() {
      const indicator = document.getElementById('health-indicator');
      const dot = indicator.querySelector('.status-dot');
      const text = indicator.querySelector('.status-text');
      
      try {
        const res = await fetch('/health');
        if (res.ok) {
          dot.className = 'status-dot online';
          text.textContent = 'System Online';
        } else {
          throw new Error('Bad response');
        }
      } catch (err) {
        dot.className = 'status-dot offline';
        text.textContent = 'API Offline';
      }
    }
  
    // Generic function to create severity badges
    function createBadge(severity) {
      return `<span class="badge badge--${severity}">${severity}</span>`;
    }
  
    // ---- Dashboard ----
    async function loadDashboard() {
      try {
        const res = await fetch('/metrics');
        const data = await res.json();
        
        if (data.status === 'ok') {
          document.getElementById('metric-total-scans').textContent = data.metrics.total_scans;
          document.getElementById('metric-total-findings').textContent = data.metrics.total_findings;
          
          const passed = data.metrics.status_breakdown.passed || 0;
          const attention = data.metrics.status_breakdown.needs_attention || 0;
          
          document.getElementById('metric-passed').textContent = passed;
          document.getElementById('metric-attention').textContent = attention;
  
          // Render rule chart
          const rulesRes = await fetch('/rules');
          const rulesData = await rulesRes.json();
          let rulesMap = {};
          if (rulesData.status === 'ok') {
            rulesData.rules.forEach(r => rulesMap[r.id] = r.title);
          }
  
          const ruleBreakdown = data.metrics.rule_breakdown;
          const ruleBars = document.getElementById('rule-bars');
          
          if (Object.keys(ruleBreakdown).length > 0) {
            let maxCount = Math.max(...Object.values(ruleBreakdown));
            let html = '';
            for (const [ruleId, count] of Object.entries(ruleBreakdown)) {
              const width = Math.max(5, (count / maxCount) * 100);
              const title = rulesMap[ruleId] || ruleId;
              html += `
                <div class="rule-bar-row">
                  <div class="rule-bar-label" title="${title}">${title}</div>
                  <div class="rule-bar-track">
                    <div class="rule-bar-fill" style="width: ${width}%"></div>
                  </div>
                  <div class="rule-bar-value">${count}</div>
                </div>
              `;
            }
            ruleBars.innerHTML = html;
          } else {
             ruleBars.innerHTML = '<p class="placeholder-text">No findings registered yet.</p>';
          }
        }
  
        // Load recent scans
        loadRecentScans();
      } catch (err) {
        console.error("Dashboard error:", err);
      }
    }
  
    async function loadRecentScans() {
      try {
        const res = await fetch('/scans?limit=5');
        const data = await res.json();
        
        const list = document.getElementById('recent-scans-list');
        if (data.status === 'ok' && data.scans.length > 0) {
          list.innerHTML = data.scans.map(scan => renderScanItem(scan)).join('');
        } else {
          list.innerHTML = '<p class="placeholder-text">No recent scans found.</p>';
        }
      } catch (err) {
        console.error("Recent scans error:", err);
      }
    }
  
    function renderScanItem(scan) {
      const date = new Date(scan.created_at).toLocaleString();
      const needsAttention = scan.status === 'needs_attention';
      
      return `
        <div class="scan-item" onclick="viewScanDetails(${scan.id})">
          <div class="scan-item__info">
            <div class="scan-item__target">${scan.target_name}</div>
            <div class="scan-item__meta">
              <span>${date}</span>
              <span>Source: ${scan.source_type}</span>
            </div>
          </div>
          <div class="scan-item__stats">
            ${needsAttention 
              ? `<span style="color:var(--color-critical); font-weight:bold;">${scan.issue_count} Findings</span>`
              : `<span style="color:var(--color-passed); font-weight:bold;">Passed</span>`
            }
          </div>
        </div>
      `;
    }
  
    // ---- Global view function for scan detail ----
    window.viewScanDetails = function(scanId) {
      // In a real app we'd open a modal or new view.
      // For now, let's just alert since the template is a single page dashboard
      // Alternatively, we can switch to scanner and populate results...
      console.log('Viewing scan ID:', scanId);
      alert('View scan details for ID ' + scanId + ' (Not fully implemented in UI yet)');
    };
  
    // ---- Scanner ----
    const btnScan = document.getElementById('btn-scan');
    const btnLoadExample = document.getElementById('btn-load-example');
    const btnClearCode = document.getElementById('btn-clear-code');
    const codeInput = document.getElementById('code-input');
    const resultsContainer = document.getElementById('scan-results');
  
    const exampleCode = `import os
import subprocess
import pickle

def run_command(user_input):
    # Potential Command Injection
    os.system(user_input)
    result = subprocess.call(user_input, shell=True)
    return result

def get_user(username):
    # Potential SQL Injection
    query = 'SELECT * FROM users WHERE name = ''' + username + ''''
    return query

def load_data(payload):
    # Unsafe Deserialization
    return pickle.loads(payload)

# Hardcoded Secret
password = 'admin123'
secret_key = 'my-secret-key-hardcoded'
`;
  
    btnLoadExample.addEventListener('click', () => {
      codeInput.value = exampleCode;
      codeInput.style.height = 'auto'; // Reset height
      // Set height based on scroll height
      codeInput.style.height = (codeInput.scrollHeight + 10) + 'px';
    });
  
    btnClearCode.addEventListener('click', () => {
      codeInput.value = '';
    });
  
    btnScan.addEventListener('click', async () => {
      const code = codeInput.value.trim();
      if (!code) return alert("Please enter some code to scan.");
  
      btnScan.disabled = true;
      btnScan.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="animate-spin"><circle cx="12" cy="12" r="10"/><path d="M12 2v4"/></svg> Scanning...`;
      
      try {
        const res = await fetch('/scan', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ code: code, filename: 'dashboard_input.py' })
        });
        
        const data = await res.json();
        
        if (!res.ok) {
           resultsContainer.innerHTML = `<div class="scan-status-banner needs_attention">Error: ${data.message}</div>`;
           return;
        }
  
        renderScanResults(data, code);
        // Refresh dashboard metrics quietly
        loadDashboard(); 
  
      } catch (err) {
        resultsContainer.innerHTML = `<div class="scan-status-banner needs_attention">Network error during scan.</div>`;
      } finally {
        btnScan.disabled = false;
        btnScan.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Scan for Vulnerabilities`;
      }
    });
  
    function renderScanResults(data, originalCode) {
      if (data.status === 'passed') {
        resultsContainer.innerHTML = `
          <div class="scan-status-banner passed">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            Scan Passed: No vulnerabilities found in ${data.target_name}.
          </div>
        `;
        return;
      }
  
      let html = `
        <div class="scan-status-banner needs_attention">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Warning: Found ${data.finding_count} vulnerabilities.
        </div>
      `;
  
      data.findings.forEach(finding => {
        // Escaping literal code for display
        const escapedCode = finding.excerpt.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        // Create an encoded string to pass to the function
        const safeCode = encodeURIComponent(originalCode);
        const safeTitle = encodeURIComponent(finding.title);
        const safeDesc = encodeURIComponent(finding.description);
        
        html += `
          <div class="finding-item">
            <div class="finding-item__header">
              <div>
                <div class="finding-item__title">${finding.title}</div>
                <div class="finding-item__meta">Line ${finding.line} • Rule ${finding.id}</div>
              </div>
              ${createBadge(finding.severity)}
            </div>
            <div class="finding-item__body">
              <div class="finding-item__desc">${finding.description}</div>
              <pre class="finding-item__code"><code>${escapedCode}</code></pre>
              <div class="finding-item__actions">
                <button class="btn btn--primary btn--sm" onclick="getAIFix('${finding.id}', '${safeTitle}', '${safeDesc}', '${safeCode}')">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                  Suggest Fix (AI)
                </button>
              </div>
            </div>
          </div>
        `;
      });
  
      resultsContainer.innerHTML = html;
    }
  
    // ---- AI Fix ----
    window.getAIFix = async function(findingId, safeTitle, safeDesc, safeCode) {
      const fixModalBody = document.getElementById('fix-modal-body');
      fixModalBody.innerHTML = `
        <div style="text-align:center; padding: 2rem; color:var(--text-muted);">
           <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" class="animate-spin" style="margin-bottom:1rem"><circle cx="12" cy="12" r="10"/><path d="M12 2v4"/></svg>
           <p>Analyzing context and generating remediation...</p>
        </div>
      `;
      fixModal.classList.add('active');
  
      try {
        const res = await fetch('/fix', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            finding_id: findingId,
            title: decodeURIComponent(safeTitle),
            description: decodeURIComponent(safeDesc),
            code: decodeURIComponent(safeCode)
          })
        });
        
        const data = await res.json();
        
        if (data.status === 'ok') {
          const escapedExample = data.secure_example.replace(/</g, "&lt;").replace(/>/g, "&gt;");
          fixModalBody.innerHTML = `
            <div class="ai-recommendation">
              <strong>Recommendation:</strong><br/>
              ${data.recommendation}
            </div>
            
            <div class="ai-code-block">
              <div class="ai-code-header">
                <span>Secure Implementation Example</span>
                <span class="provider-badge">Provider: ${data.provider}</span>
              </div>
              <pre class="ai-code-content"><code>${escapedExample}</code></pre>
            </div>
          `;
        } else {
           fixModalBody.innerHTML = `<p style="color:var(--color-critical)">Error: ${data.message}</p>`;
        }
      } catch (err) {
        fixModalBody.innerHTML = `<p style="color:var(--color-critical)">Network error generating fix.</p>`;
      }
    };
  
    // ---- History ----
    async function loadHistory() {
      try {
        const res = await fetch('/scans?limit=50');
        const data = await res.json();
        
        const list = document.getElementById('history-list');
        if (data.status === 'ok' && data.scans.length > 0) {
          list.innerHTML = data.scans.map(scan => renderScanItem(scan)).join('');
        } else {
          list.innerHTML = '<p class="placeholder-text">No history found.</p>';
        }
      } catch (err) {
        console.error("History error:", err);
      }
    }
  
    // ---- Rules ----
    async function loadRules() {
      try {
        const res = await fetch('/rules');
        const data = await res.json();
        
        const grid = document.getElementById('rules-grid');
        if (data.status === 'ok' && data.rules.length > 0) {
          let html = '';
          data.rules.forEach(rule => {
             html += `
               <div class="glass-card rule-card">
                 <div class="glass-card__header" style="margin-bottom:0.5rem">
                   <div style="font-weight:600;">${rule.title}</div>
                   ${createBadge(rule.severity)}
                 </div>
                 <div class="rule-card__id">${rule.id}</div>
                 <div class="rule-card__desc">${rule.description}</div>
               </div>
             `;
          });
          grid.innerHTML = html;
        } else {
          grid.innerHTML = '<p class="placeholder-text">No rules available.</p>';
        }
      } catch (err) {
        console.error("Rules error:", err);
      }
    }
  
    // CSS for spinner animation inside JS just in case
    const style = document.createElement('style');
    style.innerHTML = `
      .animate-spin {
        animation: spin 1s linear infinite;
      }
      @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
  
    // ==== Init ====
    checkHealth();
    loadDashboard();
    
    // Poll health every 30s
    setInterval(checkHealth, 30000);
});
