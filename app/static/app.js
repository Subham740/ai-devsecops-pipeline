document.addEventListener("DOMContentLoaded", () => {
  const navButtons = document.querySelectorAll(".nav-btn");
  const panels = document.querySelectorAll(".panel");
  const healthIndicator = document.getElementById("health-indicator");
  const backendLabel = document.getElementById("backend-label");
  const aiLabel = document.getElementById("ai-label");
  const recentScansList = document.getElementById("recent-scans-list");
  const historyList = document.getElementById("history-list");
  const ruleBars = document.getElementById("rule-bars");
  const rulesGrid = document.getElementById("rules-grid");
  const scanResults = document.getElementById("scan-results");
  const scanButton = document.getElementById("btn-scan");
  const clearButton = document.getElementById("btn-clear-code");
  const historyRefreshButton = document.getElementById("btn-refresh-history");
  const filenameInput = document.getElementById("filename-input");
  const codeInput = document.getElementById("code-input");
  const scanModal = document.getElementById("scan-modal-overlay");
  const scanModalBody = document.getElementById("scan-modal-body");
  const fixModal = document.getElementById("fix-modal-overlay");
  const fixModalBody = document.getElementById("fix-modal-body");

  let rulesCache = [];
  let latestScannerResult = null;
  let currentScanDetail = null;

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.message || "Request failed.");
    }
    return data;
  }

  function closeModal(modal) {
    modal.classList.remove("active");
  }

  function renderScanRows(scans, container, emptyMessage) {
    if (!container) return;

    if (!scans || scans.length === 0) {
      container.innerHTML = `<p class="placeholder-text">${escapeHtml(emptyMessage)}</p>`;
      return;
    }

    container.innerHTML = scans
      .map(
        (scan) => `
          <button type="button" class="scan-item" data-scan-id="${escapeHtml(scan.id)}">
            <div class="scan-item__info">
              <div class="scan-item__target">${escapeHtml(scan.target_name)}</div>
              <div class="scan-item__meta">
                <span>${escapeHtml(scan.display_timestamp)}</span>
                <span>${escapeHtml(scan.finding_count)} finding(s)</span>
              </div>
            </div>
            <div class="scan-item__stats">
              <span class="badge badge--${escapeHtml(scan.status)}">${escapeHtml(scan.status.replaceAll("_", " "))}</span>
            </div>
          </button>
        `
      )
      .join("");
  }

  function renderRuleBreakdown(ruleBreakdown) {
    if (!ruleBars) return;
    const entries = Object.entries(ruleBreakdown || {});
    if (entries.length === 0) {
      ruleBars.innerHTML = '<p class="placeholder-text">No findings registered yet.</p>';
      return;
    }

    const titleMap = Object.fromEntries(rulesCache.map((rule) => [rule.id, rule.title]));
    const maxCount = Math.max(...entries.map(([, count]) => count));

    ruleBars.innerHTML = entries
      .map(([ruleId, count]) => {
        const label = titleMap[ruleId] || ruleId;
        const width = Math.max(8, (count / maxCount) * 100);
        return `
          <div class="rule-bar-row">
            <div class="rule-bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
            <div class="rule-bar-track">
              <div class="rule-bar-fill" style="width: ${width}%"></div>
            </div>
            <div class="rule-bar-value">${count}</div>
          </div>
        `;
      })
      .join("");
  }

  function renderRules(rules) {
    if (!rulesGrid) return;
    if (!rules || rules.length === 0) {
      rulesGrid.innerHTML = '<p class="placeholder-text">No rules available.</p>';
      return;
    }

    rulesGrid.innerHTML = rules
      .map(
        (rule) => `
          <article class="glass-card rule-card">
            <div class="glass-card__header">
              <div style="font-weight: 700;">${escapeHtml(rule.title)}</div>
              <span class="badge badge--${escapeHtml(rule.severity)}">${escapeHtml(rule.severity)}</span>
            </div>
            <div class="rule-card__id">${escapeHtml(rule.id)} | ${escapeHtml(rule.cwe || "")}</div>
            <div class="rule-card__desc">${escapeHtml(rule.description)}</div>
            <div class="rule-card__footer">${escapeHtml(rule.recommendation)}</div>
          </article>
        `
      )
      .join("");
  }

  function renderScanResults(scan) {
    latestScannerResult = scan;

    if (scan.status === "passed") {
      scanResults.innerHTML = `
        <div class="scan-status-banner passed">
          <i class="fa-solid fa-circle-check"></i>
          <span>${escapeHtml(scan.target_name)} passed. No vulnerabilities were detected.</span>
        </div>
      `;
      return;
    }

    const findingsHtml = scan.findings
      .map(
        (finding, index) => `
          <div class="finding-item">
            <div class="finding-item__header">
              <div>
                <div class="finding-item__title">${escapeHtml(finding.title)}</div>
                <div class="finding-item__meta">Rule ${escapeHtml(finding.id)} | ${escapeHtml(finding.cwe || "")} | Line ${escapeHtml(finding.line)}</div>
              </div>
              <span class="badge badge--${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
            </div>
            <div class="finding-item__body">
              <div class="finding-item__desc">${escapeHtml(finding.message)}</div>
              <div class="finding-item__desc"><strong>Why it matters:</strong> ${escapeHtml(finding.description)}</div>
              <div class="finding-item__desc"><strong>Recommended action:</strong> ${escapeHtml(finding.recommendation)}</div>
              <pre class="finding-item__code"><code>${escapeHtml(finding.excerpt)}</code></pre>
              <div class="finding-item__actions">
                <button type="button" class="btn btn--primary btn--sm ai-fix-btn" data-scan-context="latest" data-finding-index="${index}">
                  <i class="fa-solid fa-wand-magic-sparkles"></i>
                  <span>Ask AI for Fix</span>
                </button>
              </div>
            </div>
          </div>
        `
      )
      .join("");

    scanResults.innerHTML = `
      <div class="scan-status-banner needs_attention">
        <i class="fa-solid fa-triangle-exclamation"></i>
        <span>${escapeHtml(scan.target_name)} has ${escapeHtml(scan.finding_count)} finding(s).</span>
      </div>
      ${findingsHtml}
    `;
  }

  function renderScanDetail(scan) {
    currentScanDetail = scan;

    if (!scan.findings || scan.findings.length === 0) {
      scanModalBody.innerHTML = `
        <div class="detail-meta-grid">
          <div class="detail-meta-card">
            <div class="detail-meta-card__label">Target</div>
            <div class="detail-meta-card__value">${escapeHtml(scan.target_name)}</div>
          </div>
          <div class="detail-meta-card">
            <div class="detail-meta-card__label">Status</div>
            <div class="detail-meta-card__value">${escapeHtml(scan.status)}</div>
          </div>
          <div class="detail-meta-card">
            <div class="detail-meta-card__label">Findings</div>
            <div class="detail-meta-card__value">0</div>
          </div>
        </div>
        <div class="empty-state">
          <i class="fa-solid fa-circle-check"></i>
          <p>This scan passed without any findings.</p>
        </div>
      `;
      scanModal.classList.add("active");
      return;
    }

    const findingsHtml = scan.findings
      .map(
        (finding, index) => `
          <div class="detail-finding">
            <div class="detail-finding__top">
              <div>
                <div class="detail-finding__title">${escapeHtml(finding.title)} (${escapeHtml(finding.id)})</div>
                <div class="detail-finding__meta">${escapeHtml(finding.filename)} | Line ${escapeHtml(finding.line)} | ${escapeHtml(finding.cwe || "")}</div>
              </div>
              <span class="badge badge--${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
            </div>
            <div class="detail-finding__text">${escapeHtml(finding.message)}</div>
            <div class="detail-finding__text"><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</div>
            <pre class="detail-code"><code>${escapeHtml(finding.excerpt)}</code></pre>
            <div class="finding-item__actions" style="margin-top: 0.75rem;">
              <button type="button" class="btn btn--primary btn--sm ai-fix-btn" data-scan-context="detail" data-finding-index="${index}">
                <i class="fa-solid fa-wand-magic-sparkles"></i>
                <span>Generate Secure Fix</span>
              </button>
            </div>
          </div>
        `
      )
      .join("");

    scanModalBody.innerHTML = `
      <div class="detail-meta-grid">
        <div class="detail-meta-card">
          <div class="detail-meta-card__label">Target</div>
          <div class="detail-meta-card__value">${escapeHtml(scan.target_name)}</div>
        </div>
        <div class="detail-meta-card">
          <div class="detail-meta-card__label">Status</div>
          <div class="detail-meta-card__value">${escapeHtml(scan.status.replaceAll("_", " "))}</div>
        </div>
        <div class="detail-meta-card">
          <div class="detail-meta-card__label">Findings</div>
          <div class="detail-meta-card__value">${escapeHtml(scan.finding_count)}</div>
        </div>
      </div>
      <h3 class="detail-section-title">Detected Issues</h3>
      ${findingsHtml}
    `;
    scanModal.classList.add("active");
  }

  async function requestAIFix(finding) {
    if (!finding) return;

    fixModalBody.innerHTML = `
      <div class="empty-state">
        <i class="fa-solid fa-robot fa-spin"></i>
        <p>Generating secure remediation guidance...</p>
      </div>
    `;
    fixModal.classList.add("active");

    try {
      const data = await fetchJson("/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: finding.id,
          title: finding.title,
          description: finding.description,
          code: finding.excerpt || finding.message || "",
        }),
      });

      const bestPractices = Array.isArray(data.best_practices)
        ? data.best_practices.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
        : "";

      fixModalBody.innerHTML = `
        <div class="ai-recommendation">
          <strong>${escapeHtml(data.title || finding.title)}</strong>
          <p>${escapeHtml(data.explanation || "")}</p>
          <p><strong>Recommended change:</strong> ${escapeHtml(data.recommendation || "")}</p>
          ${data.warning ? `<p><strong>Note:</strong> ${escapeHtml(data.warning)}</p>` : ""}
        </div>
        <div class="ai-code-block">
          <div class="ai-code-header">
            <span>Secure Implementation Example</span>
            <span class="provider-badge"><i class="fa-solid fa-bolt"></i>${escapeHtml(data.provider)}</span>
          </div>
          <pre class="ai-code-content"><code>${escapeHtml(data.secure_example || "")}</code></pre>
        </div>
        ${bestPractices ? `<ul class="best-practice-list">${bestPractices}</ul>` : ""}
      `;
    } catch (error) {
      fixModalBody.innerHTML = `
        <div class="scan-status-banner needs_attention">
          <i class="fa-solid fa-circle-exclamation"></i>
          <span>${escapeHtml(error.message)}</span>
        </div>
      `;
    }
  }

  async function viewScanDetails(scanId) {
    try {
      const data = await fetchJson(`/scans/${encodeURIComponent(scanId)}`);
      renderScanDetail(data.scan);
    } catch (error) {
      scanModalBody.innerHTML = `
        <div class="scan-status-banner needs_attention">
          <i class="fa-solid fa-circle-exclamation"></i>
          <span>${escapeHtml(error.message)}</span>
        </div>
      `;
      scanModal.classList.add("active");
    }
  }

  async function loadDashboard() {
    try {
      const metricsResponse = await fetchJson("/metrics");
      const recentResponse = await fetchJson("/scans?limit=5");
      const metrics = metricsResponse.metrics;

      document.getElementById("metric-total-scans").textContent = metrics.total_scans;
      document.getElementById("metric-total-findings").textContent = metrics.total_findings;
      document.getElementById("metric-passed").textContent = metrics.passed_scans;
      document.getElementById("metric-attention").textContent = metrics.needs_attention_scans;

      renderRuleBreakdown(metrics.rule_breakdown || {});
      renderScanRows(recentResponse.scans, recentScansList, "No scans recorded yet.");
    } catch (error) {
      if (recentScansList) {
        recentScansList.innerHTML = `<p class="placeholder-text">${escapeHtml(error.message)}</p>`;
      }
    }
  }

  async function loadHistory() {
    try {
      const response = await fetchJson("/scans?limit=50");
      renderScanRows(response.scans, historyList, "No scans recorded yet.");
    } catch (error) {
      if (historyList) {
        historyList.innerHTML = `<p class="placeholder-text">${escapeHtml(error.message)}</p>`;
      }
    }
  }

  async function loadRules() {
    try {
      const response = await fetchJson("/rules");
      rulesCache = response.rules || [];
      renderRules(rulesCache);
    } catch (error) {
      if (rulesGrid) {
        rulesGrid.innerHTML = `<p class="placeholder-text">${escapeHtml(error.message)}</p>`;
      }
    }
  }

  async function checkHealth() {
    try {
      const data = await fetchJson("/health");
      const dot = healthIndicator.querySelector(".status-dot");
      const text = healthIndicator.querySelector(".status-text");

      dot.className = `status-dot ${data.status === "ok" ? "online" : "offline"}`;
      text.textContent = data.status === "ok" ? "System online" : "System unavailable";
      backendLabel.textContent = String(data.data_backend || "unknown").toUpperCase();
      aiLabel.textContent = data.ai_enabled ? `${String(data.ai_provider || "ai").toUpperCase()} ready` : "Unavailable";
    } catch (error) {
      const dot = healthIndicator.querySelector(".status-dot");
      const text = healthIndicator.querySelector(".status-text");
      dot.className = "status-dot offline";
      text.textContent = "Health check failed";
      backendLabel.textContent = "Unknown";
      aiLabel.textContent = "Unavailable";
    }
  }

  window.switchPanel = function switchPanel(panelId) {
    navButtons.forEach((button) => {
      button.classList.toggle("active", button.dataset.panel === panelId);
    });
    panels.forEach((panel) => {
      panel.classList.toggle("active", panel.id === `panel-${panelId}`);
    });

    if (panelId === "dashboard") {
      loadDashboard();
    } else if (panelId === "history") {
      loadHistory();
    } else if (panelId === "rules") {
      loadRules();
    }
  };

  navButtons.forEach((button) => {
    button.addEventListener("click", () => window.switchPanel(button.dataset.panel));
  });

  clearButton?.addEventListener("click", () => {
    codeInput.value = "";
  });

  historyRefreshButton?.addEventListener("click", () => {
    loadHistory();
  });

  scanButton?.addEventListener("click", async () => {
    const filename = filenameInput.value.trim();
    const code = codeInput.value.trim();

    if (!filename || !code) {
      scanResults.innerHTML = `
        <div class="scan-status-banner needs_attention">
          <i class="fa-solid fa-circle-exclamation"></i>
          <span>Provide both a filename and code snippet before scanning.</span>
        </div>
      `;
      return;
    }

    scanButton.disabled = true;
    scanButton.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Scanning...</span>';

    try {
      const scan = await fetchJson("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename, code }),
      });
      renderScanResults(scan);
      await loadDashboard();
      await loadHistory();
    } catch (error) {
      scanResults.innerHTML = `
        <div class="scan-status-banner needs_attention">
          <i class="fa-solid fa-circle-exclamation"></i>
          <span>${escapeHtml(error.message)}</span>
        </div>
      `;
    } finally {
      scanButton.disabled = false;
      scanButton.innerHTML = '<i class="fa-solid fa-shield-virus"></i><span>Scan for Vulnerabilities</span>';
    }
  });

  document.getElementById("scan-modal-close")?.addEventListener("click", () => closeModal(scanModal));
  document.getElementById("fix-modal-close")?.addEventListener("click", () => closeModal(fixModal));
  scanModal?.addEventListener("click", (event) => {
    if (event.target === scanModal) closeModal(scanModal);
  });
  fixModal?.addEventListener("click", (event) => {
    if (event.target === fixModal) closeModal(fixModal);
  });

  document.addEventListener("click", (event) => {
    const scanTrigger = event.target.closest(".scan-item[data-scan-id]");
    if (scanTrigger) {
      viewScanDetails(scanTrigger.dataset.scanId);
      return;
    }

    const fixTrigger = event.target.closest(".ai-fix-btn");
    if (fixTrigger) {
      const index = Number(fixTrigger.dataset.findingIndex);
      const context = fixTrigger.dataset.scanContext;
      const finding = context === "detail" ? currentScanDetail?.findings?.[index] : latestScannerResult?.findings?.[index];
      requestAIFix(finding);
    }
  });

  checkHealth();
  Promise.allSettled([loadRules(), loadDashboard(), loadHistory()]);
  setInterval(checkHealth, 30000);
});
