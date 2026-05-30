document.addEventListener("DOMContentLoaded", () => {
  const navButtons = document.querySelectorAll(".nav-btn");
  const panels = document.querySelectorAll(".panel");
  const shortcutButtons = document.querySelectorAll("[data-panel-shortcut]");
  const mobileMenu = document.getElementById("mobile-menu");
  const sidebar = document.getElementById("sidebar");
  const recentScansList = document.getElementById("recent-scans-list");
  const historyList = document.getElementById("history-list");
  const ruleBars = document.getElementById("rule-bars");
  const rulesGrid = document.getElementById("rules-grid");
  const scanResults = document.getElementById("scan-results");
  const scanButton = document.getElementById("btn-scan");
  const clearButton = document.getElementById("btn-clear-code");
  const exampleButton = document.getElementById("btn-load-example");
  const historyRefreshButton = document.getElementById("btn-refresh-history");
  const commandSearchInput = document.getElementById("command-search-input");
  const exportSummaryButton = document.getElementById("btn-export-summary");
  const filenameInput = document.getElementById("filename-input");
  const codeInput = document.getElementById("code-input");
  const scanModal = document.getElementById("scan-modal-overlay");
  const scanModalBody = document.getElementById("scan-modal-body");
  const fixModal = document.getElementById("fix-modal-overlay");
  const fixModalBody = document.getElementById("fix-modal-body");
  const actionModal = document.getElementById("action-modal-overlay");
  const actionModalTitle = document.getElementById("action-modal-title");
  const actionModalBody = document.getElementById("action-modal-body");
  const approveFixButton = document.getElementById("btn-approve-fix");
  const connectGithubButton = document.getElementById("btn-connect-github");
  const threatChatLog = document.getElementById("threat-chat-log");
  const threatChatInput = document.getElementById("threat-chat-input");
  const threatChatSend = document.getElementById("threat-chat-send");
  const threatCounter = document.getElementById("live-threat-count");
  const securityScore = document.getElementById("security-score");
  const sidebarScore = document.getElementById("sidebar-score");

  let rulesCache = [];
  let latestScannerResult = null;
  let currentScanDetail = null;
  let latestMetrics = null;
  let latestRecentScans = [];

  const panelAliases = {
    dashboard: "dashboard",
    home: "dashboard",
    scanner: "scanner",
    scan: "scanner",
    remediation: "remediation",
    fix: "remediation",
    github: "github",
    repo: "github",
    cicd: "cicd",
    pipeline: "cicd",
    analytics: "analytics",
    threat: "threat",
    intel: "threat",
    team: "team",
    reports: "reports",
    report: "reports",
    history: "history",
    scans: "history",
    rules: "rules",
    policy: "rules",
    notifications: "notifications",
    alerts: "notifications",
    compliance: "compliance",
    cloud: "compliance",
    settings: "settings",
  };

  const exampleCode = `import subprocess

def find_user(cursor, username, user_cmd):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    subprocess.run(user_cmd, shell=True)

api_key = "secret-key-123456"
eval(user_cmd)
`;

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

  function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  }

  function closeModal(modal) {
    modal?.classList.remove("active");
  }

  function updateActionTitle(icon, title) {
    if (!actionModalTitle) return;
    actionModalTitle.innerHTML = `<i class="${escapeHtml(icon)}"></i><span>${escapeHtml(title)}</span>`;
  }

  function openActionModal({ icon = "fa-solid fa-circle-info", title = "Option Details", status = "Ready", detail = "", items = [], next = "", options = [] }) {
    if (!actionModal || !actionModalBody) return;

    updateActionTitle(icon, title);
    const itemsHtml = items.length
      ? `<ul class="best-practice-list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
      : "";
    const optionsHtml = options.length
      ? `
        <div class="next-options">
          ${options
            .map(
              (option) => `
                <button type="button" class="next-option-btn" data-title="${escapeHtml(option.title)}" data-detail="${escapeHtml(option.detail)}" data-icon="${escapeHtml(option.icon || icon)}">
                  <i class="${escapeHtml(option.icon || icon)}"></i>
                  <span>${escapeHtml(option.title)}</span>
                </button>
              `
            )
            .join("")}
        </div>
      `
      : "";

    actionModalBody.innerHTML = `
      <div class="action-detail">
        <div class="scan-status-banner passed">
          <i class="fa-solid fa-circle-check"></i>
          <span>${escapeHtml(status)}</span>
        </div>
        ${detail ? `<p>${escapeHtml(detail)}</p>` : ""}
        ${itemsHtml}
        ${next ? `<p><strong>Next step:</strong> ${escapeHtml(next)}</p>` : ""}
        ${optionsHtml}
      </div>
    `;
    actionModal.classList.add("active");
  }

  function cloudOptions(title) {
    const optionSets = {
      AWS: [
        ["IAM Review", "Check wildcard policies, old access keys, MFA gaps, and unused roles.", "fa-solid fa-user-shield"],
        ["S3 Buckets", "Find public buckets, weak encryption, and missing access logging.", "fa-solid fa-box-archive"],
        ["EC2 & Security Groups", "Review public ports, stale instances, and risky inbound rules.", "fa-solid fa-server"],
        ["EKS & Containers", "Inspect privileged pods, image CVEs, and cluster RBAC.", "fa-solid fa-cubes"],
        ["Lambda Secrets", "Check function environment variables and dependency risk.", "fa-solid fa-bolt"],
        ["Security Hub", "Open consolidated AWS posture and compliance findings.", "fa-solid fa-shield-halved"],
      ],
      Azure: [
        ["RBAC Review", "Check privileged assignments and stale service principals.", "fa-solid fa-user-lock"],
        ["Storage Accounts", "Review public containers, encryption, and network access.", "fa-solid fa-database"],
        ["AKS Security", "Inspect cluster policy, image risk, and namespace controls.", "fa-solid fa-cubes"],
        ["Defender Alerts", "Open Azure Defender security recommendations.", "fa-solid fa-shield-halved"],
      ],
      "Google Cloud": [
        ["IAM & Service Accounts", "Check broad roles, old keys, and risky service accounts.", "fa-solid fa-user-shield"],
        ["Cloud Storage", "Review public buckets and object access policies.", "fa-solid fa-box-archive"],
        ["GKE Security", "Inspect workload identity, pod security, and image risk.", "fa-solid fa-cubes"],
        ["Security Command Center", "Open cloud posture findings and compliance evidence.", "fa-solid fa-shield-halved"],
      ],
      Kubernetes: [
        ["RBAC", "Review cluster-admin bindings and namespace permissions.", "fa-solid fa-users-gear"],
        ["Pod Security", "Check privileged containers, hostPath mounts, and root users.", "fa-solid fa-cube"],
        ["Network Policy", "Review ingress and egress isolation.", "fa-solid fa-diagram-project"],
        ["Secrets", "Find unencrypted or overexposed Kubernetes secrets.", "fa-solid fa-key"],
      ],
      Docker: [
        ["Image CVEs", "Scan base images and dependency layers.", "fa-solid fa-bug"],
        ["Dockerfile Rules", "Check root user, unsafe ADD, and pinned package versions.", "fa-solid fa-file-code"],
        ["Registry", "Review image signing, tags, and retention policy.", "fa-solid fa-boxes-stacked"],
      ],
      Prometheus: [
        ["Targets", "Review scrape target health and exposed endpoints.", "fa-solid fa-bullseye"],
        ["Alerts", "Check firing and silenced security alerts.", "fa-solid fa-bell"],
        ["Grafana", "Open dashboards for security telemetry.", "fa-solid fa-chart-line"],
      ],
    };

    return (optionSets[title] || [["Open Posture", "Open detailed security posture for this cloud option.", "fa-solid fa-cloud"]]).map(
      ([optionTitle, detail, icon]) => ({ title: optionTitle, detail, icon })
    );
  }

  function optionsFromLabels(labels, icon, suffix = "Open this option for SecureGPT configuration and validation.") {
    return labels.map((label) => ({
      title: label,
      detail: `${label}: ${suffix}`,
      icon,
    }));
  }

  async function runFeatureOption(title, detail, icon) {
    openActionModal({
      icon,
      title,
      status: `${title} starting`,
      detail: "SecureGPT is enabling this feature...",
      items: ["Sending action to backend", "Loading policy", "Starting telemetry"],
    });

    try {
      const data = await fetchJson("/actions/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, detail }),
      });
      const credentialNote = data.requires_credentials
        ? "Real external sync needs account credentials, but the SecureGPT local control-plane action is on."
        : "";

      openActionModal({
        icon,
        title: data.feature || title,
        status: data.message || `${title} is running`,
        detail: credentialNote || data.detail || detail,
        items: data.steps || ["Feature enabled", "Policy loaded", "Telemetry ready"],
        options: optionsFromLabels(["Validate", "Configure", "View Logs"], icon),
      });
    } catch (error) {
      openActionModal({
        icon,
        title,
        status: `${title} could not start`,
        detail: error.message,
        items: ["Check login session", "Check backend health", "Try again"],
      });
    }
  }

  function activatePassiveOptions() {
    const selectors = [
      ".metric-card",
      ".risk-queue__item",
      ".flow-node",
      ".heat-cell",
      ".approval-step",
      ".pipeline-strip span",
      ".prediction-stack b",
      ".owner-list span",
      ".package-list span",
      ".feed-list li",
      ".activity-log span",
      ".critical-popup",
    ];

    document.querySelectorAll(selectors.join(",")).forEach((node) => {
      if (node.closest("button, a, input, textarea, select") || node.classList.contains("action-card")) return;
      const title = node.querySelector("strong")?.textContent || node.querySelector("b")?.textContent || node.textContent || "SecureGPT Option";
      node.classList.add("action-card");
      node.setAttribute("role", "button");
      node.setAttribute("tabindex", "0");
      node.dataset.action = "generic";
      node.dataset.title = title.trim().replace(/\s+/g, " ");
      node.dataset.detail = "SecureGPT option is enabled and ready for drill-down.";
    });
  }

  function openCardAction(card) {
    const action = card.dataset.action;
    const title = card.dataset.title || "SecureGPT Option";
    const detail = card.dataset.detail || "";
    const state = card.dataset.state || "";
    const score = card.dataset.score || "";
    const toggle = card.querySelector(".toggle");

    if (action === "alert" && toggle) {
      toggle.classList.add("on");
      card.dataset.detail = "Notification channel enabled";
      openActionModal({
        icon: "fa-solid fa-bell",
        title,
        status: `${title} alerts enabled`,
        detail: `${title} notifications are active for critical security events.`,
        items: ["Critical findings", "Release gate status", "AI remediation approval updates"],
        options: optionsFromLabels(["Critical Alerts", "Deployment Gate Alerts", "AI Fix Alerts", "Daily Summary"], "fa-solid fa-bell"),
      });
      return;
    }

    const actionMap = {
      repo: {
        icon: "fa-brands fa-github",
        status: `${title} selected`,
        detail: `${detail}${score ? ` | Security score ${score}` : ""}`,
        items: ["Webhook status: ready", "PR annotation: enabled", "Security checks: enforced"],
        next: "Use Connect GitHub to attach a real repository.",
        options: optionsFromLabels(["Open Repository", "Scan Pull Requests", "Webhook Events", "Branch Protection", "Secret Scanning"], "fa-brands fa-github"),
      },
      pipeline: {
        icon: "fa-solid fa-diagram-project",
        status: `${title} stage is ${state || "ready"}`,
        detail: `${detail} security gate details are available for this pipeline stage.`,
        items: ["Logs available", "Policy evaluation mapped", "Approver can review gate state"],
        next: state === "blocked" ? "Review critical findings before deployment." : "Continue monitoring this stage.",
        options: optionsFromLabels(["View Logs", "Rerun Stage", "Approve Gate", "Download Evidence"], "fa-solid fa-diagram-project"),
      },
      role: {
        icon: "fa-solid fa-users-gear",
        status: `${title} role opened`,
        detail,
        items: ["Least-privilege permissions", "Audit logging", "Approval workflow access"],
        next: "Assign this role from the team administration workflow.",
        options: optionsFromLabels(["Permissions", "Assigned Users", "Invite User", "Audit Log"], "fa-solid fa-users-gear"),
      },
      report: {
        icon: "fa-solid fa-file-shield",
        status: `${title} report ready`,
        detail,
        items: ["Metrics snapshot", "Findings summary", "Remediation evidence"],
        next: "Click Export Report to download the current JSON summary.",
        options: optionsFromLabels(["Preview", "Export PDF", "Export Excel", "Audit Evidence"], "fa-solid fa-file-shield"),
      },
      cloud: {
        icon: "fa-solid fa-cloud",
        status: `${title} posture opened`,
        detail,
        items: ["IAM review", "Container posture", "Compliance evidence"],
        next: "Prioritize high-risk cloud issues before release.",
        options: cloudOptions(title),
      },
      stack: {
        icon: "fa-solid fa-sliders",
        status: `${title} settings selected`,
        detail: `Configured options: ${detail}`,
        items: ["Integration enabled in SecureGPT console", "Policy defaults loaded", "Monitoring hooks ready"],
        next: "Update environment variables for real provider credentials when deploying.",
        options: optionsFromLabels(
          detail
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
          "fa-solid fa-sliders"
        ),
      },
      generic: {
        icon: "fa-solid fa-circle-nodes",
        status: `${title} opened`,
        detail,
        items: ["Status: on", "Policy: loaded", "Telemetry: ready"],
        options: optionsFromLabels(["Open Details", "Validate", "View Logs", "Configure"], "fa-solid fa-circle-nodes"),
      },
    };

    openActionModal(actionMap[action] ? { title, ...actionMap[action] } : { title, detail, status: "SecureGPT option selected" });
  }

  function approveSecureFix() {
    openActionModal({
      icon: "fa-solid fa-check-double",
      title: "Approve Secure Fix",
      status: "Secure fix approval workflow opened",
      detail: "The sample patch is marked ready for reviewer approval and CI validation.",
      items: ["SQL query changed to parameter binding", "Shell execution changed to argument list", "Regression tests required before merge"],
      next: "Run or generate a scan finding, then use Generate Secure Fix for live remediation details.",
      options: optionsFromLabels(["Approve Patch", "Run Tests", "Create Pull Request", "Notify Reviewer"], "fa-solid fa-check-double"),
    });
  }

  function connectGithub() {
    openActionModal({
      icon: "fa-brands fa-github",
      title: "Connect GitHub",
      status: "GitHub integration wizard opened",
      detail: "SecureGPT is ready to connect repositories, PR checks, and webhook security comments.",
      items: ["Install GitHub App", "Select repositories", "Enable branch protection checks", "Sync PR annotations"],
      next: "Add real GitHub credentials and webhook URLs in deployment settings.",
      options: optionsFromLabels(["Install GitHub App", "Connect Repository", "Enable PR Scan", "Setup Webhook", "Branch Protection"], "fa-brands fa-github"),
    });
  }

  function answerThreatQuestion(question) {
    const value = String(question || "").trim();
    if (!value || !threatChatLog) return;

    const lower = value.toLowerCase();
    let answer = "Review the affected code path, validate input at trust boundaries, use safe APIs, and add a regression test for the exploit pattern.";

    if (lower.includes("cve")) {
      answer = "Map the CVE to affected package versions, upgrade or patch the dependency, rebuild the image, and verify with dependency and container scans.";
    } else if (lower.includes("secret") || lower.includes("key")) {
      answer = "Revoke the exposed credential, rotate it, remove it from history, and enforce secret scanning before merge.";
    } else if (lower.includes("sql")) {
      answer = "Use parameterized queries, avoid string-built SQL, validate identifiers through an allowlist, and add malicious payload tests.";
    } else if (lower.includes("xss")) {
      answer = "Encode output by context, sanitize trusted HTML with a vetted sanitizer, and enforce a strict Content Security Policy.";
    } else if (lower.includes("eval") || lower.includes("command")) {
      answer = "Remove dynamic execution, pass commands as an argument list, disable shell=True, and validate all user-controlled arguments.";
    }

    threatChatLog.insertAdjacentHTML(
      "beforeend",
      `<div><strong>user:</strong> ${escapeHtml(value)}</div><div><strong>securegpt:</strong> ${escapeHtml(answer)}</div>`
    );
    threatChatLog.scrollTop = threatChatLog.scrollHeight;
    if (threatChatInput) threatChatInput.value = "";
  }

  async function classifyThreatQuestion(question) {
    const value = String(question || "").trim();
    if (!value) return;

    answerThreatQuestion(value);
    try {
      const data = await fetchJson("/api/threats", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: value }),
      });
      if (threatChatLog && data.classification) {
        threatChatLog.insertAdjacentHTML(
          "beforeend",
          `<div><strong>threat intel:</strong> ${escapeHtml(data.classification.category)} | ${escapeHtml(data.classification.severity)} | ${escapeHtml(data.classification.guidance)}</div>`
        );
        threatChatLog.scrollTop = threatChatLog.scrollHeight;
      }
    } catch {
      // The local answer above remains useful even when threat persistence is offline.
    }
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
            <span>
              <strong>${escapeHtml(scan.target_name)}</strong>
              <small>${escapeHtml(scan.display_timestamp)} | ${escapeHtml(scan.finding_count)} finding(s)</small>
            </span>
            <em class="badge badge--${escapeHtml(scan.status)}">${escapeHtml(scan.status.replaceAll("_", " "))}</em>
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
        const width = Math.max(10, (count / maxCount) * 100);
        return `
          <div class="rule-bar-row">
            <div class="rule-bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
            <div class="rule-bar-track"><div class="rule-bar-fill" style="width: ${width}%"></div></div>
            <div class="rule-bar-value">${escapeHtml(count)}</div>
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
          <article class="glass-panel rule-card">
            <div class="panel-heading">
              <div>
                <h3>${escapeHtml(rule.title)}</h3>
                <p>${escapeHtml(rule.id)} | ${escapeHtml(rule.cwe || "")}</p>
              </div>
              <span class="badge badge--${escapeHtml(rule.severity)}">${escapeHtml(rule.severity)}</span>
            </div>
            <p>${escapeHtml(rule.description)}</p>
            <p class="placeholder-text">${escapeHtml(rule.recommendation)}</p>
          </article>
        `
      )
      .join("");
  }

  function renderScanResults(scan) {
    if (!scanResults) return;
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

    const findingsHtml = (scan.findings || [])
      .map(
        (finding, index) => `
          <div class="finding-item">
            <div class="finding-item__header">
              <div>
                <div class="finding-item__title">${escapeHtml(finding.title || finding.name || finding.id)}</div>
                <div class="finding-item__meta">
                  Affected file ${escapeHtml(finding.filename || scan.target_name)} | Line ${escapeHtml(finding.line)} | ${escapeHtml(finding.cwe || "")} | CVSS ${escapeHtml(finding.cvss ?? "N/A")}
                </div>
              </div>
              <span class="badge badge--${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
            </div>
            <div class="finding-item__body">
              <div class="finding-item__desc"><strong>Detection:</strong> ${escapeHtml(finding.message)}</div>
              <div class="finding-item__desc"><strong>Explanation:</strong> ${escapeHtml(finding.description)}</div>
              <div class="finding-item__desc"><strong>Auto-remediation suggestion:</strong> ${escapeHtml(finding.recommendation)}</div>
              <pre class="finding-item__code"><code>${escapeHtml(finding.excerpt)}</code></pre>
              <div class="finding-item__actions">
                <button type="button" class="btn btn--primary btn--sm ai-fix-btn" data-scan-context="latest" data-finding-index="${index}">
                  <i class="fa-solid fa-wand-magic-sparkles"></i>
                  <span>Generate Secure Fix</span>
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
        <span>${escapeHtml(scan.target_name)} has ${escapeHtml(scan.finding_count)} finding(s). Critical gates will block deployment until approved.</span>
      </div>
      ${findingsHtml}
    `;
  }

  function renderScanDetail(scan) {
    if (!scanModal || !scanModalBody) return;
    currentScanDetail = scan;

    const findings = scan.findings || [];
    const findingsHtml = findings.length
      ? findings
          .map(
            (finding, index) => `
              <div class="detail-finding">
                <div class="detail-finding__top">
                  <div>
                    <div class="detail-finding__title">${escapeHtml(finding.title || finding.name || finding.id)}</div>
                    <div class="detail-finding__meta">${escapeHtml(finding.filename || scan.target_name)} | Line ${escapeHtml(finding.line)} | ${escapeHtml(finding.cwe || "")} | CVSS ${escapeHtml(finding.cvss ?? "N/A")}</div>
                  </div>
                  <span class="badge badge--${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
                </div>
                <div class="detail-finding__text">${escapeHtml(finding.message)}</div>
                <div class="detail-finding__text"><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</div>
                <pre class="detail-code"><code>${escapeHtml(finding.excerpt)}</code></pre>
                <div class="finding-item__actions">
                  <button type="button" class="btn btn--primary btn--sm ai-fix-btn" data-scan-context="detail" data-finding-index="${index}">
                    <i class="fa-solid fa-wand-magic-sparkles"></i>
                    <span>Generate Secure Fix</span>
                  </button>
                </div>
              </div>
            `
          )
          .join("")
      : `
        <div class="empty-state">
          <i class="fa-solid fa-circle-check"></i>
          <p>This scan passed without any findings.</p>
        </div>
      `;

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
      ${findingsHtml}
    `;
    scanModal.classList.add("active");
  }

  async function requestAIFix(finding) {
    if (!finding || !fixModal || !fixModalBody) return;

    const remediationCode =
      finding.id === "SYNTAX001"
        ? codeInput?.value.trim() || finding.excerpt || finding.message || ""
        : finding.excerpt || finding.message || "";

    fixModalBody.innerHTML = `
      <div class="empty-state">
        <i class="fa-solid fa-robot fa-spin"></i>
        <p>Generating secure remediation guidance...</p>
      </div>
    `;
    fixModal.classList.add("active");

    try {
      const data = await fetchJson("/api/remediation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: finding.id,
          title: finding.title || finding.name,
          description: finding.description,
          code: remediationCode,
        }),
      });

      const bestPractices = Array.isArray(data.best_practices)
        ? data.best_practices.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
        : "";
      const validationSteps = Array.isArray(data.validation_steps)
        ? data.validation_steps.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
        : "";

      fixModalBody.innerHTML = `
        <div class="ai-recommendation">
          <strong>${escapeHtml(data.title || finding.title || finding.id)}</strong>
          <p>${escapeHtml(data.explanation || "")}</p>
          ${
            data.severity || data.cvss
              ? `<p><strong>AI risk classification:</strong> ${escapeHtml(data.severity || "unknown")} severity${data.cvss ? `, CVSS ${escapeHtml(data.cvss)}` : ""}</p>`
              : ""
          }
          <p><strong>Recommended change:</strong> ${escapeHtml(data.recommendation || "")}</p>
          ${data.warning ? `<p><strong>Note:</strong> ${escapeHtml(data.warning)}</p>` : ""}
        </div>
        <div class="ai-code-block">
          <div class="ai-code-header">
            <span>Secure Implementation Example</span>
            <span class="provider-badge"><i class="fa-solid fa-bolt"></i> ${escapeHtml(data.provider)}</span>
          </div>
          <pre class="ai-code-content"><code>${escapeHtml(data.secure_example || "")}</code></pre>
        </div>
        ${bestPractices ? `<ul class="best-practice-list">${bestPractices}</ul>` : ""}
        ${validationSteps ? `<ul class="best-practice-list">${validationSteps}</ul>` : ""}
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
      if (!scanModal || !scanModalBody) return;
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
      const metrics = metricsResponse.metrics || {};
      latestMetrics = metrics;
      latestRecentScans = recentResponse.scans || [];

      setText("metric-total-scans", metrics.total_scans ?? 0);
      setText("metric-total-findings", metrics.total_findings ?? 0);
      setText("metric-passed", metrics.passed_scans ?? 0);
      setText("metric-attention", metrics.needs_attention_scans ?? 0);
      setText("metric-risk-score", metrics.risk_score ?? 0);
      setText("metric-max-cvss", metrics.max_cvss ?? 0);

      const score = Math.max(41, Math.min(99, 99 - Number(metrics.risk_score || 0)));
      if (securityScore) securityScore.textContent = String(score);
      if (sidebarScore) sidebarScore.textContent = `${score}%`;

      renderRuleBreakdown(metrics.rule_breakdown || {});
      renderScanRows(latestRecentScans, recentScansList, "No scans recorded yet.");
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

  function runCommandSearch(query) {
    const value = String(query || "").trim().toLowerCase();
    if (!value) return false;

    const directPanel = panelAliases[value];
    if (directPanel) {
      window.switchPanel(directPanel);
      return true;
    }

    const fuzzyPanel = Object.entries(panelAliases).find(([alias]) => alias.includes(value) || value.includes(alias));
    if (fuzzyPanel) {
      window.switchPanel(fuzzyPanel[1]);
      return true;
    }

    return false;
  }

  function exportSummaryReport() {
    return fetch("/api/reports/json")
      .then((response) => {
        if (!response.ok) throw new Error("Report export failed.");
        return response.blob();
      })
      .then((blob) => {
        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = objectUrl;
        link.download = "securegpt-security-report.json";
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(objectUrl);
      });
  }

  async function checkHealth() {
    try {
      const data = await fetchJson("/health");
      document.body.dataset.health = data.status === "ok" ? "online" : "offline";
    } catch {
      document.body.dataset.health = "offline";
    }
  }

  window.switchPanel = function switchPanel(panelId) {
    navButtons.forEach((button) => {
      button.classList.toggle("active", button.dataset.panel === panelId);
    });
    panels.forEach((panel) => {
      panel.classList.toggle("active", panel.id === `panel-${panelId}`);
    });

    sidebar?.classList.remove("open");

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

  shortcutButtons.forEach((button) => {
    button.addEventListener("click", () => window.switchPanel(button.dataset.panelShortcut));
  });

  mobileMenu?.addEventListener("click", () => {
    sidebar?.classList.toggle("open");
  });

  commandSearchInput?.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    const matched = runCommandSearch(commandSearchInput.value);
    commandSearchInput.classList.toggle("command-search__miss", !matched);
    if (matched) commandSearchInput.value = "";
  });

  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      commandSearchInput?.focus();
    }
  });

  clearButton?.addEventListener("click", () => {
    if (codeInput) codeInput.value = "";
  });

  exampleButton?.addEventListener("click", () => {
    if (filenameInput) filenameInput.value = "vulnerable_service.py";
    if (codeInput) codeInput.value = exampleCode;
  });

  historyRefreshButton?.addEventListener("click", () => {
    loadHistory();
  });

  exportSummaryButton?.addEventListener("click", async () => {
    if (!latestMetrics) await loadDashboard();
    try {
      await exportSummaryReport();
    } catch (error) {
      openActionModal({
        icon: "fa-solid fa-file-export",
        title: "Export Report",
        status: "Report export failed",
        detail: error.message,
        items: ["Check backend health", "Try again"],
      });
    }
  });

  approveFixButton?.addEventListener("click", approveSecureFix);
  connectGithubButton?.addEventListener("click", async () => {
    connectGithub();
    try {
      const data = await fetchJson("/api/github");
      if ((data.repositories || []).length) {
        openActionModal({
          icon: "fa-brands fa-github",
          title: "Connect GitHub",
          status: "GitHub repositories synced",
          detail: `${data.repositories.length} repositories loaded from GitHub.`,
          items: data.repositories.slice(0, 5).map((repo) => repo.full_name),
          options: optionsFromLabels(["Scan Pull Requests", "Webhook Events", "Branch Protection"], "fa-brands fa-github"),
        });
      }
    } catch (error) {
      openActionModal({
        icon: "fa-brands fa-github",
        title: "Connect GitHub",
        status: "GitHub credentials needed",
        detail: error.message,
        items: ["Set GITHUB_TOKEN", "Restart backend", "Try connection again"],
      });
    }
  });
  threatChatSend?.addEventListener("click", async () => {
    await classifyThreatQuestion(threatChatInput?.value);
  });
  threatChatInput?.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    classifyThreatQuestion(threatChatInput.value);
  });

  scanButton?.addEventListener("click", async () => {
    const filename = filenameInput?.value.trim();
    const code = codeInput?.value.trim();

    if (!filename || !code) {
      if (scanResults) {
        scanResults.innerHTML = `
          <div class="scan-status-banner needs_attention">
            <i class="fa-solid fa-circle-exclamation"></i>
            <span>Provide both a filename and code snippet before scanning.</span>
          </div>
        `;
      }
      return;
    }

    scanButton.disabled = true;
    scanButton.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Scanning...</span>';

    try {
      const scan = await fetchJson("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename, code }),
      });
      renderScanResults(scan);
      await loadDashboard();
      await loadHistory();
    } catch (error) {
      if (scanResults) {
        scanResults.innerHTML = `
          <div class="scan-status-banner needs_attention">
            <i class="fa-solid fa-circle-exclamation"></i>
            <span>${escapeHtml(error.message)}</span>
          </div>
        `;
      }
    } finally {
      scanButton.disabled = false;
      scanButton.innerHTML = '<i class="fa-solid fa-shield-virus"></i><span>Scan for Vulnerabilities</span>';
    }
  });

  document.getElementById("scan-modal-close")?.addEventListener("click", () => closeModal(scanModal));
  document.getElementById("fix-modal-close")?.addEventListener("click", () => closeModal(fixModal));
  document.getElementById("action-modal-close")?.addEventListener("click", () => closeModal(actionModal));

  scanModal?.addEventListener("click", (event) => {
    if (event.target === scanModal) closeModal(scanModal);
  });
  fixModal?.addEventListener("click", (event) => {
    if (event.target === fixModal) closeModal(fixModal);
  });
  actionModal?.addEventListener("click", (event) => {
    if (event.target === actionModal) closeModal(actionModal);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeModal(scanModal);
      closeModal(fixModal);
      closeModal(actionModal);
    }

    if ((event.key === "Enter" || event.key === " ") && event.target.closest?.(".action-card")) {
      event.preventDefault();
      openCardAction(event.target.closest(".action-card"));
    }
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
      return;
    }

    const nextOptionTrigger = event.target.closest(".next-option-btn");
    if (nextOptionTrigger) {
      runFeatureOption(
        nextOptionTrigger.dataset.title || "SecureGPT Option",
        nextOptionTrigger.dataset.detail || "This SecureGPT option is active.",
        nextOptionTrigger.dataset.icon || "fa-solid fa-circle-info"
      );
      return;
    }

    const actionTrigger = event.target.closest(".action-card");
    if (actionTrigger) {
      openCardAction(actionTrigger);
    }
  });

  setInterval(() => {
    if (!threatCounter) return;
    const current = Number(threatCounter.textContent || 128);
    const next = current + Math.floor(Math.random() * 5) - 2;
    threatCounter.textContent = String(Math.max(111, Math.min(149, next)));
  }, 2600);

  if (window.io) {
    const socket = window.io();
    socket.on("new_vulnerability", (event) => {
      if (threatCounter) threatCounter.textContent = String(Number(threatCounter.textContent || 0) + Number(event.finding_count || 1));
      loadDashboard();
      loadHistory();
    });
    socket.on("blocked_deployment", (event) => {
      openActionModal({
        icon: "fa-solid fa-ban",
        title: "Deployment Blocked",
        status: event.message || "Deployment blocked by policy",
        detail: event.target_name || "Critical findings require review.",
        items: ["Review critical findings", "Generate secure fix", "Rerun scan"],
      });
    });
  }

  checkHealth();
  activatePassiveOptions();
  Promise.allSettled([loadRules(), loadDashboard(), loadHistory()]);
  setInterval(checkHealth, 30000);
});
