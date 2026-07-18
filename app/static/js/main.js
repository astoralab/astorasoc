document.addEventListener("DOMContentLoaded", () => {
  initShellControls();
  initPageComponents();
});

let ravenLastUserActivity = Date.now();
let ravenLoginRedirecting = false;
let ravenLiveUpdatesStarted = false;
let ravenCasePollTimer = null;
let ravenAlertPollTimer = null;
let ravenAnalyticsTimer = null;
let ravenChatPollTimer = null;
let ravenConfirmState = { form: null, submitter: null, href: null };
["click", "keydown", "mousedown", "mousemove", "scroll", "touchstart"].forEach((eventName) => {
  window.addEventListener(eventName, () => {
    ravenLastUserActivity = Date.now();
  }, { passive: true });
});

function neuralLoaderHtml(label = "Working") {
  return `<span class="neural-loader" aria-hidden="true"><span></span><span></span><span></span></span><span>${escapeHtml(label)}</span>`;
}

function setActionLoading(element, loading, label = "Working") {
  if (!element) return;
  if (loading) {
    if (element.dataset.loading === "1") return;
    element.dataset.loading = "1";
    element.dataset.originalHtml = element.innerHTML;
    if (element.matches?.('input[type="submit"], input[type="button"], input[type="reset"]')) {
      element.dataset.originalValue = element.value || "";
    }
    element.classList.add("is-loading");
    element.setAttribute("aria-busy", "true");
    if ("disabled" in element) element.disabled = true;
    if (element.matches?.('input[type="submit"], input[type="button"], input[type="reset"]')) {
      element.value = label;
    } else {
      element.innerHTML = neuralLoaderHtml(label);
    }
    refreshIcons();
    return;
  }
  element.dataset.loading = "0";
  element.classList.remove("is-loading");
  element.removeAttribute("aria-busy");
  if ("disabled" in element) element.disabled = false;
  if (element.dataset.originalValue) element.value = element.dataset.originalValue;
  if (element.dataset.originalHtml) element.innerHTML = element.dataset.originalHtml;
  refreshIcons();
}

function setSectionLoading(target, loading) {
  if (!target) return;
  target.classList.toggle("section-busy", Boolean(loading));
  target.setAttribute("aria-busy", loading ? "true" : "false");
  if (!loading) target.removeAttribute("aria-busy");
}

function initPageComponents() {
  for (const field of document.querySelectorAll("input, textarea, form")) {
    if (field.dataset.allowAutocomplete === "1") continue;
    field.setAttribute("autocomplete", "off");
  }
  initFlashToasts();
  initRememberedLogin();
  initLoginLoading();
  initPasswordAutofillGuards();
  initMultiDropdowns();

  refreshIcons();
  initProfileCards();
  initImagePreview();
  initFileControls();
  initSecretControls();
  initAISettings();
  initReportDownloads();
  initAlertTriage();
  initCaseInvestigation();
  initContainmentConsole();
  initAlertWorkflowPolling();
  initCaseWorkflowPolling();
  initReviewMenus();
  initPlaybookForms();
  initAssetFilters();
  initAssetOwnerCards();
  initAssetStatusProbes();
  initAssetMetadataPickers();
  initAssetOsDetection();
  initDangerConfirm();
  if (window.RavenAnalytics && window.ApexCharts) {
    initThreatAnalytics(window.RavenAnalytics.endpoint);
  }
  initChatPage();
}

function initAssetFilters() {
  const bar = document.querySelector("[data-asset-filter-bar]");
  if (!bar || bar.dataset.assetFilterBound === "1") return;
  bar.dataset.assetFilterBound = "1";
  const controls = Array.from(bar.querySelectorAll("[data-asset-filter]"));
  const rows = Array.from(document.querySelectorAll("[data-asset-row]"));
  const empty = document.querySelector("[data-asset-empty]");
  const visibleCount = document.querySelector("[data-asset-visible-count]");
  const apply = () => {
    const filters = Object.fromEntries(controls.map((control) => [control.dataset.assetFilter, (control.value || "").toLowerCase().trim()]));
    let visible = 0;
    for (const row of rows) {
      const matchesSearch = !filters.search || (row.dataset.search || "").includes(filters.search);
      const matchesCriticality = !filters.criticality || (row.dataset.criticality || "").toLowerCase() === filters.criticality;
      const matchesStatus = !filters.status || (row.dataset.status || "").toLowerCase() === filters.status;
      const matchesType = !filters.asset_type || (row.dataset.asset_type || "").toLowerCase() === filters.asset_type;
      const matchesDepartment = !filters.department || (row.dataset.department || "").toLowerCase() === filters.department;
      const matchesOs = !filters.os || (row.dataset.os || "").toLowerCase() === filters.os;
      const show = matchesSearch && matchesCriticality && matchesStatus && matchesType && matchesDepartment && matchesOs;
      row.hidden = !show;
      if (show) visible += 1;
    }
    if (empty) empty.hidden = visible !== 0;
    if (visibleCount) visibleCount.textContent = visible;
  };
  for (const control of controls) {
    control.addEventListener("input", apply);
    control.addEventListener("change", apply);
  }
  apply();
}

function initAssetStatusProbes() {
  const badges = Array.from(document.querySelectorAll("[data-asset-status-url]"));
  if (!badges.length || document.body.dataset.assetStatusProbeBound === "1") return;
  document.body.dataset.assetStatusProbeBound = "1";
  const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";
  let index = 0;
  const worker = async () => {
    while (index < badges.length) {
      const badge = badges[index++];
      const row = badge.closest("[data-asset-row]");
      badge.classList.add("is-checking");
      badge.title = "Checking current reachability...";
      try {
        const response = await fetch(badge.dataset.assetStatusUrl, {
          method: "POST",
          headers: {
            Accept: "application/json",
            "X-CSRFToken": csrfToken,
          },
        });
        if (!response.ok) throw new Error("status_probe_failed");
        const data = await response.json();
        const status = data.status || "Unknown";
        badge.textContent = status;
        badge.className = `asset-status-badge asset-status-${status.toLowerCase()} `;
        badge.title = data.last_seen ? `Last reachable ${data.last_seen}` : "Checked current reachability.";
        if (row) row.dataset.status = status;
      } catch {
        badge.title = "Could not verify reachability right now.";
      } finally {
        badge.classList.remove("is-checking");
      }
    }
  };
  window.setTimeout(() => {
    const workers = Array.from({ length: Math.min(3, badges.length) }, worker);
    Promise.allSettled(workers);
  }, 300);
}

function initAssetOsDetection() {
  const button = document.querySelector("[data-detect-os]");
  const ipField = document.querySelector("[data-asset-ip]");
  const osField = document.querySelector("[data-asset-os]");
  const status = document.querySelector("[data-detect-os-status]");
  if (!button || !ipField || !osField || button.dataset.osDetectBound === "1") return;
  button.dataset.osDetectBound = "1";

  let detectTimer = null;
  const setStatus = (message, tone = "") => {
    if (!status) return;
    status.textContent = message;
    status.dataset.tone = tone;
  };
  const setLoading = (loading) => {
    button.disabled = loading;
    button.classList.toggle("is-loading", loading);
    button.setAttribute("aria-busy", loading ? "true" : "false");
  };
  const ensureOption = (value) => {
    if (!value) return;
    if (!Array.from(osField.options).some((option) => option.value === value)) {
      osField.append(new Option(value, value));
    }
  };
  const detect = async (silent = false) => {
    const ipAddress = ipField.value.trim();
    if (!ipAddress) {
      if (!silent) setStatus("Enter an IP address first. Manual OS selection stays available.", "warn");
      return;
    }
    setLoading(true);
    setStatus("Detecting OS from IP...", "loading");
    try {
      const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";
      const response = await fetch(button.dataset.detectOs, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: JSON.stringify({ ip_address: ipAddress }),
      });
      const data = await response.json();
      if (!response.ok || data.error) {
        setStatus(data.error || "OS detection failed. Choose manually.", "error");
        return;
      }
      if (data.detected && data.os) {
        ensureOption(data.os);
        osField.value = data.os;
        osField.dispatchEvent(new Event("change", { bubbles: true }));
        const ttl = data.ttl ? ` TTL ${data.ttl}` : "";
        const confidence = data.confidence ? `, ${String(data.confidence).toLowerCase()} confidence` : "";
        setStatus(`Detected ${data.os}.${ttl}${confidence}. You can still change it manually.`, "success");
      } else {
        setStatus(data.message || "Could not detect OS. Choose manually.", "warn");
      }
    } catch {
      setStatus("OS detection is unavailable right now. Choose manually.", "error");
    } finally {
      setLoading(false);
    }
  };

  button.addEventListener("click", () => detect(false));
  ipField.addEventListener("input", () => {
    clearTimeout(detectTimer);
    const value = ipField.value.trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
      setStatus("Manual OS selection stays available.", "");
      return;
    }
    detectTimer = setTimeout(() => detect(true), 900);
  });
  ipField.addEventListener("blur", () => {
    const value = ipField.value.trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) detect(true);
  });
}

function initAssetOwnerCards() {
  const modal = document.querySelector("#assetOwnerModal");
  if (!modal || modal.dataset.assetOwnerBound === "1") return;
  modal.dataset.assetOwnerBound = "1";
  const nameSlot = modal.querySelector("[data-owner-modal-name]");
  const phoneSlot = modal.querySelector("[data-owner-modal-phone]");
  const emailSlot = modal.querySelector("[data-owner-modal-email]");
  const close = () => {
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
  };
  for (const trigger of document.querySelectorAll("[data-asset-owner-card]")) {
    trigger.addEventListener("click", () => {
      if (nameSlot) nameSlot.textContent = trigger.dataset.ownerName || "Asset Owner";
      if (phoneSlot) phoneSlot.textContent = trigger.dataset.ownerPhone || "Not provided";
      if (emailSlot) emailSlot.textContent = trigger.dataset.ownerEmail || "Not provided";
      modal.classList.add("open");
      modal.setAttribute("aria-hidden", "false");
    });
  }
  modal.querySelector("[data-close-asset-owner]")?.addEventListener("click", close);
  modal.addEventListener("click", (event) => {
    if (event.target === modal) close();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && modal.classList.contains("open")) close();
  });
}

function initAssetMetadataPickers() {
  const aliasMaps = {
    department: {
      hr: "Human Resources (HR)",
      ict: "Information and Communications Technology (ICT)",
      it: "Information and Communications Technology (ICT)",
      soc: "Security Operations Center (SOC)",
      dba: "Database Administration (DBA)",
      rnd: "Research & Development (R&D)",
      "r&d": "Research & Development (R&D)",
    },
    business_function: {
      ad: "Active Directory",
      iam: "Identity Management",
      lms: "Learning Management System (LMS)",
      siem: "SIEM Platform",
      soc: "SOC Platform",
      vpn: "VPN Gateway",
      dns: "DNS Service",
      dhcp: "DHCP Service",
      ca: "Certificate Authority",
      ci: "CI/CD Pipeline",
      cicd: "CI/CD Pipeline",
      "ci/cd": "CI/CD Pipeline",
    },
  };
  for (const input of document.querySelectorAll("[data-standard-metadata]")) {
    if (input.dataset.standardBound === "1") continue;
    input.dataset.standardBound = "1";
    const picker = input.closest(".standard-picker");
    const badge = picker?.querySelector("[data-standard-badge]");
    const custom = input.dataset.otherTarget ? document.querySelector(input.dataset.otherTarget) : null;
    const options = Array.from(document.getElementById(input.getAttribute("list"))?.querySelectorAll("option") || []).map((option) => option.value);
    input.removeAttribute("list");
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-expanded", "false");
    input.setAttribute("autocomplete", "off");
    const menu = document.createElement("div");
    menu.className = "standard-picker-menu";
    menu.hidden = true;
    menu.setAttribute("role", "listbox");
    picker?.appendChild(menu);
    let activeIndex = -1;
    const canonicalByLower = Object.fromEntries(options.map((option) => [option.toLowerCase(), option]));
    const aliases = aliasMaps[input.dataset.standardMetadata] || {};
    const normalize = (value) => {
      const collapsed = String(value || "").replace(/\s+/g, " ").trim();
      const lowered = collapsed.toLowerCase();
      return aliases[lowered] || canonicalByLower[lowered] || collapsed;
    };
    const setMenuOpen = (open) => {
      menu.hidden = !open;
      input.setAttribute("aria-expanded", open ? "true" : "false");
    };
    const filteredOptions = () => {
      const query = String(input.value || "").trim().toLowerCase();
      const selected = new Set([input.value.toLowerCase()]);
      const matches = options.filter((option) => !selected.has(option.toLowerCase()) && (!query || option.toLowerCase().includes(query)));
      if (query && !matches.some((option) => option.toLowerCase() === "other")) matches.push("Other");
      return matches;
    };
    const renderMenu = () => {
      const rows = filteredOptions();
      activeIndex = Math.min(activeIndex, rows.length - 1);
      menu.replaceChildren();
      if (!rows.length) {
        const empty = document.createElement("div");
        empty.className = "standard-picker-empty";
        empty.textContent = "Type a custom value";
        menu.appendChild(empty);
        setMenuOpen(document.activeElement === input);
        return;
      }
      rows.forEach((option, index) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = "standard-picker-option";
        item.setAttribute("role", "option");
        item.setAttribute("aria-selected", index === activeIndex ? "true" : "false");
        item.innerHTML = `<span>${escapeHtml(option)}</span>${option === "Other" ? "<small>Custom</small>" : ""}`;
        item.addEventListener("mousedown", (event) => event.preventDefault());
        item.addEventListener("click", () => {
          input.value = option;
          sync();
          setMenuOpen(false);
          input.focus();
        });
        menu.appendChild(item);
      });
      setMenuOpen(document.activeElement === input);
    };
    const sync = () => {
      const normalized = normalize(input.value);
      if (normalized && normalized !== input.value) input.value = normalized;
      const isOther = input.value.toLowerCase() === "other";
      if (custom) {
        custom.hidden = !isOther;
        custom.disabled = !isOther;
        if (!isOther) custom.value = "";
      }
      if (badge) {
        badge.hidden = !input.value;
        badge.textContent = input.value;
        badge.classList.toggle("is-custom", Boolean(input.value && !canonicalByLower[input.value.toLowerCase()]));
      }
    };
    input.addEventListener("input", () => {
      activeIndex = -1;
      sync();
      renderMenu();
    });
    input.addEventListener("change", sync);
    input.addEventListener("focus", renderMenu);
    input.addEventListener("blur", () => {
      window.setTimeout(() => setMenuOpen(false), 120);
      sync();
    });
    input.addEventListener("keydown", (event) => {
      const rows = Array.from(menu.querySelectorAll(".standard-picker-option"));
      if (event.key === "ArrowDown") {
        event.preventDefault();
        activeIndex = rows.length ? (activeIndex + 1 + rows.length) % rows.length : -1;
        renderMenu();
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        activeIndex = rows.length ? (activeIndex - 1 + rows.length) % rows.length : -1;
        renderMenu();
      } else if (event.key === "Enter" && activeIndex >= 0 && rows[activeIndex]) {
        event.preventDefault();
        input.value = rows[activeIndex].querySelector("span")?.textContent || input.value;
        sync();
        setMenuOpen(false);
      } else if (event.key === "Escape") {
        setMenuOpen(false);
      }
    });
    input.form?.addEventListener("submit", () => {
      sync();
      if (custom && input.value.toLowerCase() === "other" && custom.value.trim()) {
        input.value = normalize(custom.value);
      }
    });
    sync();
    renderMenu();
    setMenuOpen(false);
  }
}

function initPlaybookForms() {
  for (const form of document.querySelectorAll("[data-playbook-form]")) {
    if (form.dataset.playbookBound === "1") continue;
    form.dataset.playbookBound = "1";
    const matchType = form.querySelector("[data-playbook-match-type]");
    const matchValue = form.querySelector("[data-match-value]");
    const caseSelect = form.querySelector("[data-match-case]");
    const mitreSelect = form.querySelector("[data-match-mitre]");
    const hint = form.querySelector("[data-match-hint]");
    const nameInput = form.querySelector("[data-preview-name]");
    const categoryInput = form.querySelector("[data-preview-category]");
    const descriptionInput = form.querySelector("[data-preview-description]");
    const priorityInput = form.querySelector("[data-preview-priority]");
    const tasksInput = form.querySelector("[data-preview-tasks]");
    const previewRoot = form.closest(".panel")?.parentElement || document;
    const previewName = previewRoot.querySelector("[data-preview-name]:not(input):not(textarea):not(select)");
    const previewCategory = previewRoot.querySelector("[data-preview-category]:not(input):not(textarea):not(select)");
    const previewDescription = previewRoot.querySelector("[data-preview-description]:not(input):not(textarea):not(select)");
    const previewMatch = previewRoot.querySelector("[data-preview-match]");
    const previewValue = previewRoot.querySelector("[data-preview-value]:not(input):not(textarea):not(select)");
    const previewPriority = previewRoot.querySelector("[data-preview-priority]:not(input):not(textarea):not(select)");
    const previewStepCount = previewRoot.querySelector("[data-preview-step-count]");
    const previewStepList = previewRoot.querySelector("[data-preview-step-list]");

    const optionHasValue = (select, value) => Array.from(select?.options || []).some((option) => option.value === value);
    const setHidden = (element, hidden) => {
      if (!element) return;
      element.classList.toggle("hidden", hidden);
      element.disabled = hidden;
    };
    const selectedLabel = (select) => select?.selectedOptions?.[0]?.textContent?.trim() || "";
    const syncMatchValue = () => {
      if (!matchType || !matchValue) return;
      const type = matchType.value;
      if (type === "CASE_TYPE" && caseSelect) {
        if (optionHasValue(caseSelect, matchValue.value)) caseSelect.value = matchValue.value;
        setHidden(matchValue, true);
        setHidden(caseSelect, false);
        setHidden(mitreSelect, true);
        matchValue.value = caseSelect.value;
      } else if (type === "MITRE_TACTIC" && mitreSelect) {
        if (optionHasValue(mitreSelect, matchValue.value)) mitreSelect.value = matchValue.value;
        setHidden(matchValue, true);
        setHidden(caseSelect, true);
        setHidden(mitreSelect, false);
        matchValue.value = mitreSelect.value;
      } else if (type === "GENERIC") {
        setHidden(matchValue, true);
        setHidden(caseSelect, true);
        setHidden(mitreSelect, true);
        matchValue.value = "*";
      } else {
        setHidden(matchValue, false);
        setHidden(caseSelect, true);
        setHidden(mitreSelect, true);
        if (matchValue.value === "*") matchValue.value = "";
      }
      if (hint) hint.hidden = type !== "GENERIC";
      updatePreview();
    };
    const updatePreview = () => {
      if (previewName) previewName.textContent = nameInput?.value?.trim() || "New playbook";
      if (previewCategory) previewCategory.textContent = categoryInput?.value || "Generic";
      if (previewDescription) previewDescription.textContent = descriptionInput?.value?.trim() || "Describe the investigation purpose.";
      if (previewMatch) previewMatch.textContent = selectedLabel(matchType) || "Match";
      if (previewValue) previewValue.textContent = matchValue?.value?.trim() || "-";
      if (previewPriority) previewPriority.textContent = priorityInput?.value || "100";
      const steps = (tasksInput?.value || "").split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
      if (previewStepCount) previewStepCount.textContent = String(steps.length);
      if (previewStepList) {
        previewStepList.innerHTML = steps.length
          ? steps.slice(0, 8).map((step) => `<li>${escapeHtml(step)}</li>`).join("")
          : '<li class="muted">Add investigation steps to preview the workflow.</li>';
      }
    };

    matchType?.addEventListener("change", syncMatchValue);
    caseSelect?.addEventListener("change", () => { if (matchValue) matchValue.value = caseSelect.value; updatePreview(); });
    mitreSelect?.addEventListener("change", () => { if (matchValue) matchValue.value = mitreSelect.value; updatePreview(); });
    for (const field of [matchValue, nameInput, categoryInput, descriptionInput, priorityInput, tasksInput]) {
      field?.addEventListener("input", updatePreview);
      field?.addEventListener("change", updatePreview);
    }
    form.addEventListener("submit", () => {
      if (!matchType || !matchValue) return;
      if (matchType.value === "CASE_TYPE" && caseSelect) matchValue.value = caseSelect.value;
      if (matchType.value === "MITRE_TACTIC" && mitreSelect) matchValue.value = mitreSelect.value;
      if (matchType.value === "GENERIC") matchValue.value = "*";
      matchValue.disabled = false;
    });
    syncMatchValue();
  }
}

function initReportDownloads() {
  for (const link of document.querySelectorAll("[data-report-download]")) {
    if (link.dataset.reportBound === "1") continue;
    link.dataset.reportBound = "1";
    link.addEventListener("click", () => {
      if (link.dataset.loading === "1") return;
      link.dataset.loading = "1";
      link.dataset.originalHtml = link.innerHTML;
      const loading = link.dataset.reportLoading || "Preparing report...";
      link.classList.add("report-generating");
      link.setAttribute("aria-busy", "true");
      link.innerHTML = neuralLoaderHtml(loading);
      setTimeout(() => {
        if (!link.isConnected) return;
        link.dataset.loading = "0";
        link.classList.remove("report-generating");
        link.removeAttribute("aria-busy");
        link.innerHTML = link.dataset.originalHtml || link.dataset.reportLabel || "Generate Report";
        refreshIcons();
      }, 25000);
    });
  }
}

function initFlashToasts() {
  for (const toast of document.querySelectorAll("[data-flash-toast]")) {
    if (toast.dataset.flashBound === "1") continue;
    toast.dataset.flashBound = "1";
    const dismiss = () => {
      if (toast.dataset.flashClosing === "1") return;
      toast.dataset.flashClosing = "1";
      toast.classList.add("soft-hide");
      setTimeout(() => toast.remove(), 260);
    };
    toast.querySelector("[data-flash-close]")?.addEventListener("click", dismiss);
    setTimeout(dismiss, 4600);
  }
}

function clearPageTimers() {
  if (ravenCasePollTimer) clearInterval(ravenCasePollTimer);
  if (ravenAlertPollTimer) clearInterval(ravenAlertPollTimer);
  if (ravenAnalyticsTimer) clearInterval(ravenAnalyticsTimer);
  if (ravenChatPollTimer) clearInterval(ravenChatPollTimer);
  ravenCasePollTimer = null;
  ravenAlertPollTimer = null;
  ravenAnalyticsTimer = null;
  ravenChatPollTimer = null;
  window.ravenAnalyticsRefresh = null;
  window.RavenAnalytics = null;
}

function redirectToLoginOnce() {
  if (ravenLoginRedirecting || window.location.pathname === "/login") return;
  ravenLoginRedirecting = true;
  window.location.replace("/login");
}

function initShellControls() {
  const savedTheme = localStorage.getItem("raven-theme");
  const savedSidebar = sessionStorage.getItem("raven-sidebar");
  if (savedTheme === "light") document.body.classList.add("light-mode");
  if (savedSidebar !== "expanded") document.body.classList.add("sidebar-collapsed");
  if (savedTheme === "light") document.documentElement.classList.add("light-mode");
  if (savedSidebar !== "expanded") document.documentElement.classList.add("sidebar-collapsed");

  initSmoothNavigation();

  const sidebarToggle = document.querySelector("#sidebarToggle");
  if (sidebarToggle) {
    sidebarToggle.addEventListener("click", () => {
      document.body.classList.toggle("sidebar-collapsed");
      document.documentElement.classList.toggle("sidebar-collapsed", document.body.classList.contains("sidebar-collapsed"));
      sessionStorage.setItem("raven-sidebar", document.body.classList.contains("sidebar-collapsed") ? "collapsed" : "expanded");
      refreshIcons();
    });
  }

  const themeToggle = document.querySelector("#themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      document.body.classList.toggle("light-mode");
      document.documentElement.classList.toggle("light-mode", document.body.classList.contains("light-mode"));
      localStorage.setItem("raven-theme", document.body.classList.contains("light-mode") ? "light" : "dark");
      refreshIcons();
      if (window.ravenAnalyticsRefresh) window.ravenAnalyticsRefresh();
    });
  }

  initLiveUpdates();
  initLogoutConfirm();
  refreshIcons();
}

function initSmoothNavigation() {
  window.addEventListener("pageshow", () => document.body.classList.remove("page-navigating"));
  for (const link of document.querySelectorAll(".sidebar nav a[href], .brand[href]")) {
    if (link.dataset.smoothNavBound === "1") continue;
    link.dataset.smoothNavBound = "1";
    if (link.dataset.confirmLogout !== undefined) continue;
    link.addEventListener("click", (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      if (link.target && link.target !== "_self") return;
      const target = new URL(link.href, window.location.origin);
      if (target.origin !== window.location.origin) return;
      if (target.pathname === window.location.pathname && target.search === window.location.search) return;
      event.preventDefault();
      smoothNavigate(target.toString(), link);
    });
  }
}

async function smoothNavigate(url, clickedLink) {
  const shell = document.querySelector("main.shell, main.auth-shell");
  if (!shell || document.body.dataset.navLoading === "1") {
    window.location.href = url;
    return;
  }
  document.body.dataset.navLoading = "1";
  document.body.classList.add("page-navigating");
  try {
    const response = await fetch(url, { headers: { "X-Requested-With": "Raven-Navigation" } });
    if (response.status === 401 || response.redirected && new URL(response.url).pathname === "/login") {
      window.location.href = response.url || "/login";
      return;
    }
    if (!response.ok) throw new Error("navigation failed");
    const html = await response.text();
    const parser = new DOMParser();
    const nextDoc = parser.parseFromString(html, "text/html");
    const nextMain = nextDoc.querySelector("main.shell, main.auth-shell");
    const nextNav = nextDoc.querySelector(".sidebar nav");
    if (!nextMain) throw new Error("missing page shell");

    clearPageTimers();
    shell.innerHTML = nextMain.innerHTML;
    document.title = nextDoc.title || document.title;
    if (nextNav) {
      const currentNav = document.querySelector(".sidebar nav");
      if (currentNav) currentNav.innerHTML = nextNav.innerHTML;
    } else if (clickedLink?.closest("nav")) {
      document.querySelectorAll(".sidebar nav a.active").forEach((item) => item.classList.remove("active"));
      clickedLink.classList.add("active");
    }
    history.pushState({}, "", url);
    await runNavigationScripts(nextDoc);
    initSmoothNavigation();
    initLogoutConfirm();
    initPageComponents();
    document.body.classList.remove("page-navigating");
    window.scrollTo(0, 0);
  } catch (error) {
    window.location.href = url;
  } finally {
    document.body.dataset.navLoading = "0";
  }
}

async function runNavigationScripts(nextDoc) {
  const scripts = [...nextDoc.querySelectorAll("script")];
  for (const script of scripts) {
    const src = script.getAttribute("src") || "";
    if (!src) continue;
    if (src.includes("/static/js/main.js") || src.includes("bootstrap") || src.includes("lucide")) continue;
    const absolute = new URL(src, window.location.origin).toString();
    if (document.querySelector(`script[src="${absolute}"], script[src="${src}"]`)) continue;
    await new Promise((resolve, reject) => {
      const tag = document.createElement("script");
      tag.src = absolute;
      tag.onload = resolve;
      tag.onerror = reject;
      document.body.appendChild(tag);
    });
  }
  for (const script of scripts) {
    if (script.getAttribute("src")) continue;
    const tag = document.createElement("script");
    tag.textContent = script.textContent;
    document.body.appendChild(tag);
    tag.remove();
  }
}

window.addEventListener("popstate", () => {
  window.location.reload();
});

function initReviewMenus() {
  for (const picker of document.querySelectorAll(".review-assignee-picker")) {
    const summary = picker.querySelector("[data-assignee-summary]");
    const updateSummary = () => {
      if (!summary) return;
      const count = picker.querySelectorAll('input[type="checkbox"]:checked').length;
      summary.textContent = count ? `${count} selected` : "Assign analysts";
    };
    picker.querySelectorAll('input[type="checkbox"]').forEach((input) => {
      input.addEventListener("change", updateSummary);
    });
    picker.querySelector("[data-close-details]")?.addEventListener("click", () => {
      picker.open = false;
    });
    updateSummary();
  }
  if (document.body.dataset.reviewMenuBound !== "1") {
    document.body.dataset.reviewMenuBound = "1";
    document.addEventListener("click", (event) => {
      for (const details of document.querySelectorAll(".review-assignee-picker[open], .review-more-actions[open]")) {
        if (!details.contains(event.target)) details.open = false;
      }
    });
  }
}

function initLiveUpdates() {
  if (document.body.dataset.forcePasswordChange === "1") return;
  if (!document.querySelector(".sidebar")) return;
  if (ravenLiveUpdatesStarted) return;
  ravenLiveUpdatesStarted = true;
  const refresh = async () => {
    try {
      const active = !document.hidden && Date.now() - ravenLastUserActivity < 20000;
      const response = await fetch(`/api/live/state${active ? "?active=1" : ""}`, { headers: { Accept: "application/json" } });
      if (response.status === 401) {
        redirectToLoginOnce();
        return;
      }
      if (!response.ok) return;
      const data = await response.json();
      updateNavBadges(data.unread_counts || {});
      updateUserPresence(data.online_users || {});
    } catch {}
  };
  refresh();
  setInterval(refresh, 15000);
}

function updateNavBadges(counts) {
  for (const link of document.querySelectorAll("[data-nav-section]")) {
    const section = link.dataset.navSection;
    let count = Number(counts[section] || 0);
    if (link.classList.contains("active")) count = 0;
    let badge = link.querySelector(".nav-badge");
    if (!count) {
      badge?.remove();
      continue;
    }
    if (!badge) {
      badge = document.createElement("b");
      badge.className = "nav-badge";
      link.appendChild(badge);
    }
    badge.textContent = count > 99 ? "99+" : String(count);
  }
}

function updateUserPresence(users) {
  for (const dot of document.querySelectorAll("[data-user-status]")) {
    const online = Boolean(users[dot.dataset.userStatus]);
    dot.classList.toggle("online", online);
    dot.classList.toggle("offline", !online);
    dot.title = online ? "Online" : "Offline";
  }
}

function initCaseWorkflowPolling() {
  if (document.body.dataset.forcePasswordChange === "1") return;
  if (!document.querySelector("[data-case-row]")) return;
  if (ravenCasePollTimer) clearInterval(ravenCasePollTimer);
  const refresh = async () => {
    if (document.hidden) return;
    try {
      const response = await fetch("/api/cases/workflow", { headers: { Accept: "application/json" } });
      if (!response.ok) return;
      const data = await response.json();
      for (const item of data.cases || []) {
        const status = document.querySelector(`[data-case-status="${item.id}"]`);
        const updated = document.querySelector(`[data-case-updated="${item.id}"]`);
        if (status) {
          status.textContent = item.status_label;
          status.className = `badge status status-${String(item.status || "").toLowerCase().replaceAll("_", "-")}`;
        }
        if (updated) updated.textContent = item.updated;
      }
    } catch {}
  };
  ravenCasePollTimer = setInterval(refresh, 20000);
}

function initAlertWorkflowPolling() {
  if (document.body.dataset.forcePasswordChange === "1") return;
  if (!document.querySelector("[data-alert-row]")) return;
  if (ravenAlertPollTimer) clearInterval(ravenAlertPollTimer);
  const refresh = async () => {
    if (document.hidden || document.querySelector("[data-alert-detail][open]")) return;
    try {
      const response = await fetch("/api/alerts/workflow", { headers: { Accept: "application/json" } });
      if (!response.ok) return;
      const data = await response.json();
      for (const item of data.alerts || []) {
        const cls = `badge status status-${String(item.status || "").toLowerCase().replaceAll("_", "-")}`;
        document.querySelectorAll(`[data-alert-status="${item.id}"]`).forEach((status) => {
          status.textContent = item.status_label;
          status.className = cls;
        });
        document.querySelectorAll(`[data-alert-status-text="${item.id}"]`).forEach((status) => {
          status.textContent = item.status_label;
        });
      }
    } catch {}
  };
  ravenAlertPollTimer = setInterval(refresh, 20000);
}

function initSecretControls() {
  for (const button of document.querySelectorAll("[data-toggle-secret]")) {
    button.addEventListener("click", () => {
      const input = document.querySelector(button.dataset.toggleSecret);
      if (!input) return;
      const revealed = input.classList.toggle("is-revealed");
      input.classList.toggle("is-blurred", !revealed);
      if (input.type === "password" || input.type === "text") input.type = revealed ? "text" : "password";
      const label = button.dataset.secretLabel || "key";
      button.title = revealed ? `Hide ${label}` : `Show ${label}`;
      button.setAttribute("aria-label", button.title);
      const hiddenIcon = button.dataset.secretHiddenIcon || "eye";
      const visibleIcon = button.dataset.secretVisibleIcon || "eye-off";
      button.innerHTML = `<i data-lucide="${revealed ? visibleIcon : hiddenIcon}"></i>`;
      refreshIcons();
    });
  }
  for (const button of document.querySelectorAll("[data-copy-secret]")) {
    button.addEventListener("click", async () => {
      const input = document.querySelector(button.dataset.copySecret);
      if (!input?.value) return;
      try {
        await navigator.clipboard.writeText(input.value);
      } catch {
        input.select();
        document.execCommand("copy");
        input.setSelectionRange(0, 0);
      }
      const oldTitle = button.title;
      button.title = "Copied";
      button.setAttribute("aria-label", "Copied");
      button.querySelector("i")?.setAttribute("data-lucide", "check");
      refreshIcons();
      setTimeout(() => {
        button.title = oldTitle || "Copy key";
        button.setAttribute("aria-label", button.title);
        button.querySelector("i")?.setAttribute("data-lucide", "copy");
        refreshIcons();
      }, 1200);
    });
  }
  for (const button of document.querySelectorAll("[data-copy-target]")) {
    button.addEventListener("click", async () => {
      const target = document.querySelector(button.dataset.copyTarget);
      const text = target?.innerText || target?.textContent || "";
      if (!text.trim()) return;
      await copyText(text.trim());
      const icon = button.querySelector("i");
      const oldIcon = icon?.getAttribute("data-lucide") || "copy";
      icon?.setAttribute("data-lucide", "check");
      refreshIcons();
      setTimeout(() => {
        icon?.setAttribute("data-lucide", oldIcon);
        refreshIcons();
      }, 1000);
    });
  }
}

function initAISettings() {
  const root = document.querySelector("[data-ai-settings]");
  if (!root || root.dataset.aiSettingsBound === "1") return;
  root.dataset.aiSettingsBound = "1";
  const provider = root.querySelector("[data-ai-provider]");
  const model = root.querySelector("[data-ai-model]");
  const endpoint = root.querySelector("[data-ai-endpoint]");
  const endpointWrap = root.querySelector("[data-ai-endpoint-wrap]");
  const endpointHelp = root.querySelector("[data-ai-endpoint-help]");
  const testButton = root.querySelector("[data-ai-test-url]");
  const result = root.querySelector("[data-ai-test-result]");
  const selectedProviderLabel = root.querySelector("[data-ai-selected-provider]");
  let models = {};
  let requirements = {};
  try {
    models = JSON.parse(root.dataset.aiModels || "{}");
    requirements = JSON.parse(root.dataset.aiRequirements || "{}");
  } catch {}

  const providerOptionLabel = () => provider?.selectedOptions?.[0]?.textContent?.trim() || "AI Provider";

  const updateProviderState = ({ preserveModel = true } = {}) => {
    if (!provider || !model) return;
    const selectedProvider = provider.value || "openai";
    const currentModel = model.value;
    const providerModels = models[selectedProvider] || [];
    model.innerHTML = providerModels.map((item) => `<option value="${escapeAttr(item.value)}">${escapeHtml(item.label)}</option>`).join("");
    const values = providerModels.map((item) => item.value);
    model.value = preserveModel && values.includes(currentModel) ? currentModel : values[0] || "";
    if (selectedProviderLabel) selectedProviderLabel.textContent = `Selected provider: ${providerOptionLabel()}`;
    const req = requirements[selectedProvider] || {};
    const showEndpoint = Boolean(req.requires_endpoint);
    if (endpointWrap) endpointWrap.hidden = !showEndpoint;
    if (endpoint && showEndpoint && !endpoint.value && req.default_endpoint) endpoint.placeholder = req.default_endpoint;
    if (endpointHelp) {
      endpointHelp.textContent = showEndpoint
        ? "Required for this provider. Use a chat/completions URL or local Ollama base URL."
        : "Endpoint is managed automatically for this provider.";
    }
  };

  provider?.addEventListener("change", () => {
    updateProviderState({ preserveModel: false });
    if (result) {
      result.className = "ai-test-result";
      result.innerHTML = '<span class="muted">Connection test validates authentication, endpoint reachability, model access, and latency.</span>';
    }
  });
  updateProviderState({ preserveModel: true });

  testButton?.addEventListener("click", async () => {
    const form = root.closest("form");
    if (!form || !result) return;
    const body = new FormData();
    for (const name of ["csrf_token", "ai_provider", "ai_model", "ai_api_key", "ai_endpoint"]) {
      const field = form.querySelector(`[name="${name}"]`);
      if (field) body.append(name, field.value || "");
    }
    setActionLoading(testButton, true, "Testing");
    result.className = "ai-test-result is-loading";
    result.innerHTML = `<span>${neuralLoaderHtml("Testing provider connection...")}</span>`;
    refreshIcons();
    try {
      const response = await fetch(testButton.dataset.aiTestUrl, {
        method: "POST",
        body,
        headers: { Accept: "application/json" },
      });
      const data = await response.json();
      if (!response.ok || !data.ok) throw data;
      result.className = "ai-test-result is-success";
      result.innerHTML = `<b>Connected</b><span>Provider: ${escapeHtml(data.provider)}</span><span>Model: ${escapeHtml(data.model)}</span><span>Latency: ${escapeHtml(data.latency_ms)}ms</span>`;
    } catch (error) {
      result.className = "ai-test-result is-error";
      result.innerHTML = `<b>Authentication Failed</b><span>${escapeHtml(error?.message || "Unable to connect to the AI provider.")}</span>`;
    } finally {
      setActionLoading(testButton, false);
      refreshIcons();
    }
  });
}

function initMultiDropdowns() {
  for (const dropdown of document.querySelectorAll("[data-multi-dropdown]")) {
    if (dropdown.dataset.multiBound === "1") continue;
    dropdown.dataset.multiBound = "1";
    const label = dropdown.querySelector("[data-multi-label]");
    const inputs = Array.from(dropdown.querySelectorAll("input[type='checkbox']"));
    const update = () => {
      const selected = inputs.filter((input) => input.checked);
      if (!label) return;
      if (!selected.length) {
        label.textContent = "Select Analyst";
      } else if (selected.length === 1) {
        label.textContent = selected[0].closest("label")?.innerText.trim() || "1 analyst selected";
      } else {
        label.textContent = `${selected.length} analysts selected`;
      }
    };
    inputs.forEach((input) => input.addEventListener("change", update));
    update();
  }
  if (window.ravenMultiDropdownCloseBound === "1") return;
  window.ravenMultiDropdownCloseBound = "1";
  document.addEventListener("click", (event) => {
    for (const dropdown of document.querySelectorAll("[data-multi-dropdown][open]")) {
      if (!dropdown.contains(event.target)) dropdown.removeAttribute("open");
    }
  });
}

function initRememberedLogin() {
  const username = document.querySelector("[data-remember-username]");
  const form = document.querySelector("[data-login-form]");
  if (!username || !form) return;
  try {
    const remembered = localStorage.getItem("astorasoc-last-username") || "";
    if (!username.value && remembered) username.value = remembered;
    form.addEventListener("submit", () => {
      const value = username.value.trim();
      if (value) localStorage.setItem("astorasoc-last-username", value);
    });
  } catch {}
}

function initLoginLoading() {
  const form = document.querySelector("[data-login-form]");
  if (!form || form.dataset.loginLoadingBound === "1") return;
  form.dataset.loginLoadingBound = "1";
  const submit = form.querySelector(".login-submit");
  const overlay = document.querySelector("[data-login-loading-overlay]");
  form.addEventListener("submit", (event) => {
    if (form.dataset.loginReadyToSubmit === "1") return;
    event.preventDefault();
    if (form.dataset.loginSubmitting === "1") return;
    form.dataset.loginSubmitting = "1";
    form.classList.add("login-is-loading");
    document.body.classList.add("login-loading-active");
    if (overlay) {
      overlay.classList.add("open");
      overlay.setAttribute("aria-hidden", "false");
    }
    setActionLoading(submit, true, "Signing in");
    window.setTimeout(() => {
      form.dataset.loginReadyToSubmit = "1";
      HTMLFormElement.prototype.submit.call(form);
    }, 5000);
  });
}

function initPasswordAutofillGuards() {
  const fields = document.querySelectorAll("[data-no-password-autofill]");
  for (const field of fields) {
    const clear = () => {
      if (field.matches(":focus")) return;
      field.value = "";
    };
    clear();
    window.setTimeout(clear, 80);
    window.setTimeout(clear, 450);
    field.addEventListener("focus", () => field.removeAttribute("readonly"), { once: true });
    field.addEventListener("pointerdown", () => field.removeAttribute("readonly"), { once: true });
    field.addEventListener("keydown", () => field.removeAttribute("readonly"), { once: true });
  }
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
}

function initAlertTriage() {
  for (const details of document.querySelectorAll("[data-alert-detail]")) {
    details.addEventListener("toggle", () => {
      if (!details.open) return;
      const localView = details.querySelector("[data-local-view]");
      if (localView) {
        localView.hidden = false;
        const small = localView.querySelector("small");
        if (small) small.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
      }
    });
  }
  for (const tab of document.querySelectorAll("[data-alert-tab]")) {
    tab.addEventListener("click", () => {
      const key = tab.dataset.alertTab;
      const alertId = key.split("-")[0];
      const panel = document.querySelector(`[data-alert-panel="${key}"]`);
      if (!panel) return;
      document.querySelectorAll(`[data-alert-tab^="${alertId}-"]`).forEach((item) => item.classList.toggle("active", item === tab));
      document.querySelectorAll(`[data-alert-panel^="${alertId}-"]`).forEach((item) => item.classList.toggle("active", item === panel));
    });
  }

  const modal = document.querySelector("#alertReasonModal");
  if (!modal) return;
  const textarea = modal.querySelector("#alertReasonText");
  const prompt = modal.querySelector("[data-alert-reason-prompt]");
  const submit = modal.querySelector("[data-alert-reason-submit]");
  const cancel = modal.querySelector("[data-alert-reason-cancel]");
  let pendingForm = null;

  for (const form of document.querySelectorAll("form[data-alert-reason]")) {
    form.addEventListener("submit", (event) => {
      if (form.dataset.reasonConfirmed === "true") return;
      event.preventDefault();
      pendingForm = form;
      if (prompt) prompt.textContent = form.dataset.alertReason || "Add a concise triage comment before continuing.";
      modal.querySelector("h2").textContent = form.dataset.alertReasonLabel || "Reason required";
      textarea.value = "";
      modal.classList.add("open");
      textarea.focus();
    });
  }
  cancel?.addEventListener("click", () => {
    pendingForm = null;
    modal.classList.remove("open");
  });
  modal.addEventListener("click", (event) => {
    if (event.target === modal) {
      pendingForm = null;
      modal.classList.remove("open");
    }
  });
  submit?.addEventListener("click", () => {
    const reason = textarea.value.trim();
    if (!pendingForm || !reason) {
      textarea.focus();
      return;
    }
    const input = pendingForm.querySelector('input[name="reason"]');
    if (input) input.value = reason;
    pendingForm.dataset.reasonConfirmed = "true";
    modal.classList.remove("open");
    pendingForm.submit();
    pendingForm = null;
  });
}

function initCaseInvestigation() {
  const workspace = document.querySelector("[data-case-investigation]");
  if (!workspace) return;

  const savedScroll = sessionStorage.getItem("raven-case-scroll");
  if (savedScroll) {
    const targetScroll = Number(savedScroll) || 0;
    const restore = () => window.scrollTo(0, targetScroll);
    restore();
    requestAnimationFrame(() => {
      restore();
      requestAnimationFrame(() => {
        restore();
        document.documentElement.classList.remove("case-scroll-restoring");
        sessionStorage.removeItem("raven-case-scroll");
      });
    });
    setTimeout(() => {
      document.documentElement.classList.remove("case-scroll-restoring");
      sessionStorage.removeItem("raven-case-scroll");
    }, 700);
  }

  for (const form of workspace.querySelectorAll("form")) {
    if (form.dataset.caseFormBound === "1") continue;
    form.dataset.caseFormBound = "1";
    if (form.matches("[data-case-async]")) {
      form.addEventListener("submit", (event) => submitCaseFormAsync(event, form));
      continue;
    }
    form.addEventListener("submit", () => {
      sessionStorage.setItem("raven-case-scroll", String(window.scrollY || 0));
      const button = form.querySelector('button[type="submit"], button:not([type])');
      setActionLoading(button, true, form.dataset.loadingMessage || "Working");
    });
  }

  const noteSearch = workspace.querySelector("[data-note-search]");
  const noteList = workspace.querySelector("[data-note-list]");
  if (noteSearch && noteList && noteSearch.dataset.noteSearchBound !== "1") {
    noteSearch.dataset.noteSearchBound = "1";
    noteSearch.addEventListener("input", () => {
      const query = noteSearch.value.trim().toLowerCase();
      for (const note of noteList.querySelectorAll("[data-note-item]")) {
        note.hidden = query && !note.innerText.toLowerCase().includes(query);
      }
    });
  }
}

async function submitCaseFormAsync(event, form) {
  event.preventDefault();
  if (form.dataset.asyncSubmitting === "1") return;
  const button = event.submitter || form.querySelector('button[type="submit"], button:not([type])');
  const originalText = button?.innerHTML || "";
  const scrollY = window.scrollY || 0;
  form.dataset.asyncSubmitting = "1";
  const selectors = [
    form.dataset.caseTarget,
    ...(form.dataset.caseExtraTargets || "").split(","),
  ].map((item) => item && item.trim()).filter(Boolean);
  const loadingTargets = selectors.map((selector) => document.querySelector(selector)).filter(Boolean);
  loadingTargets.forEach((target) => setSectionLoading(target, true));
  setActionLoading(button, true, form.dataset.loadingMessage || "Working");
  try {
    const response = await fetch(form.action, {
      method: (form.method || "POST").toUpperCase(),
      body: new FormData(form),
      headers: { "X-Requested-With": "Raven-Case-Action" },
    });
    if (!response.ok) throw new Error("case action failed");
    const html = await response.text();
    const nextDoc = new DOMParser().parseFromString(html, "text/html");
    let replaced = false;
    for (const selector of selectors) {
      const current = document.querySelector(selector);
      const next = nextDoc.querySelector(selector);
      if (current && next) {
        current.replaceWith(next);
        replaced = true;
      }
    }
    if (!replaced) throw new Error("case sections missing");
    window.scrollTo(0, scrollY);
    initFileControls();
    initDangerConfirm();
    initImagePreview();
    initCaseInvestigation();
    refreshIcons();
  } catch (error) {
    sessionStorage.setItem("raven-case-scroll", String(scrollY));
    form.submit();
    return;
  } finally {
    form.dataset.asyncSubmitting = "0";
    loadingTargets.forEach((target) => setSectionLoading(target, false));
    if (button && button.isConnected) setActionLoading(button, false);
    if (button && button.isConnected && originalText && !button.dataset.originalHtml) button.innerHTML = originalText;
  }
}

function initContainmentConsole() {
  const panel = document.querySelector(".containment-console-panel");
  if (!panel || panel.dataset.containmentBound === "1") return;
  panel.dataset.containmentBound = "1";

  const actionType = panel.querySelector("#containmentActionType");
  const target = panel.querySelector("#containmentTarget");
  const host = panel.querySelector("#containmentTargetHost");
  const risk = panel.querySelector("#containmentRiskLevel");
  const previewIoc = panel.querySelector("[data-containment-preview-ioc]");
  const previewImpact = panel.querySelector("[data-containment-preview-impact]");
  const previewHost = panel.querySelector("[data-containment-preview-host]");
  const riskStrip = panel.querySelector("[data-containment-risk-strip]");
  const highRiskActions = new Set(["DISABLE_USER", "ISOLATE_HOST", "KILL_PROCESS"]);
  const actionLabels = {
    BLOCK_IP: "Block IP",
    DISABLE_USER: "Disable User",
    KILL_PROCESS: "Kill Process",
    ISOLATE_HOST: "Isolate Host",
    ADD_FIREWALL_RULE: "Add Firewall Rule",
    QUARANTINE_FILE: "Quarantine File",
    CUSTOM_SCRIPT: "Custom Script"
  };

  const updatePreview = () => {
    const action = actionType?.value || "";
    const targetValue = target?.value.trim() || "No target selected";
    const hostValue = host?.value.trim() || previewHost?.textContent || "Not Available";
    const riskValue = risk?.value || "Medium";
    if (previewIoc) previewIoc.textContent = targetValue;
    if (previewHost) previewHost.textContent = hostValue;
    if (previewImpact) previewImpact.textContent = `${actionLabels[action] || "Containment"} affects ${targetValue} on ${hostValue}.`;
    if (riskStrip) {
      const isHighRisk = highRiskActions.has(action) || riskValue === "High" || riskValue === "Critical";
      riskStrip.classList.toggle("high-risk", isHighRisk);
      const text = riskStrip.querySelector("span");
      if (text) text.textContent = isHighRisk
        ? "High-risk action: confirm business impact, approval, rollback plan, and operator notes before requesting."
        : "Manual execution remains locked until approval is recorded.";
    }
  };

  const inferActionForIoc = (iocType) => {
    const kind = String(iocType || "").toLowerCase();
    if (kind.includes("ip")) return "BLOCK_IP";
    if (kind.includes("host")) return "ISOLATE_HOST";
    if (kind.includes("user")) return "DISABLE_USER";
    if (kind.includes("hash") || kind.includes("file")) return "QUARANTINE_FILE";
    return actionType?.value || "BLOCK_IP";
  };

  document.querySelectorAll("[data-containment-ioc]").forEach((button) => {
    button.addEventListener("click", () => {
      if (target) target.value = button.dataset.iocValue || "";
      if (actionType) actionType.value = inferActionForIoc(button.dataset.iocType);
      if (risk && Number(button.dataset.iocAlerts || 0) > 2 && risk.value === "Medium") risk.value = "High";
      if (host && !host.value.trim() && previewHost?.textContent && previewHost.textContent !== "Not Available") {
        host.value = previewHost.textContent.trim();
      }
      panel.scrollIntoView({ behavior: "smooth", block: "start" });
      target?.focus();
      updatePreview();
      refreshIcons();
    });
  });

  [actionType, target, host, risk].forEach((field) => {
    field?.addEventListener("input", updatePreview);
    field?.addEventListener("change", updatePreview);
  });

  const requestForm = panel.querySelector("[data-containment-form]");
  requestForm?.addEventListener("submit", () => {
    const action = actionType?.value || "";
    if (highRiskActions.has(action)) {
      requestForm.dataset.confirmDanger = `${actionLabels[action]} is a high-risk containment action. Confirm approval path, affected asset, and rollback plan before requesting.`;
    }
  });

  panel.querySelectorAll("[data-containment-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const row = document.querySelector(button.dataset.containmentToggle);
      if (!row) return;
      row.hidden = !row.hidden;
      button.classList.toggle("active", !row.hidden);
    });
  });

  const filters = {
    search: panel.querySelector("[data-containment-search]"),
    status: panel.querySelector("[data-containment-filter-status]"),
    action: panel.querySelector("[data-containment-filter-action]"),
    analyst: panel.querySelector("[data-containment-filter-analyst]"),
    from: panel.querySelector("[data-containment-filter-from]"),
    to: panel.querySelector("[data-containment-filter-to]")
  };
  const applyFilters = () => {
    const search = filters.search?.value.trim().toLowerCase() || "";
    const status = filters.status?.value || "";
    const action = filters.action?.value || "";
    const analyst = filters.analyst?.value.trim().toLowerCase() || "";
    const from = filters.from?.value || "";
    const to = filters.to?.value || "";
    panel.querySelectorAll("[data-containment-row]").forEach((row) => {
      const text = row.innerText.toLowerCase();
      const rowDate = row.dataset.date || "";
      const visible = (!search || text.includes(search))
        && (!status || row.dataset.status === status)
        && (!action || row.dataset.action === action)
        && (!analyst || (row.dataset.analyst || "").includes(analyst))
        && (!from || rowDate >= from)
        && (!to || rowDate <= to);
      row.hidden = !visible;
      const detail = row.nextElementSibling?.matches("[data-containment-detail]") ? row.nextElementSibling : null;
      if (detail && !visible) detail.hidden = true;
    });
  };
  Object.values(filters).forEach((field) => {
    field?.addEventListener("input", applyFilters);
    field?.addEventListener("change", applyFilters);
  });

  updatePreview();
}

function initLogoutConfirm() {
  const logout = document.querySelector("[data-confirm-logout]");
  if (!logout) return;
  if (logout.dataset.logoutBound === "1") return;
  logout.dataset.logoutBound = "1";
  initDangerConfirm();
  const modal = document.querySelector("#logoutConfirm");
  if (!modal) return;
  const link = modal.querySelector("[data-confirm-link]");
  logout.addEventListener("click", (event) => {
    event.preventDefault();
    openRavenConfirm({
      title: "Log out?",
      message: "Are you sure you want to end this Raven session?",
      confirmText: "Yes, log out",
      icon: "log-out",
      href: link?.href || logout.href
    });
  });
}

function initDangerConfirm() {
  const modal = document.querySelector("#logoutConfirm");
  if (!modal) return;
  bindRavenConfirmModal(modal);
  for (const form of document.querySelectorAll("form")) {
    if (form.dataset.dangerBound === "1") continue;
    form.dataset.dangerBound = "1";
    form.addEventListener("submit", (event) => {
      const trigger = event.submitter;
      const message = trigger?.dataset.confirmDanger || form.dataset.confirmDanger;
      if (!message || form.dataset.confirmed === "true") return;
      event.preventDefault();
      openRavenConfirm({
        title: trigger?.dataset.confirmTitle || form.dataset.confirmTitle || "Confirm action",
        message,
        confirmText: trigger?.dataset.confirmText || form.dataset.confirmText || "Confirm",
        icon: trigger?.dataset.confirmIcon || form.dataset.confirmIcon || "shield-alert",
        form,
        submitter: trigger
      });
    });
  }
  for (const link of document.querySelectorAll("a[data-confirm-danger]")) {
    if (link.dataset.dangerBound === "1") continue;
    link.dataset.dangerBound = "1";
    link.addEventListener("click", (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      openRavenConfirm({
        title: link.dataset.confirmTitle || "Confirm action",
        message: link.dataset.confirmDanger,
        confirmText: link.dataset.confirmText || "Confirm",
        icon: link.dataset.confirmIcon || "shield-alert",
        href: link.href
      });
    });
  }
}

function bindRavenConfirmModal(modal) {
  if (modal.dataset.confirmModalBound === "1") return;
  modal.dataset.confirmModalBound = "1";
  const submit = modal.querySelector("[data-confirm-submit]");
  const close = () => {
    modal.classList.remove("open");
    ravenConfirmState = { form: null, submitter: null, href: null };
  };
  modal.querySelector("[data-cancel-logout]")?.addEventListener("click", close);
  modal.addEventListener("click", (event) => {
    if (event.target === modal) close();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && modal.classList.contains("open")) close();
  });
  submit?.addEventListener("click", () => {
    const { form, submitter, href } = ravenConfirmState;
    if (href) {
      setActionLoading(submit, true, "Opening");
      window.location.href = href;
      return;
    }
    if (!form) return;
    if (submitter?.name) {
      const hidden = document.createElement("input");
      hidden.type = "hidden";
      hidden.name = submitter.name;
      hidden.value = submitter.value;
      form.appendChild(hidden);
    }
    form.dataset.confirmed = "true";
    ravenConfirmState = { form: null, submitter: null, href: null };
    modal.classList.remove("open");
    setActionLoading(submit, true, form.dataset.loadingMessage || submitter?.dataset.loadingMessage || "Working");
    if (form.requestSubmit) {
      form.requestSubmit(submitter || undefined);
    } else {
      form.submit();
    }
  });
}

function openRavenConfirm({ title, message, confirmText, icon, form, submitter, href }) {
  const modal = document.querySelector("#logoutConfirm");
  if (!modal) return;
  bindRavenConfirmModal(modal);
  ravenConfirmState = { form: form || null, submitter: submitter || null, href: href || null };
  modal.querySelector("h2").textContent = title || "Confirm action";
  modal.querySelector("p").textContent = message || "Review this action before continuing.";
  const iconSlot = modal.querySelector(".confirm-modal-icon");
  if (iconSlot) iconSlot.innerHTML = `<i data-lucide="${icon || "shield-alert"}"></i>`;
  const linkButton = modal.querySelector("[data-confirm-link]");
  const submitButton = modal.querySelector("[data-confirm-submit]");
  if (linkButton) linkButton.hidden = true;
  if (submitButton) {
    submitButton.hidden = false;
    submitButton.textContent = confirmText || (href ? "Continue" : "Confirm");
  }
  modal.classList.add("open");
  refreshIcons();
}

function initProfileCards() {
  const backdrop = document.querySelector("#profileModalBackdrop");
  for (const trigger of document.querySelectorAll("[data-profile-card]")) {
    trigger.addEventListener("click", () => {
      const card = document.querySelector(`#profile-card-${trigger.dataset.profileCard}`);
      if (!card) return;
      document.querySelectorAll(".profile-popover.open").forEach((item) => item.classList.remove("open"));
      card.classList.add("open");
      if (backdrop) backdrop.classList.add("open");
    });
  }
  for (const close of document.querySelectorAll("[data-close-profile]")) {
    close.addEventListener("click", closeProfileModal);
  }
  if (backdrop) {
    backdrop.addEventListener("click", (event) => {
      if (event.target === backdrop) closeProfileModal();
    });
  }
}

function closeProfileModal() {
  document.querySelector("#profileModalBackdrop")?.classList.remove("open");
  document.querySelectorAll(".profile-popover.open").forEach((item) => item.classList.remove("open"));
}

function initChatPage() {
  if (document.body.dataset.forcePasswordChange === "1") return;
  const stream = document.querySelector("#chatStream");
  const input = document.querySelector("#chatMessageInput");
  const menu = document.querySelector("#mentionMenu");
  const attachment = document.querySelector("#chatAttachment");
  const attachmentName = document.querySelector("#attachmentName");
  const emojiToggle = document.querySelector("#emojiToggle");
  const emojiMenu = document.querySelector("#emojiMenu");
  const emojiTray = document.querySelector("#emojiTray");
  const replyToId = document.querySelector("#replyToId");
  const editMessageId = document.querySelector("#editMessageId");
  const replyCompose = document.querySelector("#replyCompose");
  const replyComposeText = document.querySelector("#replyComposeText");
  const replyCancel = document.querySelector("#replyCancel");
  const editCompose = document.querySelector("#editCompose");
  const editCancel = document.querySelector("#editCancel");
  const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";

  if (stream) {
    document.querySelector('[data-nav-section="chats"] .nav-badge')?.remove();
    if ("scrollRestoration" in history) history.scrollRestoration = "manual";
    const scrollToTarget = () => {
      const target = document.querySelector("#unreadMarker");
      stream.scrollTop = target ? Math.max(target.offsetTop - stream.offsetTop - 10, 0) : stream.scrollHeight;
      stream.dataset.ready = "true";
    };
    requestAnimationFrame(scrollToTarget);
    startChatPolling(stream, csrfToken);
    stream.addEventListener("click", (event) => {
      const profileTrigger = event.target.closest("[data-profile-card]");
      if (profileTrigger) {
        const card = document.querySelector(`#profile-card-${profileTrigger.dataset.profileCard}`);
        const backdrop = document.querySelector("#profileModalBackdrop");
        if (card) {
          document.querySelectorAll(".profile-popover.open").forEach((item) => item.classList.remove("open"));
          card.classList.add("open");
          backdrop?.classList.add("open");
        }
      }
      const replyButton = event.target.closest("[data-reply-message]");
      if (replyButton && replyToId && replyCompose && replyComposeText) {
        replyToId.value = replyButton.dataset.replyMessage;
        if (editMessageId) editMessageId.value = "";
        if (editCompose) editCompose.hidden = true;
        replyComposeText.textContent = `${replyButton.dataset.replyAuthor}: ${replyButton.dataset.replyBody || "Attachment"}`;
        replyCompose.hidden = false;
        input?.focus();
      }
      const editButton = event.target.closest("[data-edit-message]");
      if (editButton && editMessageId && editCompose && input) {
        editMessageId.value = editButton.dataset.editMessage;
        if (replyToId) replyToId.value = "";
        if (replyCompose) replyCompose.hidden = true;
        input.value = editButton.dataset.editBody || "";
        editCompose.hidden = false;
        input.focus();
        input.selectionStart = input.selectionEnd = input.value.length;
      }
    });
  }
  if (replyToId && replyCompose && replyComposeText) {
    for (const button of document.querySelectorAll("[data-reply-message]")) {
      button.addEventListener("click", () => {
        replyToId.value = button.dataset.replyMessage;
        if (editMessageId) editMessageId.value = "";
        if (editCompose) editCompose.hidden = true;
        replyComposeText.textContent = `${button.dataset.replyAuthor}: ${button.dataset.replyBody || "Attachment"}`;
        replyCompose.hidden = false;
        input?.focus();
      });
    }
    replyCancel?.addEventListener("click", () => {
      replyToId.value = "";
      replyCompose.hidden = true;
    });
  }
  if (editMessageId && editCompose && input) {
    for (const button of document.querySelectorAll("[data-edit-message]")) {
      button.addEventListener("click", () => {
        editMessageId.value = button.dataset.editMessage;
        if (replyToId) replyToId.value = "";
        if (replyCompose) replyCompose.hidden = true;
        input.value = button.dataset.editBody || "";
        editCompose.hidden = false;
        input.focus();
        input.selectionStart = input.selectionEnd = input.value.length;
      });
    }
    editCancel?.addEventListener("click", () => {
      editMessageId.value = "";
      editCompose.hidden = true;
      input.value = "";
      input.focus();
    });
  }
  if (attachment && attachmentName) {
    attachment.addEventListener("change", () => {
      attachmentName.textContent = attachment.files?.[0]?.name || "";
    });
  }
  if (input && emojiToggle && emojiMenu) {
    emojiToggle.addEventListener("click", (event) => {
      event.stopPropagation();
      closeReactionMenus();
      emojiMenu.classList.toggle("open");
    });
    for (const option of emojiMenu.querySelectorAll("[data-insert-emoji]")) {
      option.addEventListener("click", () => {
        if (option.dataset.insertEmoji.startsWith("file:")) {
          addEmojiToken(emojiTray, option.dataset.insertEmoji, option.innerHTML);
        } else {
          insertAtCursor(input, option.dataset.insertEmoji);
        }
        emojiMenu.classList.remove("open");
      });
    }
  }
  initChatReactions(csrfToken);
  initAutoUploadForms();
  if (!input || !menu || !window.RavenChat) return;

  input.addEventListener("input", () => renderMentionMenu(input, menu));
  input.addEventListener("keydown", (event) => {
    if (event.key === "Escape") menu.classList.remove("open");
    if (event.key === "Enter" && !event.shiftKey && menu.classList.contains("open")) {
      const first = menu.querySelector(".mention-option");
      if (first) {
        event.preventDefault();
        insertMention(input, menu, first.dataset.value);
      }
    }
  });
  document.addEventListener("click", (event) => {
    if (!menu.contains(event.target) && event.target !== input) menu.classList.remove("open");
    if (emojiMenu && !emojiMenu.contains(event.target) && event.target !== emojiToggle) emojiMenu.classList.remove("open");
    if (!event.target.closest(".chat-reaction-bar")) closeReactionMenus();
  });
}

function startChatPolling(stream, csrfToken) {
  let inFlight = false;
  let lastSeenId = latestChatMessageId(stream);
  const poll = async () => {
    if (inFlight || document.hidden || chatInteractionOpen()) return;
    inFlight = true;
    try {
      const nearBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 80;
      const response = await fetch("/chats?partial=stream", { headers: { Accept: "text/html" } });
      if (response.status === 401) {
        redirectToLoginOnce();
        return;
      }
      if (!response.ok) return;
      const html = await response.text();
      const incomingId = latestChatMessageIdFromHtml(html);
      if (html.trim() && incomingId && incomingId !== lastSeenId) {
        stream.innerHTML = html;
        lastSeenId = incomingId;
        initChatReactions(csrfToken);
        refreshIcons();
        if (nearBottom) stream.scrollTop = stream.scrollHeight;
      }
    } finally {
      inFlight = false;
    }
  };
  if (ravenChatPollTimer) clearInterval(ravenChatPollTimer);
  ravenChatPollTimer = setInterval(poll, 5000);
}

function chatInteractionOpen() {
  return Boolean(
    document.querySelector(".reaction-menu.open") ||
      document.querySelector("#emojiMenu.open") ||
      document.querySelector("#mentionMenu.open") ||
      document.querySelector("#replyCompose:not([hidden])") ||
      document.querySelector("#editCompose:not([hidden])")
  );
}

function latestChatMessageId(root) {
  const messages = root.querySelectorAll("[data-message-id]");
  return messages.length ? messages[messages.length - 1].dataset.messageId : "";
}

function latestChatMessageIdFromHtml(html) {
  const template = document.createElement("template");
  template.innerHTML = html;
  return latestChatMessageId(template.content);
}

function addEmojiToken(tray, value, html) {
  if (!tray) return;
  const chip = document.createElement("span");
  chip.className = "emoji-token-chip";
  chip.innerHTML = `${html}<input type="hidden" name="emoji_tokens" value="${escapeAttr(value)}"><button type="button" title="Remove emoji"><i data-lucide="x"></i></button>`;
  chip.querySelector("button")?.addEventListener("click", () => chip.remove());
  tray.appendChild(chip);
  refreshIcons();
}

function initImagePreview() {
  const backdrop = document.querySelector("#imagePreviewBackdrop");
  const image = document.querySelector("#imagePreview");
  if (!backdrop || !image) return;
  for (const trigger of document.querySelectorAll("[data-image-preview]")) {
    trigger.addEventListener("click", (event) => {
      const src = trigger.dataset.imagePreview;
      if (!src) return;
      event.stopPropagation();
      image.src = src;
      backdrop.classList.add("open");
    });
  }
  const close = () => {
    backdrop.classList.remove("open");
    image.removeAttribute("src");
  };
  backdrop.querySelector("[data-close-image]")?.addEventListener("click", close);
  backdrop.addEventListener("click", (event) => {
    if (event.target === backdrop) close();
  });
}

function initAutoUploadForms() {
  for (const input of document.querySelectorAll(".auto-upload-form input[type='file']")) {
    input.addEventListener("change", () => {
      if (input.files?.length) input.form?.submit();
    });
  }
}

function initFileControls() {
  for (const input of document.querySelectorAll(".raven-file-control input[type='file']")) {
    if (input.dataset.fileControlBound === "1") continue;
    input.dataset.fileControlBound = "1";
    const control = input.closest(".raven-file-control");
    const name = control?.querySelector("[data-file-name]");
    const fallback = name?.dataset.fileName || "No file selected";
    if (name && !name.textContent.trim()) name.textContent = fallback;
    input.addEventListener("change", () => {
      const files = Array.from(input.files || []);
      if (!name) return;
      if (!files.length) {
        name.textContent = fallback;
      } else if (files.length === 1) {
        name.textContent = files[0].name;
      } else {
        name.textContent = `${files.length} files selected`;
      }
    });
  }
}

function initChatReactions(csrfToken) {
  for (const toggle of document.querySelectorAll("[data-reaction-menu-for]")) {
    if (toggle.dataset.reactionBound === "true") continue;
    toggle.dataset.reactionBound = "true";
    toggle.addEventListener("click", (event) => {
      event.stopPropagation();
      document.querySelector("#emojiMenu")?.classList.remove("open");
      const menu = document.querySelector(`[data-reaction-menu="${toggle.dataset.reactionMenuFor}"]`);
      for (const item of document.querySelectorAll(".reaction-menu.open")) {
        if (item !== menu) item.classList.remove("open");
      }
      menu?.classList.toggle("open");
    });
  }
  for (const button of document.querySelectorAll("[data-react-url][data-emoji]")) {
    if (button.dataset.reactBound === "true") continue;
    button.dataset.reactBound = "true";
    button.addEventListener("click", () => submitReaction(button, csrfToken));
  }
}

async function submitReaction(button, csrfToken) {
  const body = new FormData();
  body.append("emoji", button.dataset.emoji);
  body.append("csrf_token", csrfToken);
  const response = await fetch(button.dataset.reactUrl, {
    method: "POST",
    body,
    headers: { Accept: "application/json" },
  });
  if (!response.ok) return;
  const data = await response.json();
  const list = document.querySelector(`[data-reaction-list="${data.message_id}"]`);
  if (list) {
    list.innerHTML = data.reactions.map((reaction) => reactionButtonHtml(data.message_id, button.dataset.reactUrl, reaction)).join("");
    const bar = document.querySelector(`[data-reaction-bar="${data.message_id}"]`);
    bar?.classList.toggle("has-reactions", data.reactions.length > 0);
    bar?.closest(".chat-message")?.classList.toggle("has-message-reactions", data.reactions.length > 0);
    for (const item of list.querySelectorAll("[data-react-url][data-emoji]")) {
      item.addEventListener("click", () => submitReaction(item, csrfToken));
    }
  }
  closeReactionMenus();
  refreshIcons();
}

function reactionButtonHtml(messageId, url, reaction) {
  const html = reaction.html || escapeHtml(reaction.emoji);
  return `<button class="chat-reaction ${reaction.reacted ? "active" : ""}" type="button" data-react-url="${escapeAttr(url)}" data-emoji="${escapeAttr(reaction.emoji)}">${html} <span>${escapeHtml(reaction.count)}</span></button>`;
}

function closeReactionMenus() {
  document.querySelectorAll(".reaction-menu.open").forEach((item) => item.classList.remove("open"));
}

function renderMentionMenu(input, menu) {
  const match = input.value.slice(0, input.selectionStart).match(/(^|\s)@([A-Za-z0-9 _-]*)$/);
  if (!match) {
    menu.classList.remove("open");
    return;
  }
  const query = match[2].toLowerCase();
  const options = (window.RavenChat.mentions || [])
    .filter((item) => item.label.toLowerCase().includes(query) || item.value.toLowerCase().includes(query))
    .slice(0, 8);
  if (!options.length) {
    menu.classList.remove("open");
    return;
  }
  menu.innerHTML = options
    .map((item) => `<button type="button" class="mention-option" data-value="${escapeAttr(item.value)}"><span>@${escapeHtml(item.value)}</span><small>${escapeHtml(item.type === "role" ? "role" : item.role)}</small></button>`)
    .join("");
  for (const option of menu.querySelectorAll(".mention-option")) {
    option.addEventListener("click", () => insertMention(input, menu, option.dataset.value));
  }
  menu.classList.add("open");
}

function insertMention(input, menu, value) {
  const before = input.value.slice(0, input.selectionStart);
  const after = input.value.slice(input.selectionStart);
  const replaced = before.replace(/(^|\s)@([A-Za-z0-9 _-]*)$/, `$1@${value} `);
  input.value = replaced + after;
  input.focus();
  input.selectionStart = input.selectionEnd = replaced.length;
  menu.classList.remove("open");
}

function insertAtCursor(input, value) {
  const start = input.selectionStart || 0;
  const end = input.selectionEnd || 0;
  input.value = input.value.slice(0, start) + value + input.value.slice(end);
  input.focus();
  input.selectionStart = input.selectionEnd = start + value.length;
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}

function refreshIcons() {
  const sidebarToggle = document.querySelector("#sidebarToggle");
  if (sidebarToggle) {
    const collapsed = document.body.classList.contains("sidebar-collapsed");
    const label = collapsed ? "Expand navigation" : "Collapse navigation";
    sidebarToggle.title = label;
    sidebarToggle.setAttribute("aria-label", label);
    sidebarToggle.innerHTML = `<i data-lucide="${collapsed ? "chevron-right" : "chevron-left"}"></i>`;
  }
  const themeToggle = document.querySelector("#themeToggle");
  if (themeToggle) {
    themeToggle.innerHTML = `<i data-lucide="${document.body.classList.contains("light-mode") ? "moon" : "sun"}"></i>`;
  }
  if (window.lucide) window.lucide.createIcons();
}

function initThreatAnalytics(endpoint) {
  const severityEl = document.querySelector("#severityChart");
  const statusEl = document.querySelector("#statusChart");
  if (!severityEl || !statusEl) return;
  let activePeriod = window.RavenAnalytics?.initialPeriod || "all";
  let activeDateFilter = {
    date: window.RavenAnalytics?.date || "",
  };
  let lastStatusLabels = ["Assigned", "Investigating", "Pending Review", "Closed", "False Positive"];
  let lastStatusSeries = [0, 0, 0, 0, 0];
  const chartHeight = () => Math.max(280, Math.min(520, window.innerHeight - 520));

  const shared = {
    chart: {
      background: "transparent",
      foreColor: "#cfe5e0",
      animations: { enabled: true, easing: "easeinout", speed: 700, dynamicAnimation: { speed: 450 } },
      toolbar: { show: false },
    },
    theme: { mode: "dark" },
    dataLabels: { style: { colors: ["#07100f"] } },
    tooltip: { theme: "dark" },
    grid: { borderColor: "rgba(160, 255, 226, 0.12)" },
  };

  const severityChart = new ApexCharts(severityEl, {
    ...shared,
    chart: { ...shared.chart, type: "donut", height: chartHeight() },
    labels: ["Critical", "High", "Medium", "Low"],
    series: [0, 0, 0, 0],
    colors: ["#ff355d", "#ff8a2a", "#ffd84d", "#4da3ff"],
    stroke: { colors: ["#07100f"], width: 3 },
    legend: { position: "bottom" },
    plotOptions: { pie: { donut: { size: "68%", labels: { show: true, total: { show: true, label: "Incidents" } } } } },
  });

  const statusChart = new ApexCharts(statusEl, {
    ...shared,
    chart: { ...shared.chart, type: "bar", height: chartHeight() },
    series: [{ name: "Cases", data: [0, 0, 0, 0, 0] }],
    xaxis: {
      categories: ["Assigned", "Investigating", "Pending Review", "Closed", "False Positive"],
      min: 0,
      tickAmount: 2,
      forceNiceScale: true,
      labels: { formatter: (value) => formatAxisCount(value) },
    },
    colors: ["#4da3ff", "#a78bfa", "#ffd84d", "#24d66f", "#87919a"],
    plotOptions: { bar: { horizontal: true, borderRadius: 4, barHeight: "38%", distributed: true, dataLabels: { position: "right" } } },
    dataLabels: {
      enabled: true,
      formatter: (value) => formatFullCount(value),
      offsetX: 8,
      textAnchor: "start",
      style: { fontSize: "12px", fontWeight: 800, colors: ["#cfe5e0"] },
      background: { enabled: false },
    },
    fill: { opacity: 0.92 },
    legend: { show: false },
  });

  severityChart.render();
  statusChart.render();

  function endpointForPeriod() {
    const url = new URL(endpoint, window.location.origin);
    url.searchParams.set("period", activePeriod);
    for (const [key, value] of Object.entries(activeDateFilter)) {
      if (value) url.searchParams.set(key, value);
    }
    return url.toString();
  }

  function renderCards(cards) {
    for (const [key, card] of Object.entries(cards || {})) {
      const target = document.querySelector(`[data-dashboard-card="${key}"]`);
      if (target) target.textContent = card?.value ?? card ?? "0";
      const trend = document.querySelector(`[data-dashboard-trend="${key}"]`);
      if (trend && card?.trend) {
        trend.textContent = card.trend.value || "";
        trend.className = `trend trend-${card.trend.direction || "flat"}`;
      }
    }
  }

  function renderActivity(items) {
    const feed = document.querySelector("[data-dashboard-activity]");
    if (!feed) return;
    if (!items || !items.length) {
      feed.innerHTML = '<p class="muted">No incident activity in this period.</p>';
      return;
    }
    feed.innerHTML = items.map((item) => {
      return `<article class="incident-feed-item severity-${escapeAttr(String(item.severity || "medium").toLowerCase())}"><b>${escapeHtml(item.kind || "Item")}</b><span>${escapeHtml(item.case || "")} ${escapeHtml(item.description || "")}</span><small>${escapeHtml(item.status || "Unknown")} / ${escapeHtml(item.time || "")}</small></article>`;
    }).join("");
  }

  function renderList(key, rows, emptyText) {
    const target = document.querySelector(`[data-dashboard-list="${key}"]`);
    if (!target) return;
    if (!rows || !rows.length) {
      target.innerHTML = `<p class="muted">${escapeHtml(emptyText)}</p>`;
      return;
    }
    target.innerHTML = rows.map((row) => `<span><b>${escapeHtml(row.label || "Not Available")}</b><em>${escapeHtml(row.value ?? 0)}</em></span>`).join("");
  }

  function sourceClass(value) {
    return String(value || "custom").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "custom";
  }

  function plural(value, label) {
    const count = Number(value) || 0;
    return `${count} ${label}${count === 1 ? "" : "s"}`;
  }

  function renderTopRules(rows) {
    const target = document.querySelector('[data-dashboard-list="top_rules"]');
    if (!target) return;
    if (!rows || !rows.length) {
      target.innerHTML = '<p class="muted">No rule activity.</p>';
      return;
    }
    const header = '<div class="soc-table-head detection-row"><span>Detection Name</span><span>Source</span><span>Count</span></div>';
    target.innerHTML = header + rows.map((row) => {
      const detection = row.detection || row.label || "Unnamed detection";
      const source = row.source || "Custom";
      const title = `${detection}${row.rule_id ? ` / Rule ID ${row.rule_id}` : ""}`;
      return `<div class="soc-table-row detection-row" title="${escapeAttr(title)}">`
        + `<a href="${escapeAttr(row.alerts_url || "#")}"><b>${escapeHtml(detection)}</b></a>`
        + `<span class="source-pill source-${escapeAttr(sourceClass(source))}">${escapeHtml(source)}</span>`
        + `<a class="mini-count" href="${escapeAttr(row.cases_url || row.alerts_url || "#")}" title="Open related cases">${escapeHtml(row.count ?? row.value ?? 0)}</a>`
        + `</div>`;
    }).join("");
  }

  function renderAffectedAssets(rows) {
    const target = document.querySelector('[data-dashboard-list="affected_assets"]');
    if (!target) return;
    if (!rows || !rows.length) {
      target.innerHTML = '<p class="muted">No linked asset impact.</p>';
      return;
    }
    const header = '<div class="soc-table-head asset-impact-row"><span>Asset Name</span><span>Criticality</span><span>Open Alerts</span><span>Open Cases</span><span>Risk Score</span></div>';
    target.innerHTML = header + rows.map((row) => {
      const name = row.name || row.label || "Unnamed asset";
      const criticality = row.criticality || "Medium";
      const riskTone = row.risk_tone || "low";
      return `<div class="soc-table-row asset-impact-row" title="${escapeAttr(name)}">`
        + `<a href="${escapeAttr(row.asset_url || "#")}"><b>${escapeHtml(name)}</b></a>`
        + `<span class="asset-criticality-pill asset-criticality-${escapeAttr(String(criticality).toLowerCase())}">${escapeHtml(criticality)}</span>`
        + `<a class="mini-count" href="${escapeAttr(row.alerts_url || "#")}">${escapeHtml(plural(row.open_alerts, "alert"))}</a>`
        + `<a class="mini-count" href="${escapeAttr(row.cases_url || "#")}">${escapeHtml(plural(row.open_cases, "case"))}</a>`
        + `<em class="asset-risk-pill asset-risk-${escapeAttr(riskTone)}">${escapeHtml(row.risk_score ?? 0)}/100 ${escapeHtml(row.risk_label || "Low Risk")}</em>`
        + `</div>`;
    }).join("");
  }

  function renderWorkload(rows) {
    const target = document.querySelector('[data-dashboard-list="workload"]');
    if (!target) return;
    if (!rows || !rows.length) {
      target.innerHTML = '<p class="muted">No assigned open cases.</p>';
      return;
    }
    const header = '<div class="soc-table-head workload-row"><span>Analyst Name</span><span>Assigned</span><span>Investigating</span><span>Pending Review</span></div>';
    target.innerHTML = header + rows.map((row) => {
      const name = row.name || row.label || "Analyst";
      return `<a class="soc-table-row workload-row" href="${escapeAttr(row.cases_url || "#")}" title="${escapeAttr(name)}">`
        + `<b>${escapeHtml(name)}</b>`
        + `<span class="mini-count">${escapeHtml(row.assigned ?? 0)} Assigned</span>`
        + `<span class="mini-count purple">${escapeHtml(row.investigating ?? 0)} Investigating</span>`
        + `<span class="mini-count amber">${escapeHtml(row.pending_review ?? 0)} Pending Review</span>`
        + `</a>`;
    }).join("");
  }

  function renderSocPanels(data) {
    renderTopRules(data.top_rules);
    renderAffectedAssets(data.affected_assets);
    renderWorkload(data.workload);
    renderList("ioc_types", data.iocs?.by_type, "No IOC activity.");
    for (const [key, value] of Object.entries(data.iocs || {})) {
      if (key === "by_type") continue;
      const target = document.querySelector(`[data-dashboard-ioc="${key}"]`);
      if (target) target.textContent = value;
    }
    for (const [key, value] of Object.entries(data.containment || {})) {
      const target = document.querySelector(`[data-dashboard-containment="${key}"]`);
      if (target) target.textContent = value;
    }
    for (const [key, value] of Object.entries(data.assets || {})) {
      const target = document.querySelector(`[data-dashboard-asset="${key}"]`);
      if (target) target.textContent = value;
    }
    const caseTotal = document.querySelector("[data-dashboard-case-total]");
    if (caseTotal) caseTotal.textContent = `${data.case_total || 0} cases`;
  }

  function formatFullCount(value) {
    return Math.round(Number(value) || 0).toLocaleString();
  }

  function formatAxisCount(value) {
    const number = Math.round(Number(value) || 0);
    if (number >= 1000000) return `${Number((number / 1000000).toFixed(number % 1000000 === 0 ? 0 : 1))}M`;
    if (number >= 1000) return `${Number((number / 1000).toFixed(number % 1000 === 0 ? 0 : 1))}k`;
    return String(number);
  }

  function niceStep(rawStep) {
    const value = Math.max(1, Number(rawStep) || 1);
    const magnitude = 10 ** Math.floor(Math.log10(value));
    const residual = value / magnitude;
    const niceResidual = residual <= 1 ? 1 : residual <= 2 ? 2 : residual <= 5 ? 5 : 10;
    return niceResidual * magnitude;
  }

  function statusAxisScale(series) {
    const maxValue = Math.max(...(series || []).map((value) => Number(value) || 0), 0);
    if (!maxValue) return { max: undefined, tickAmount: 2 };
    const preferredTicks = window.innerWidth < 680 ? 3 : window.innerWidth < 1180 ? 4 : 5;
    const step = niceStep(maxValue / preferredTicks);
    let max = step * Math.ceil(maxValue / step);
    if (max === maxValue && maxValue > 1) max += step;
    return { max, tickAmount: Math.max(2, Math.round(max / step)) };
  }

  async function refresh() {
    const response = await fetch(endpointForPeriod(), { headers: { Accept: "application/json" } });
    if (!response.ok) return;
    const data = await response.json();
    renderCards(data.cards);
    renderActivity(data.activity);
    renderSocPanels(data);
    const periodLabel = document.querySelector("[data-dashboard-period-label]");
    if (periodLabel) periodLabel.textContent = data.period_label || "";
    const light = document.body.classList.contains("light-mode");
    const chartText = light ? "#203039" : "#cfe5e0";
    const chartGrid = light ? "rgba(32, 48, 57, 0.14)" : "rgba(160, 255, 226, 0.12)";
    const severityTotal = data.severity.series.reduce((sum, value) => sum + value, 0);
    severityChart.updateOptions({
      chart: { foreColor: chartText },
      theme: { mode: light ? "light" : "dark" },
      labels: severityTotal ? data.severity.labels : ["No Incidents"],
      colors: severityTotal ? ["#ff355d", "#ff8a2a", "#ffd84d", "#4da3ff"] : ["#87919a"],
      plotOptions: {
        pie: {
          donut: {
            size: "68%",
            labels: {
              show: true,
              total: {
                show: true,
                label: "Cases",
                formatter: () => String(severityTotal),
              },
            },
          },
        },
      },
    });
    severityChart.updateSeries(severityTotal ? data.severity.series : [1]);
    const statusLabels = data.status?.labels || [];
    const statusSeries = data.status?.series || [];
    lastStatusLabels = statusLabels;
    lastStatusSeries = statusSeries;
    const statusAxis = statusAxisScale(statusSeries);
    const statusColors = statusLabels.map((label) => {
      if (label.includes("Assigned")) return "#4da3ff";
      if (label.includes("Investigating")) return "#a78bfa";
      if (label.includes("Pending") || label.includes("Review")) return "#ffd84d";
      if (label.includes("Closed")) return "#24d66f";
      if (label.includes("False")) return "#87919a";
      return "#24d6a3";
    });
    statusChart.updateOptions({
      chart: { foreColor: chartText },
      theme: { mode: light ? "light" : "dark" },
      grid: { borderColor: chartGrid },
      xaxis: {
        categories: statusLabels,
        min: 0,
        max: statusAxis.max,
        tickAmount: statusAxis.tickAmount,
        forceNiceScale: true,
        labels: { formatter: (value) => formatAxisCount(value) },
      },
      yaxis: { labels: { maxWidth: 150 } },
      colors: statusColors,
      plotOptions: { bar: { horizontal: true, borderRadius: 4, barHeight: "38%", distributed: true, dataLabels: { position: "right" } } },
      dataLabels: {
        enabled: true,
        formatter: (value) => formatFullCount(value),
        offsetX: 8,
        textAnchor: "start",
        style: { fontSize: "12px", fontWeight: 800, colors: [chartText] },
        background: { enabled: false },
      },
      tooltip: { y: { formatter: (value) => `${formatFullCount(value)} cases` } },
    });
    statusChart.updateSeries([{ name: "Cases", data: statusSeries }]);
  }

  refresh();
  window.ravenAnalyticsRefresh = refresh;
  window.addEventListener("resize", () => {
    const height = chartHeight();
    const statusAxis = statusAxisScale(lastStatusSeries);
    severityChart.updateOptions({ chart: { height } }, false, false);
    statusChart.updateOptions({
      chart: { height },
      xaxis: {
        categories: lastStatusLabels,
        min: 0,
        max: statusAxis.max,
        tickAmount: statusAxis.tickAmount,
        forceNiceScale: true,
        labels: { formatter: (value) => formatAxisCount(value) },
      },
    }, false, false);
  });
  for (const button of document.querySelectorAll("[data-dashboard-period]")) {
    button.addEventListener("click", () => {
      activePeriod = button.dataset.dashboardPeriod || "all";
      document.querySelectorAll("[data-dashboard-period]").forEach((item) => item.classList.toggle("active", item === button));
      const url = new URL(window.location.href);
      url.searchParams.set("period", activePeriod);
      activeDateFilter = { date: "" };
      for (const key of ["date", "month", "year"]) {
        url.searchParams.delete(key);
        const input = document.querySelector(`[data-dashboard-calendar] [name="${key}"]`);
        if (input) input.value = "";
      }
      const periodInput = document.querySelector("[data-dashboard-period-input]");
      if (periodInput) periodInput.value = activePeriod;
      window.history.replaceState({}, "", url.toString());
      refresh();
    });
  }
  ravenAnalyticsTimer = setInterval(refresh, 20000);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[char]));
}
