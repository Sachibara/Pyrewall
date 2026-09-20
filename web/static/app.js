(() => {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const role = document.body.dataset.role || "user";
  const isAdmin = role === "admin";
  let activePage = "overview";
  const trafficHistory = { up: [], down: [] };

  const $ = (id) => document.getElementById(id);
  const qsa = (selector, root = document) => [...root.querySelectorAll(selector)];

  if (!isAdmin) qsa(".admin-only").forEach((node) => node.classList.add("hidden"));

  async function api(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = { ...(options.headers || {}) };

    if (options.body && typeof options.body !== "string") {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(options.body);
    }
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      headers["X-CSRF-Token"] = csrf;
    }

    const response = await fetch(path, { ...options, method, headers, credentials: "same-origin" });
    if (response.status === 401) {
      location.href = "/login";
      throw new Error("Your session has expired.");
    }

    let data;
    try {
      data = await response.json();
    } catch {
      data = { ok: false, error: "Invalid response from PyreWall." };
    }
    if (!response.ok || !data.ok) throw new Error(data.error || "Request failed.");
    return data;
  }

  function toast(title, message = "", type = "info") {
    const node = document.createElement("div");
    node.className = "toast" + (type === "error" ? " error" : "");
    const strong = document.createElement("strong");
    strong.textContent = title;
    const span = document.createElement("span");
    span.textContent = message;
    node.append(strong, span);
    $("toastRegion").appendChild(node);
    setTimeout(() => node.remove(), 4500);
  }

  function showError(error) {
    console.error(error);
    toast("PyreWall error", error?.message || String(error), "error");
  }

  function formatBytesPerSecond(value) {
    let n = Number(value) || 0;
    const units = ["B/s", "KB/s", "MB/s", "GB/s"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }
    const digits = n >= 100 ? 0 : n >= 10 ? 1 : 2;
    return n.toFixed(digits) + " " + units[i];
  }

  function textCell(text, className = "") {
    const td = document.createElement("td");
    td.textContent = text ?? "—";
    if (className) td.className = className;
    return td;
  }

  function emptyRow(tbody, colSpan, message) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = colSpan;
    td.className = "empty-cell";
    td.textContent = message;
    tr.appendChild(td);
    tbody.replaceChildren(tr);
  }

  function actionButton(label, className, handler) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className || "ghost-button compact";
    button.textContent = label;
    button.addEventListener("click", handler);
    return button;
  }

  const pageMeta = {
    overview: ["Firewall status", "Overview"],
    network: ["Network control", "Network Control"],
    rules: ["Policy management", "Firewall Rules"],
    threats: ["IDS / IPS", "Threats"],
    history: ["Audit trail", "History"],
    settings: ["Configuration", "Settings"],
    users: ["Administration", "User Management"],
  };

  const loaders = {
    overview: loadOverview,
    network: loadNetwork,
    rules: loadRules,
    threats: loadThreats,
    history: loadHistory,
    settings: loadSettings,
    users: loadUsers,
  };

  function openPage(page) {
    if (page === "users" && !isAdmin) return;
    activePage = page;
    qsa("[data-page-panel]").forEach((panel) => {
      panel.classList.toggle("active", panel.dataset.pagePanel === page);
    });
    qsa("[data-page]").forEach((button) => {
      button.classList.toggle("active", button.dataset.page === page);
    });
    $("pageEyebrow").textContent = pageMeta[page][0];
    $("pageTitle").textContent = pageMeta[page][1];
    $("sidebar").classList.remove("open");
    loaders[page]?.().catch(showError);
  }

  qsa("[data-page]").forEach((button) => button.addEventListener("click", () => openPage(button.dataset.page)));
  $("menuButton").addEventListener("click", () => $("sidebar").classList.toggle("open"));

  async function loadOverview() {
    const data = await api("/api/overview");
    const overview = data.overview;
    const fw = overview.firewall;
    const counts = overview.counts;

    $("statDomains").textContent = counts.domains;
    $("statIps").textContent = counts.blocked_ips;
    $("statDevices").textContent = counts.devices;
    $("statRules").textContent = counts.rules;
    $("statSignatures").textContent = counts.signatures;
    $("statThreats").textContent = counts.threats;

    $("hostName").textContent = fw.hostname;
    $("hostPlatform").textContent = fw.platform;
    $("hostAdmin").textContent = fw.administrator ? "Yes" : "No";
    $("hostReady").textContent = fw.ready ? "Ready" : "Not ready";
    $("adminWarning").classList.toggle("hidden", fw.administrator);

    const badge = $("engineBadge");
    const dot = $("sidebarStatusDot");
    const orb = $("engineOrb");
    badge.className = "state-badge";
    dot.className = "status-dot";
    orb.classList.remove("active");

    if (fw.ready) {
      $("engineState").textContent = "Firewall active";
      $("engineDetail").textContent = "WinDivert is open and the packet filter is actively enforcing PyreWall policy.";
      $("sidebarStatus").textContent = "Firewall active";
      $("sidebarReady").textContent = "WinDivert ready";
      badge.textContent = "Active";
      badge.classList.add("active");
      dot.classList.add("online");
      orb.classList.add("active");
    } else if (fw.running) {
      $("engineState").textContent = "Firewall starting";
      $("engineDetail").textContent = "The worker is running and completing WinDivert / DNS initialization.";
      $("sidebarStatus").textContent = "Starting";
      $("sidebarReady").textContent = "Waiting for WinDivert";
      badge.textContent = "Starting";
      badge.classList.add("starting");
      dot.classList.add("starting");
    } else {
      $("engineState").textContent = "Firewall stopped";
      $("engineDetail").textContent = fw.administrator
        ? "Start the firewall to begin WinDivert packet filtering."
        : "Restart this web console as Administrator before starting the firewall.";
      $("sidebarStatus").textContent = "Firewall stopped";
      $("sidebarReady").textContent = "Engine idle";
      badge.textContent = "Stopped";
      badge.classList.add("offline");
    }

    if ($("startFirewallBtn")) $("startFirewallBtn").disabled = fw.running || !fw.administrator;
    if ($("stopFirewallBtn")) $("stopFirewallBtn").disabled = !fw.running;
  }

  async function sampleTraffic() {
    const data = await api("/api/traffic");
    const t = data.traffic;
    if (!t.available) {
      $("trafficLabel").textContent = "psutil unavailable";
      return;
    }
    $("trafficUp").textContent = formatBytesPerSecond(t.sent_bps);
    $("trafficDown").textContent = formatBytesPerSecond(t.recv_bps);
    $("trafficLabel").textContent = "Live host counters";
    trafficHistory.up.push(t.sent_bps);
    trafficHistory.down.push(t.recv_bps);
    if (trafficHistory.up.length > 45) trafficHistory.up.shift();
    if (trafficHistory.down.length > 45) trafficHistory.down.shift();
    drawTraffic();
  }

  function drawTraffic() {
    const canvas = $("trafficCanvas");
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const ratio = window.devicePixelRatio || 1;
    const width = Math.max(300, rect.width);
    const height = 260;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    const ctx = canvas.getContext("2d");
    ctx.scale(ratio, ratio);
    ctx.clearRect(0, 0, width, height);

    const css = getComputedStyle(document.body);
    const border = css.getPropertyValue("--border").trim();
    const accent = css.getPropertyValue("--accent").trim();
    const accent2 = css.getPropertyValue("--accent2").trim();

    ctx.strokeStyle = border;
    ctx.lineWidth = 1;
    for (let i = 1; i < 5; i++) {
      const y = (height / 5) * i;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    const values = [...trafficHistory.up, ...trafficHistory.down];
    const max = Math.max(1024, ...values);

    function line(series, color) {
      if (!series.length) return;
      ctx.strokeStyle = color;
      ctx.lineWidth = 2.3;
      ctx.beginPath();
      series.forEach((value, index) => {
        const x = series.length === 1 ? width : (index / (Math.max(1, series.length - 1))) * width;
        const y = height - (value / max) * (height - 22) - 10;
        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    line(trafficHistory.up, accent);
    line(trafficHistory.down, accent2);
  }

  async function setFirewall(action) {
    const button = action === "start" ? $("startFirewallBtn") : $("stopFirewallBtn");
    button.disabled = true;
    try {
      await api("/api/firewall/" + action, { method: "POST" });
      toast(action === "start" ? "Start requested" : "Firewall stopped", "Refreshing engine status…");
      await loadOverview();
    } finally {
      setTimeout(() => loadOverview().catch(showError), 900);
    }
  }

  $("startFirewallBtn")?.addEventListener("click", () => setFirewall("start").catch(showError));
  $("stopFirewallBtn")?.addEventListener("click", () => setFirewall("stop").catch(showError));

  async function loadDomains() {
    const data = await api("/api/domains");
    const list = $("domainList");
    list.replaceChildren();
    if (!data.domains.length) {
      const row = document.createElement("div");
      row.className = "item-row";
      row.textContent = "No blocked domains.";
      list.appendChild(row);
      return;
    }
    data.domains.forEach((domain) => {
      const row = document.createElement("div");
      row.className = "item-row";
      const code = document.createElement("code");
      code.textContent = domain;
      row.appendChild(code);
      if (isAdmin) {
        row.appendChild(actionButton("Unblock", "danger-button compact", async () => {
          await api("/api/domains", { method: "DELETE", body: { domain } });
          toast("Domain unblocked", domain);
          await loadDomains();
          await loadOverview();
        }));
      }
      list.appendChild(row);
    });
  }

  async function loadIps() {
    const data = await api("/api/blocked-ips");
    const list = $("ipList");
    list.replaceChildren();
    if (!data.ips.length) {
      const row = document.createElement("div");
      row.className = "item-row";
      row.textContent = "No blocked IP addresses.";
      list.appendChild(row);
      return;
    }
    data.ips.forEach((item) => {
      const row = document.createElement("div");
      row.className = "item-row";
      const left = document.createElement("div");
      const code = document.createElement("code");
      code.textContent = item.ip;
      const meta = document.createElement("div");
      meta.className = "item-meta";
      meta.textContent = item.reason === "manual"
        ? "Manual block"
        : (item.domain ? "Resolved for " + item.domain : (item.reason || "Resolved block"));
      left.append(code, meta);
      row.appendChild(left);
      if (isAdmin) {
        row.appendChild(actionButton("Remove", "danger-button compact", async () => {
          await api("/api/blocked-ips", { method: "DELETE", body: { ip: item.ip } });
          toast("IP unblocked", item.ip);
          await loadIps();
          await loadOverview();
        }));
      }
      list.appendChild(row);
    });
  }

  async function loadDevices() {
    const tbody = $("deviceTableBody");
    emptyRow(tbody, isAdmin ? 4 : 3, "Scanning ARP table…");
    const data = await api("/api/devices");
    tbody.replaceChildren();
    if (!data.devices.length) {
      emptyRow(tbody, isAdmin ? 4 : 3, "No devices are currently visible in the ARP table.");
      return;
    }
    data.devices.forEach((device) => {
      const tr = document.createElement("tr");
      tr.append(textCell(device.ip), textCell(device.mac || "Unknown"));
      const status = textCell(device.blocked ? "Blocked" : "Allowed", "badge " + (device.blocked ? "danger" : "ok"));
      tr.appendChild(status);
      if (isAdmin) {
        const actions = document.createElement("td");
        const button = actionButton(device.blocked ? "Unblock" : "Block", device.blocked ? "ghost-button compact" : "danger-button compact", async () => {
          const path = device.blocked ? "/api/devices/unblock" : "/api/devices/block";
          await api(path, { method: "POST", body: { ip: device.ip } });
          toast(device.blocked ? "Device unblocked" : "Device blocked", device.ip);
          await loadDevices();
          await loadOverview();
        });
        actions.appendChild(button);
        tr.appendChild(actions);
      }
      tbody.appendChild(tr);
    });
  }

  async function loadSignatures() {
    const tbody = $("signatureTableBody");
    const data = await api("/api/signatures");
    tbody.replaceChildren();
    if (!data.signatures.length) {
      emptyRow(tbody, isAdmin ? 6 : 5, "No application/service signatures configured.");
      return;
    }
    data.signatures.forEach((sig) => {
      const tr = document.createElement("tr");
      tr.append(
        textCell(sig.app_name),
        textCell(sig.pattern || "—"),
        textCell(sig.domain_pattern || "—"),
        textCell(sig.ip_range || "—"),
        textCell(sig.protocol || "ANY")
      );
      if (isAdmin) {
        const td = document.createElement("td");
        td.appendChild(actionButton("Remove", "danger-button compact", async () => {
          await api("/api/signatures/" + sig.id, { method: "DELETE" });
          toast("Signature removed", sig.app_name);
          await loadSignatures();
          await loadOverview();
        }));
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    });
  }

  async function loadNetwork() {
    await Promise.all([loadDomains(), loadIps(), loadSignatures(), loadDevices()]);
  }

  $("refreshNetworkBtn")?.addEventListener("click", () => loadNetwork().catch(showError));
  $("scanDevicesBtn")?.addEventListener("click", () => loadDevices().catch(showError));

  $("domainForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const domain = $("domainInput").value.trim();
    if (!domain) return;
    try {
      const data = await api("/api/domains", { method: "POST", body: { domain } });
      $("domainInput").value = "";
      toast("Domain blocked", data.domain);
      await loadDomains();
      await loadIps();
      await loadOverview();
    } catch (error) { showError(error); }
  });

  $("ipForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const ip = $("ipInput").value.trim();
    if (!ip) return;
    try {
      const data = await api("/api/blocked-ips", { method: "POST", body: { ip } });
      $("ipInput").value = "";
      toast("IP blocked", data.ip);
      await loadIps();
      await loadOverview();
    } catch (error) { showError(error); }
  });

  $("signatureForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/signatures", {
        method: "POST",
        body: {
          app_name: $("signatureName").value.trim(),
          pattern: $("signaturePattern").value.trim(),
          domain_pattern: $("signatureDomain").value.trim(),
          ip_range: $("signatureIpRange").value.trim(),
          protocol: $("signatureProtocol").value,
        },
      });
      event.target.reset();
      $("signatureProtocol").value = "ANY";
      toast("Signature added", "The running firewall will reload its application rules.");
      await loadSignatures();
      await loadOverview();
    } catch (error) { showError(error); }
  });

  async function loadRules() {
    const data = await api("/api/rules");
    const tbody = $("ruleTableBody");
    tbody.replaceChildren();
    if (!data.rules.length) {
      emptyRow(tbody, isAdmin ? 7 : 6, "No custom firewall rules configured.");
      return;
    }
    data.rules.forEach((rule) => {
      const tr = document.createElement("tr");
      tr.append(
        textCell(rule.id),
        textCell(rule.username || "—"),
        textCell(rule.ip),
        textCell(rule.port),
        textCell(rule.protocol),
        textCell(rule.action, "badge " + (rule.action === "BLOCK" ? "danger" : "ok"))
      );
      if (isAdmin) {
        const td = document.createElement("td");
        td.appendChild(actionButton("Remove", "danger-button compact", async () => {
          await api("/api/rules/" + rule.id, { method: "DELETE" });
          toast("Rule removed", "#" + rule.id);
          await loadRules();
          await loadOverview();
        }));
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    });
  }

  $("ruleForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await api("/api/rules", {
        method: "POST",
        body: {
          ip: $("ruleIp").value.trim(),
          port: $("rulePort").value.trim() || "ANY",
          protocol: $("ruleProtocol").value,
          action: $("ruleAction").value,
        },
      });
      $("ruleIp").value = "";
      $("rulePort").value = "ANY";
      toast(data.applied ? "Rule applied" : "Rule saved", data.message || ("Rule #" + data.rule_id));
      await loadRules();
      await loadOverview();
    } catch (error) { showError(error); }
  });

  async function loadThreats() {
    const data = await api("/api/threats");
    const tbody = $("threatTableBody");
    tbody.replaceChildren();
    if (!data.threats.length) {
      emptyRow(tbody, 6, "No threat events recorded.");
      return;
    }
    data.threats.forEach((threat) => {
      const severity = String(threat.severity || "unknown").toLowerCase();
      const tr = document.createElement("tr");
      tr.append(
        textCell(threat.timestamp),
        textCell(threat.src_ip || "—"),
        textCell(threat.dst_ip || "—"),
        textCell(threat.protocol || "—"),
        textCell(threat.severity || "Unknown", "severity " + severity),
        textCell(threat.description || "—")
      );
      tbody.appendChild(tr);
    });
  }

  $("refreshThreatsBtn")?.addEventListener("click", () => loadThreats().catch(showError));
  $("clearThreatsBtn")?.addEventListener("click", async () => {
    if (!confirm("Clear all recorded threat events?")) return;
    try {
      await api("/api/threats", { method: "DELETE" });
      toast("Threat events cleared");
      await loadThreats();
      await loadOverview();
    } catch (error) { showError(error); }
  });

  async function loadHistory() {
    const search = $("historySearch").value.trim();
    const data = await api("/api/history?limit=250&search=" + encodeURIComponent(search));
    const tbody = $("historyTableBody");
    tbody.replaceChildren();
    if (!data.history.length) {
      emptyRow(tbody, 4, search ? "No matching history records." : "No history records.");
      return;
    }
    data.history.forEach((item) => {
      const tr = document.createElement("tr");
      tr.append(
        textCell(item.timestamp),
        textCell(item.username || "—"),
        textCell(item.action || "—"),
        textCell(item.description || "—")
      );
      tbody.appendChild(tr);
    });
  }

  $("historySearchBtn")?.addEventListener("click", () => loadHistory().catch(showError));
  $("historySearch")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") loadHistory().catch(showError);
  });

  function applyTheme(darkMode) {
    document.body.classList.toggle("light", !darkMode);
    requestAnimationFrame(drawTraffic);
  }

  async function loadSettings() {
    const data = await api("/api/settings");
    const settings = data.settings;
    $("settingAutoStart").checked = !!settings.auto_start;
    $("settingLogging").checked = !!settings.detailed_logging;
    $("settingDark").checked = !!settings.dark_mode;
    $("settingDns").checked = !!settings.dns_proxy_enabled;
    $("settingNetsh").checked = !!settings.create_netsh_blocks;
    applyTheme(!!settings.dark_mode);
  }

  $("saveSettingsBtn")?.addEventListener("click", async () => {
    try {
      const data = await api("/api/settings", {
        method: "PUT",
        body: {
          auto_start: $("settingAutoStart").checked,
          detailed_logging: $("settingLogging").checked,
          dark_mode: $("settingDark").checked,
          dns_proxy_enabled: $("settingDns").checked,
          create_netsh_blocks: $("settingNetsh").checked,
        },
      });
      applyTheme(!!data.settings.dark_mode);
      toast("Settings saved", data.autostart?.message || "Preferences updated.");
    } catch (error) { showError(error); }
  });

  $("backupBtn")?.addEventListener("click", async () => {
    try {
      const data = await api("/api/backup", { method: "POST" });
      $("backupResult").textContent = "Backed up " + data.copied.join(", ") + " → " + data.folder;
      toast("Database backup complete", data.copied.length + " files copied.");
    } catch (error) { showError(error); }
  });

  async function loadUsers() {
    if (!isAdmin) return;
    const data = await api("/api/users");
    const tbody = $("userTableBody");
    tbody.replaceChildren();
    if (!data.users.length) {
      emptyRow(tbody, 4, "No users found.");
      return;
    }
    data.users.forEach((user) => {
      const tr = document.createElement("tr");
      tr.append(textCell(user.username), textCell(user.role));

      const passwordCell = document.createElement("td");
      const password = document.createElement("input");
      password.type = "password";
      password.placeholder = "Leave blank to keep";
      password.autocomplete = "new-password";
      passwordCell.appendChild(password);

      const actions = document.createElement("td");
      const roleSelect = document.createElement("select");
      ["user", "admin"].forEach((r) => {
        const option = document.createElement("option");
        option.value = r;
        option.textContent = r;
        option.selected = user.role === r;
        roleSelect.appendChild(option);
      });

      const save = actionButton("Save", "ghost-button compact", async () => {
        await api("/api/users/" + encodeURIComponent(user.username), {
          method: "PUT",
          body: { role: roleSelect.value, password: password.value },
        });
        password.value = "";
        toast("User updated", user.username);
        await loadUsers();
      });

      const remove = actionButton("Delete", "danger-button compact", async () => {
        if (!confirm("Delete user " + user.username + "?")) return;
        await api("/api/users/" + encodeURIComponent(user.username), { method: "DELETE" });
        toast("User deleted", user.username);
        await loadUsers();
      });

      actions.append(roleSelect, save, remove);
      tr.append(passwordCell, actions);
      tbody.appendChild(tr);
    });
  }

  $("userForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/users", {
        method: "POST",
        body: {
          username: $("newUsername").value.trim(),
          password: $("newPassword").value,
          role: $("newUserRole").value,
        },
      });
      event.target.reset();
      toast("User created");
      await loadUsers();
      await loadOverview();
    } catch (error) { showError(error); }
  });

  async function bootstrap() {
    try {
      const data = await api("/api/bootstrap");
      applyTheme(!!data.settings.dark_mode);
      await loadOverview();
      await sampleTraffic();
    } catch (error) {
      showError(error);
    }
  }

  window.addEventListener("resize", drawTraffic);

  setInterval(() => {
    if (activePage === "overview") {
      loadOverview().catch(() => {});
      sampleTraffic().catch(() => {});
    }
  }, 2500);

  bootstrap();
})();