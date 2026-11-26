/* po0fw Surge
 * 自动读取 [SSID Setting]；状态 GET 与加白 POST 严格分开。
 * API contract: https://github.com/w0ven/po0fw/blob/main/po0fw.sh
 * 不存储配置全文或 token；不会修改 Surge 配置。
 */
(function () {
  "use strict";
  var API = "https://124.221.69.228/api/firewall/";
  var trigger = typeof $trigger === "string" ? $trigger : "";
  var eventName = typeof $event !== "undefined" && $event ? $event.name : "";
  var scriptType = typeof $script !== "undefined" ? $script.type : "generic";
  var panel = typeof $input !== "undefined" && $input && $input.purpose === "panel";
  var network = typeof $network !== "undefined" && $network ? $network : {};
  var params = {};
  var argumentsText = String(typeof $argument !== "undefined" ? $argument : "");
  // Wi-Fi 名单放在参数末尾，保留名称中的 &、=、% 等字符，不当作查询参数解析。
  var ssidArgument = argumentsText.indexOf("&exclude_ssids=");
  if (ssidArgument >= 0) {
    params.exclude_ssids = argumentsText.slice(ssidArgument + "&exclude_ssids=".length);
    argumentsText = argumentsText.slice(0, ssidArgument);
  }
  // 从后往前拆原文参数（策略组名、节点名里可能有 & 等字符）；兼容旧模块传入的 policy_group，但不再用它筛选节点。
  ["select_groups", "node_keywords", "node_names", "policy_group"].forEach(function (name) {
    var marker = "&" + name + "=", at = argumentsText.indexOf(marker);
    if (at >= 0) { params[name] = argumentsText.slice(at + marker.length); argumentsText = argumentsText.slice(0, at); }
  });
  argumentsText.split("&").forEach(function (pair) {
    var n = pair.indexOf("=");
    if (n < 0) return;
    var v = pair.slice(n + 1);
    try { v = decodeURIComponent(v); } catch (_) {}
    params[pair.slice(0, n).trim()] = v;
  });
  var hash = 2166136261;
  var tokenText = String(params.tokens || "");
  for (var i = 0; i < tokenText.length; i++) hash = Math.imul(hash ^ tokenText.charCodeAt(i), 16777619);
  var key = "po0_v2_" + (hash >>> 0).toString(16);
  var action = params.action || "status"; // 未指定动作时只读，绝不默认加白。
  var generation = null;
  var finished = false;
  var attemptedWrite = false;
  // 设备上的模块级名单，不绑定 token；更新脚本、修改 token 后仍保留。
  var networkKey = "po0_firewall_network_exclusions_v1";
  var selectedNode = "";
  var DIRECT_MODE = "当前为全局直连模式；不加白。";
  var checkedAt = 0; // 本次节点检查读取请求记录的时间

  function read(k) {
    try { return JSON.parse($persistentStore.read(k) || "null"); } catch (_) { return null; }
  }
  function write(k, v) {
    try { return $persistentStore.write(JSON.stringify(v), k); } catch (_) { return false; }
  }
  function current() { return generation === null || read(key + "_generation") === generation; }
  function card(title, content, tone) {
    tone = tone || "info";
    return { title: title, content: content, tone: tone,
      icon: tone === "error" || tone === "alert" ? "exclamationmark.shield" : "checkmark.shield",
      "icon-color": { good: "#34C759", info: "#007AFF", alert: "#FF9500", error: "#FF3B30" }[tone] || "#007AFF" };
  }
  function done(value) {
    if (finished) return;
    finished = true;
    if (panel || scriptType === "generic") {
      // style 会覆盖自定义图标；只把 Surge 支持的显示字段交给面板。
      $done(value ? { title: value.title, content: value.content, icon: value.icon, "icon-color": value["icon-color"] } : {});
    } else $done();
  }
  function redact(s) { return String(s).replace(/pgnfw_[A-Za-z0-9_-]+/g, "[token]"); }
  function notice(value) {
    try { $notification.post("po0 防火墙", value.title, redact(value.content)); } catch (_) {}
  }
  function wait(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }
  function connected() { return !!((network.v4 || {}).primaryAddress || (network.v6 || {}).primaryAddress); }
  function networkLabel() {
    var w = network.wifi || {};
    var iface = (network.v4 || {}).primaryInterface || (network.v6 || {}).primaryInterface || "";
    var carrier = String((network["cellular-data"] || {}).carrier || "").trim();
    return w.ssid ? "Wi-Fi：" + w.ssid : /^pdp_ip/.test(iface) ? "蜂窝网络" + (carrier ? "：" + carrier : "") : "当前网络";
  }
  function networkIdentity() {
    var w = network.wifi || {}, v4 = network.v4 || {}, v6 = network.v6 || {};
    var interfaces = [v4.primaryInterface, v6.primaryInterface].filter(Boolean);
    var cellular = interfaces.some(function (v) { return /^pdp_ip/.test(v); });
    if (!connected() || cellular && (w.ssid || w.bssid || interfaces.some(function (v) { return !/^pdp_ip/.test(v); }))) return null;
    if (cellular) {
      // 运营商标识只用 Surge 返回的 carrier 原值，不做解释。
      var carrier = String((network["cellular-data"] || {}).carrier || "").trim();
      return { type: "cellular", carrier: carrier, label: "蜂窝网络" + (carrier ? "：" + carrier : "") };
    }
    if (typeof w.ssid === "string" && w.ssid.length) return { type: "wifi", ssid: w.ssid, label: "Wi-Fi：" + w.ssid };
    return null;
  }
  function networkRules() {
    // lock_cellular：1（默认）锁定，蜂窝始终自动加白、面板不能排除；0 允许在面板按运营商排除。
    var lock = String(params.lock_cellular === undefined ? "1" : params.lock_cellular).trim();
    if (lock !== "0" && lock !== "1") throw new Error("lock_cellular 请填 0 或 1；本次不加白。");
    var raw;
    try { raw = $persistentStore.read(networkKey); } catch (_) { throw new Error("无法读取本地网络排除名单；本次不加白。"); }
    var saved = { ssids: [], cellular: false, carriers: [] };
    if (raw) {
      try { saved = JSON.parse(raw); } catch (_) { throw new Error("本地网络排除名单损坏；请运行清空排除脚本后重新设置。"); }
      if (saved && typeof saved === "object" && saved.carriers === undefined) saved.carriers = []; // 旧版名单没有运营商这一项
      if (!saved || !Array.isArray(saved.ssids) || saved.ssids.some(function (v) { return typeof v !== "string" || !v.length; }) || typeof saved.cellular !== "boolean" ||
        !Array.isArray(saved.carriers) || saved.carriers.some(function (v) { return typeof v !== "string" || !v.length; })) {
        throw new Error("本地网络排除名单格式无效；请运行清空排除脚本后重新设置。");
      }
    }
    return { configured: String(params.exclude_ssids || "").split("|").map(function (s) { return s.trim(); }).filter(Boolean),
      lockCellular: lock === "1", saved: saved };
  }
  function networkExclusion() {
    var rules = networkRules(), currentNetwork = networkIdentity();
    if (!currentNetwork) {
      if (rules.configured.length || rules.saved.ssids.length || !rules.lockCellular && rules.saved.carriers.length) {
        throw new Error("无法确认当前网络或读取 Wi-Fi 名称，不能判断排除名单；本次不加白。");
      }
      return "";
    }
    // 蜂窝：lock_cellular=1 时一律加白；=0 时看面板记下的运营商。旧版面板的「整体蜂窝排除」不再生效。
    if (currentNetwork.type === "cellular") {
      if (rules.lockCellular || !currentNetwork.carrier) return "";
      return rules.saved.carriers.indexOf(currentNetwork.carrier) >= 0 ? "此蜂窝网络（" + currentNetwork.carrier + "）已在面板排除名单中。" : "";
    }
    if (rules.configured.indexOf(currentNetwork.ssid) >= 0) return "此 Wi-Fi 已在模块参数的排除名单中。";
    if (rules.saved.ssids.indexOf(currentNetwork.ssid) >= 0) return "此 Wi-Fi 已在本地快捷排除名单中。";
    return "";
  }
  // 排除面板，优先级：SSID Setting ＞ 参数（lock_cellular / exclude_ssids）＞ 面板名单。
  // SSID Setting 命中、lock_cellular=1 的蜂窝、exclude_ssids 里的 Wi-Fi：只显示，不改名单。
  async function networkControl(change) {
    var rules = networkRules(), identity = networkIdentity();
    var tail = "\n仅控制自动加白 · 不影响 Surge 上网";
    if (!identity) return card("po0 网络排除 · 无法识别", "未更改名单。请连接 Wi-Fi 并允许读取名称，或使用蜂窝网络。", "alert");
    var ssidHit = "", ssidError = "";
    try { ssidHit = await suspension(); } catch (error) { ssidError = String(error && error.message || "无法读取 SSID Setting"); }
    if (ssidHit) {
      return card("po0 网络排除 · 已挂起", identity.label + "\n" +
        "由 SSID Setting 挂起（优先级最高），不会自动加白\n面板不可更改" + tail, "alert");
    }
    var warn = ssidError ? "\n⚠️ " + ssidError.replace(/；?本次不加白。?$/, "") : "";
    var saved = rules.saved;
    if (identity.type === "cellular") {
      if (rules.lockCellular) {
        return card("po0 网络排除 · 未排除", identity.label + "\n已锁定（lock_cellular=1）：蜂窝始终自动加白，面板不可排除" + warn + tail, "info");
      }
      if (!identity.carrier) {
        return card("po0 网络排除 · 无法识别", identity.label + "\nSurge 没有返回运营商信息，无法按运营商排除；未更改名单" + warn + tail, "alert");
      }
      var cellBlocked = saved.carriers.indexOf(identity.carrier) >= 0;
      if (change) {
        if (cellBlocked) saved.carriers = saved.carriers.filter(function (c) { return c !== identity.carrier; });
        else saved.carriers.push(identity.carrier);
        if (!write(networkKey, saved)) throw new Error("保存网络排除设置失败；未更改名单。");
        cellBlocked = !cellBlocked;
      }
      return card("po0 网络排除 · " + (cellBlocked ? "已排除" : "未排除"), identity.label + "\n" +
        (cellBlocked ? "点刷新解除排除" : "点刷新将当前运营商设为不自动加白") + warn + tail, cellBlocked ? "alert" : "info");
    }
    var localBlocked = saved.ssids.indexOf(identity.ssid) >= 0;
    var fixed = rules.configured.indexOf(identity.ssid) >= 0;
    if (change && !fixed) {
      if (localBlocked) saved.ssids = saved.ssids.filter(function (s) { return s !== identity.ssid; });
      else saved.ssids.push(identity.ssid);
      if (!write(networkKey, saved)) throw new Error("保存网络排除设置失败；未更改名单。");
      localBlocked = !localBlocked;
    }
    var blocked = fixed || localBlocked;
    return card("po0 网络排除 · " + (blocked ? "已排除" : "未排除"), identity.label + "\n" +
      (fixed ? "参数里已排除，请去参数 exclude_ssids 里删除" : localBlocked ? "点刷新解除排除" : "点刷新将当前 Wi-Fi 设为不自动加白") +
      warn + tail, blocked ? "alert" : "info");
  }
  function cached() {
    var readonly = action !== "add", saved = read(key + (readonly ? "_snapshot" : "_add"));
    if (saved && saved.layout === 2) return decorate(saved, readonly);
    return card(readonly ? "po0 状态 · 只读" : "po0 手动加白",
      (saved ? "已有旧记录，请刷新更新显示。" : "暂无记录") + "\n" +
      (readonly ? "点刷新查询 · 不加白" : "点刷新执行加白") + "\n" + scheduleLabel());
  }
  function stamp(at) {
    var d = new Date(at);
    function two(n) { return (n < 10 ? "0" : "") + n; }
    return two(d.getMonth() + 1) + "/" + two(d.getDate()) + " " + two(d.getHours()) + ":" + two(d.getMinutes());
  }
  function decorate(record, readonly) {
    record.content = record.body + "\n\n记录 " + stamp(record.recordedAt) + " · " + record.source + "\n" +
      (readonly ? "点刷新仅查询" : "点刷新加白") + " · " + scheduleLabel();
    return record;
  }
  function messageCard(title, body, tone, readonly, source) {
    var result = card(title, "", tone);
    result.layout = 2; result.body = body; result.recordedAt = Date.now(); result.source = source;
    return decorate(result, readonly);
  }
  function tokens() {
    var values = tokenText.split(/[,，|;、\s]+/).filter(Boolean), seen = {};
    if (!values.length) throw new Error("请填写模块参数 tokens。");
    if (values.length > 32) throw new Error("单次最多支持 32 个 token。");
    return values.map(function (v, n) {
      var m = /^(pgnfw_[A-Za-z0-9_-]+)(?:@([0-4]))?$/.exec(v);
      if (!m) throw new Error("第 " + (n + 1) + " 个 token 格式无效；固定槽位可用 @0 至 @4。");
      if (seen[m[1]]) throw new Error("同一 token 不能重复填写。");
      seen[m[1]] = true;
      return { token: m[1], slot: m[2] === undefined ? null : Number(m[2]) };
    });
  }
  function fallbackPlan() {
    var enabled = String(params.fallback_enabled === undefined ? "1" : params.fallback_enabled).trim();
    // 关闭优先于时间解析：禁用后不读取、不校验时间设置，不访问任何接口。
    if (enabled === "0") return { unit: "off", value: 0, totalMinutes: 0, uniform: true };
    if (enabled !== "1") throw new Error("fallback_enabled 请填写 0（关闭）或 1（开启）。");
    var rawMinutes = String(params.fallback_minutes === undefined ? "30" : params.fallback_minutes).trim();
    var rawHours = String(params.fallback_hours === undefined ? "0" : params.fallback_hours).trim();
    if (!/^(0|[1-9]\d*)$/.test(rawMinutes) || !/^(0|[1-9]\d*)$/.test(rawHours) || Number(rawMinutes) > 59 || Number(rawHours) > 23) {
      throw new Error("兜底参数无效：分钟请填 0–59，小时请填 0–23 的整数；1 小时请填分钟 0、小时 1。");
    }
    var minutes = Number(rawMinutes), hours = Number(rawHours);
    if (minutes > 0) return { unit: "minutes", value: minutes, totalMinutes: minutes, uniform: 60 % minutes === 0 };
    if (hours > 0) return { unit: "hours", value: hours, totalMinutes: hours * 60, uniform: 24 % hours === 0 };
    return { unit: "off", value: 0, totalMinutes: 0, uniform: true };
  }
  function scheduleLabel() {
    try {
      var plan = fallbackPlan();
      if (plan.unit === "off") return "兜底关闭";
      var unit = plan.unit === "minutes" ? "分钟" : "小时";
      return plan.uniform ? "兜底 " + plan.value + " " + unit : unit + "步进 " + plan.value;
    } catch (_) { return "兜底参数无效（查看说明）"; }
  }
  function localAPI(path, body, label) {
    label = label || "当前配置";
    return new Promise(function (resolve, reject) {
      var ended = false;
      var timer = setTimeout(function () {
        if (!ended) { ended = true; reject(new Error("读取 Surge " + label + "超时；本次不加白。")); }
      }, 4000);
      function settle(error, value) {
        if (ended) return;
        ended = true; clearTimeout(timer);
        if (error) reject(error); else resolve(value);
      }
      try {
        if (typeof $httpAPI !== "function") throw new Error("此环境无法读取 Surge " + label + "；本次不加白。");
        $httpAPI("GET", path, body || {}, function (r) {
          if (!r || r.error) settle(new Error("无法读取 Surge " + label + "；本次不加白。"));
          else settle(null, r);
        });
      } catch (_) { settle(new Error("无法调用 Surge " + label + "读取接口；本次不加白。")); }
    });
  }
  function nodeFilter() {
    function list(v) { return String(v || "").split("|").map(function (s) { return s.trim(); }).filter(Boolean); }
    var names = list(params.node_names), keywords = list(params.node_keywords);
    return names.length || keywords.length ? { names: names, keywords: keywords } : null;
  }
  function requestNetworkMark() {
    // 只保存网络特征的哈希和切换时间，不保存请求、域名、URL 或配置全文。
    var w = network.wifi || {}, v4 = network.v4 || {}, v6 = network.v6 || {};
    var text = JSON.stringify([w.ssid, w.bssid, v4.primaryInterface, v4.primaryAddress, v4.primaryRouter, v6.primaryInterface, v6.primaryAddress]);
    var h = 2166136261;
    for (var n = 0; n < text.length; n++) h = Math.imul(h ^ text.charCodeAt(n), 16777619);
    return (h >>> 0).toString(16);
  }
  function observeRequestNetwork() {
    if (!nodeFilter()) return;
    var now = Date.now(), fingerprint = requestNetworkMark(), old = read(key + "_request_network");
    var changed = old && old.fingerprint !== fingerprint;
    var reset = eventName === "network-changed" || eventName === "engine-started";
    var invalid = old && (typeof old.since !== "number" || !isFinite(old.since) || old.since < 0 || old.since > now);
    var since = reset || changed || invalid ? now : old ? old.since : 0;
    if (!write(key + "_request_network", { fingerprint: fingerprint, since: since })) throw new Error("无法保存请求的网络边界；本次不加白。");
  }
  function requestTime(value) {
    if (typeof value === "number" && isFinite(value) && value > 0) return value < 1e12 ? value * 1000 : value;
    if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
      var time = Date.parse(value); return isFinite(time) && time > 0 ? time : null;
    }
    return null;
  }
  function requestRows(value, label) {
    if (value && Array.isArray(value.requests)) return value.requests;
    if (Array.isArray(value)) return value;
    throw new Error("Surge " + label + "格式无法识别；本次不加白。");
  }
  // floor：当前网络的边界（切网时间）；recentFloor：上次检查的时间（没有就等于 floor）。
  function requestCandidate(row, active, floor, recentFloor, now) {
    if (!row || typeof row !== "object") return false;
    if (row.rejected === true || /^rejected$/i.test(String(row.status || ""))) return false;
    var start = requestTime(row.startDate), end = requestTime(row.completedDate);
    // 切网后只认在当前网络边界之后发起的请求，不能复用上个网络的历史记录。
    if (floor > 0 && (start === null || start < floor)) return false;
    if (start !== null && start > now || end !== null && (end > now || start !== null && end < start)) return false;
    if (active) {
      return end === null && row.completed !== true && row.disconnected !== true && row.failed !== true &&
        !/^(?:complete|completed|closed|disconnected|failed|error|finished|rejected|cancelled|canceled)$/i.test(String(row.status || ""));
    }
    // 已结束的请求：上次检查以来在这个网络上有过活动就算。
    var activity = end !== null ? end : start;
    return activity !== null && activity >= recentFloor && activity <= now;
  }
  // 记下这次检查的时间，下次检查只看这之后的请求。
  function markChecked() {
    if (!checkedAt) return;
    write(key + "_last_check", { fingerprint: requestNetworkMark(), at: checkedAt });
  }
  async function nodeRestriction() {
    var filter = nodeFilter();
    if (!filter) return "";
    selectedNode = "";
    var mode = await localAPI("/v1/outbound", {}, "出站模式");
    if (mode.mode === "direct") return DIRECT_MODE;
    if (mode.mode !== "rule" && mode.mode !== "proxy") throw new Error("无法确认 Surge 出站模式；本次不加白。");
    var mark = read(key + "_request_network");
    if (!mark || mark.fingerprint !== requestNetworkMark() || typeof mark.since !== "number" || !isFinite(mark.since) || mark.since < 0 || mark.since > Date.now()) {
      throw new Error("网络环境已变化或请求边界不可读；等待下一次触发。");
    }
    var last = read(key + "_last_check");
    var recentFloor = last && last.fingerprint === mark.fingerprint && typeof last.at === "number" && isFinite(last.at) &&
      last.at >= mark.since && last.at <= Date.now() ? last.at : mark.since;
    // 策略组列表：用于区分策略组和节点、把外部节点标识换成名称。
    var all = await localAPI("/v1/policies", { include_external: true }, "策略类型列表");
    var groupRows = Array.isArray(all["policy-groups"]) ? all["policy-groups"] : all.groups;
    if (!Array.isArray(groupRows)) throw new Error("无法区分请求中的策略组与节点；本次不加白。");
    var groups = groupRows.map(function (entry) { return typeof entry === "string" ? entry : entry && entry.name; });
    if (groups.some(function (name) { return typeof name !== "string" || !name; })) throw new Error("Surge 策略组列表格式无法识别；本次不加白。");
    var external = Array.isArray(all["external-policies"]) ? all["external-policies"] : [];
    // 返回节点名；是策略组或无法确认时返回 null。
    function nodeName(candidate) {
      if (groups.indexOf(candidate) >= 0) return null;
      var name = candidate;
      if (/^POLICY::/.test(name)) {
        var mapped = external.filter(function (p) { return p && p.identifier === name && typeof p.name === "string"; });
        if (mapped.length !== 1 || !mapped[0].name) return null;
        name = mapped[0].name;
      }
      return groups.indexOf(name) >= 0 ? null : name;
    }
    function hits(name) {
      return filter.names.indexOf(name) >= 0 || filter.keywords.some(function (word) { return name.toLowerCase().indexOf(word.toLowerCase()) >= 0; });
    }
    function show(list, suffix) {
      selectedNode = list.slice(0, 3).join("、") + (list.length > 3 ? " 等 " + list.length + " 个" : "") + suffix;
    }
    // 1) select_groups 指定的手动选择组当前选中的节点：顺着嵌套的 select 组往下找，只认节点，不认策略组名。
    var picked = [], pickedGroups = [];
    selectedChains().forEach(function (entry) {
      var name = nodeName(entry.name);
      if (!name || !hits(name)) return;
      if (picked.indexOf(name) < 0) picked.push(name);
      if (pickedGroups.indexOf(entry.group) < 0) pickedGroups.push(entry.group);
    });
    checkedAt = Date.now();
    if (picked.length) { show(picked, "（" + pickedGroups.slice(0, 2).join("、") + " 选中）"); return ""; }
    // 2) 上次检查以来、当前网络上的请求记录。
    var active = requestRows(await localAPI("/v1/requests/active", {}, "活动请求"), "活动请求");
    var recent = requestRows(await localAPI("/v1/requests/recent", {}, "近期请求"), "近期请求");
    var now = Date.now(), candidates = [];
    checkedAt = now;
    function collect(rows, isActive) {
      rows.forEach(function (row) {
        if (!requestCandidate(row, isActive, mark.since, recentFloor, now)) return;
        // 只读该次请求的最终策略；不匹配 originalPolicyName、规则、URL 或备注。
        if (typeof row.policyName !== "string" || !row.policyName) return;
        var name = row.policyName;
        if (/^(?:DIRECT|REJECT(?:-.*)?|PROXY)$/i.test(name) || /^DEVICE:/i.test(name)) return;
        if (candidates.indexOf(name) < 0) candidates.push(name);
      });
    }
    collect(active, true); collect(recent, false);
    if (!candidates.length) return "上次检查以来没有代理请求，手动选择组也没有选中指定节点；未加白。";
    var matched = [], unresolved = false;
    candidates.forEach(function (candidate) {
      var name = nodeName(candidate);
      if (!name) { unresolved = true; return; }
      if (hits(name) && matched.indexOf(name) < 0) matched.push(name);
    });
    if (!matched.length) {
      return unresolved ? "请求尚未提供可确认的最终节点，或已知节点未匹配；手动选择组也没有选中指定节点；未加白。" :
        "实际请求的节点未匹配指定名称或关键词，手动选择组也没有选中；未加白。";
    }
    show(matched, "");
    return "";
  }
  // select_groups：组名里包含的文字，多个用 | 分隔，不分大小写；不填则不做「选中」判断。
  function selectGroupWords() {
    return String(params.select_groups || "").split("|").map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean);
  }
  // 名称匹配 select_groups 的手动选择组当前选中的策略，含嵌套 select 组一路往下的每一层。
  // 返回 [{ group: 起点组名, name: 选中的策略名 }]；没填参数或读不到时返回空列表。
  function selectedChains() {
    var words = selectGroupWords();
    if (!words.length) return [];
    var details = null;
    try {
      if (typeof $surge !== "undefined" && $surge && typeof $surge.selectGroupDetails === "function") details = $surge.selectGroupDetails();
    } catch (_) {}
    var decisions = details && details.decisions;
    if (!decisions || typeof decisions !== "object") return [];
    var out = [];
    Object.keys(decisions).forEach(function (group) {
      var lower = group.toLowerCase();
      if (!words.some(function (w) { return lower.indexOf(w) >= 0; })) return;
      var seen = {}, cur = decisions[group], depth = 0;
      while (typeof cur === "string" && cur && !seen[cur] && depth < 16) {
        seen[cur] = true;
        out.push({ group: group, name: cur });
        cur = decisions[cur];
        depth++;
      }
    });
    return out;
  }
  // 注释分隔符只在引号外、且行首或前有空格时生效。
  function withoutComment(line) {
    var quote = false, escape = false;
    for (var n = 0; n < line.length; n++) {
      var c = line[n];
      if (escape) { escape = false; continue; }
      if (quote && c === "\\") { escape = true; continue; }
      if (c === '"') { quote = !quote; continue; }
      if (!quote && (n === 0 || /\s/.test(line[n - 1])) && (c === "#" || c === ";" || line.slice(n, n + 2) === "//")) return line.slice(0, n).trim();
    }
    if (quote) throw new Error("挂起配置的引号不完整；本次不加白。");
    return line.trim();
  }
  function unquote(value) {
    value = value.trim();
    if (value[0] !== '"') return value;
    try { return JSON.parse(value); } catch (_) { throw new Error("无法解析挂起配置中的 Wi-Fi 名称；本次不加白。"); }
  }
  function parseProfile(profile) {
    var inSection = false, rules = [], unresolved = false;
    String(profile).replace(/^\uFEFF/, "").split(/\r?\n/).forEach(function (raw) {
      var trimmed = raw.trim();
      if (inSection && /^#!include\b/i.test(trimmed)) { unresolved = true; return; }
      if (inSection && /(?:#!|\/\/)\!?REQUIREMENT\b|#!(?:IOS|MACOS|TVOS)-ONLY\b/i.test(trimmed)) {
        throw new Error("SSID Setting 中有未展开的条件指令；本次不加白。");
      }
      // 其他 section 的内容无需解析，也不输出/持久化。
      var section = /^\[([^\]]+)\]/.exec(trimmed);
      if (section) { inSection = section[1].trim().toLowerCase() === "ssid setting"; return; }
      if (!inSection) return;
      var line = withoutComment(raw);
      if (!line) return;
      var m = /^(.*?)\s+([A-Za-z][\w-]*\s*=.*)$/.exec(line);
      if (!m) {
        if (/\bsuspend\b/i.test(line)) throw new Error("无法解析 SSID Setting 挂起配置；本次不加白。");
        return;
      }
      var setting = /(?:^|,)\s*suspend\s*=\s*(true|false)\s*(?=,|$)/i.exec(m[2]);
      if (!setting) {
        if (/(?:^|,)\s*suspend\s*=/i.test(m[2])) throw new Error("suspend 参数不是 true/false；本次不加白。");
        return;
      }
      var expression = unquote(m[1].replace(/\s*=\s*$/, ""));
      rules.push({ expression: expression, suspended: setting[1].toLowerCase() === "true" });
    });
    return { rules: rules, unresolved: unresolved };
  }
  function wildcard(pattern, value, insensitive) {
    var escaped = String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
    return new RegExp("^" + escaped + "$", insensitive ? "i" : "").test(String(value));
  }
  // true / false / null（所需网络信息不可得）。
  function matchNetwork(expression) {
    var wifi = network.wifi || {}, v4 = network.v4 || {}, v6 = network.v6 || {};
    var iface = v4.primaryInterface || v6.primaryInterface || "";
    var cellular = /^pdp_ip/.test(iface), hasWifi = !!(wifi.ssid || wifi.bssid);
    var m = /^(SSID|BSSID|ROUTER|TYPE|MCCMNC):(.*)$/i.exec(expression);
    var type = m ? m[1].toUpperCase() : "LEGACY", value = unquote(m ? m[2] : expression);
    if (type === "SSID") return cellular ? false : wifi.ssid ? wildcard(value, wifi.ssid, false) : null;
    if (type === "BSSID") return cellular ? false : wifi.bssid ? wildcard(value, wifi.bssid, true) : null;
    if (type === "ROUTER") return v4.primaryRouter ? String(v4.primaryRouter) === value : null;
    if (type === "TYPE") {
      value = value.toUpperCase();
      if (["WIFI", "WIRED", "CELLULAR"].indexOf(value) < 0) return null;
      if (cellular) return value === "CELLULAR";
      if (hasWifi) return value === "WIFI";
      return null; // en0 本身不能可靠地区分有线与 SSID 权限缺失。
    }
    if (type === "MCCMNC") return hasWifi ? false : null; // 公开 $network 未承诺 MCCMNC 字段。
    if (type === "LEGACY") {
      if (/[?*]/.test(value)) return cellular ? false : wifi.ssid ? wildcard(value, wifi.ssid, false) : null;
      if (wifi.ssid === value || (wifi.bssid && String(wifi.bssid).toLowerCase() === value.toLowerCase()) || v4.primaryRouter === value) return true;
      if (cellular || (wifi.ssid && wifi.bssid && v4.primaryRouter)) return false;
      return null;
    }
    return null;
  }
  async function suspension() {
    var r = await localAPI("/v1/profiles/current", { sensitive: 0 });
    if (typeof r.profile !== "string" || !/^\s*\[[^\]]+\]/m.test(r.profile)) throw new Error("Surge 没有返回可读的当前配置；本次不加白。");
    var parsed = parseProfile(r.profile);
    if (parsed.unresolved) {
      // 新版 Surge 可读取拆分 section；旧版不支持则明确停止加白。
      var section = await localAPI("/v1/profiles/section", { name: "SSID Setting" });
      if (typeof section.content !== "string") throw new Error("无法展开 SSID Setting 引用的配置；本次不加白。");
      parsed = parseProfile("[SSID Setting]\n" + section.content);
      if (parsed.unresolved) throw new Error("SSID Setting 仍有未展开的 include；本次不加白。");
    }
    var yes = [], no = [], unknown = false;
    parsed.rules.forEach(function (rule) {
      var m = matchNetwork(rule.expression);
      if (m === true) (rule.suspended ? yes : no).push(rule.expression);
      if (m === null && rule.suspended) unknown = true;
    });
    if (yes.length && no.length) throw new Error("当前网络同时匹配 suspend=true 和 false；为避免猜测优先级，本次不加白。");
    if (yes.length) return "匹配挂起配置：" + yes.join("、") + "；未发送加白请求。";
    if (unknown) throw new Error("无法完整判断挂起条件（可能缺少 SSID/BSSID/网关信息）；本次不加白。");
    return "";
  }
  function ipv4(value) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/24)?$/.exec(String(value || ""));
    if (!m || m.slice(1, 5).some(function (p) { return Number(p) > 255; })) return null;
    return { parts: m.slice(1, 5).map(Number), subnet: !!m[5] };
  }
  function sameSubnet(a, b) {
    var aa = ipv4(a), bb = ipv4(b);
    if (!aa || !bb) return false;
    var count = aa.subnet || bb.subnet ? 3 : 4;
    for (var n = 0; n < count; n++) if (aa.parts[n] !== bb.parts[n]) return false;
    return true;
  }
  function normalize(data, item, readonly) {
    if (!data || typeof data !== "object") return { error: "API 响应格式异常" };
    if (typeof data.code === "number" && data.code >= 400) return { error: "API 错误 " + data.code };
    if (!Array.isArray(data.whitelist) || typeof data.enabled !== "boolean") return { error: "API 缺少白名单或启用状态" };
    var list = data.whitelist.map(function (entry) {
      if (typeof entry === "string") return { ip: entry, slot: null, slotKnown: false };
      entry = entry || {};
      var known = Object.prototype.hasOwnProperty.call(entry, "slot");
      return { ip: String(entry.ip || "?"), slot: known ? entry.slot : null, slotKnown: known };
    });
    var matching = list.filter(function (entry) { return sameSubnet(entry.ip, data.currentIp); });
    var applied = data.enabled && matching.some(function (entry) {
      return item.slot === null || entry.slot !== null && entry.slot !== undefined && String(entry.slot) === String(item.slot);
    });
    return { enabled: data.enabled, ip: ipv4(data.currentIp) ? data.currentIp : "未知", list: list,
      limit: data.limit === undefined ? "?" : data.limit, matching: matching, applied: applied,
      ok: readonly || applied };
  }
  // force=true：「po0 手动加白」，不看节点、SSID Setting 和排除名单。
  async function api(item, readonly, attempt, force) {
    if (!current()) return { cancelled: true };
    // 排除名单可能在等待配置读取或重试期间被另一个面板操作更新。
    if (!readonly && !force) { var excluded = networkExclusion(); if (excluded) return { error: excluded }; }
    if (!readonly && !force && attempt > 1) {
      var nodeReason = await nodeRestriction();
      if (!current()) return { cancelled: true };
      if (nodeReason) return { error: nodeReason };
      var newExclusion = networkExclusion(); if (newExclusion) return { error: newExclusion };
    }
    var response = await new Promise(function (resolve) {
      var url = API + encodeURIComponent(item.token);
      if (!readonly) url += "/add" + (item.slot === null ? "" : "?slot=" + item.slot);
      var opts = { url: url, policy: "DIRECT", timeout: 10, "auto-redirect": false,
        headers: { "Cache-Control": "no-cache" } };
      function callback(error, resp, body) {
        var data = null; try { data = JSON.parse(body); } catch (_) {}
        resolve({ error: !!error, status: Number(resp && resp.status || 0), data: data });
      }
      try {
        if (readonly) $httpClient.get(opts, callback);
        else { opts.body = ""; opts.headers["Content-Type"] = "application/json"; $httpClient.post(opts, callback); }
      } catch (_) { resolve({ error: true, status: 0 }); }
    });
    if (!current()) return { cancelled: true };
    var retry = response.error || !response.status || response.status >= 500 || (response.status === 400 && !response.data);
    if (retry && attempt < 3) { await wait(1500 * attempt); return api(item, readonly, attempt + 1, force); }
    if (response.error || !response.status) return { error: "网络请求失败（共尝试 " + attempt + " 次）" };
    if (response.status < 200 || response.status >= 300) return { error: "HTTP " + response.status + (response.status === 403 ? "：请检查 token 权限/固定槽位冲突" : "") };
    return normalize(response.data, item, readonly);
  }
  // 先查后加（手动和自动都用）：先只读查询，当前出口（含目标槽位）已在白名单就不再添加。
  // force=true 是手动加白，添加时不再检查排除名单；自动加白在添加前仍会重新检查排除名单。
  async function ensure(item, force) {
    var status = await api(item, true, 1, force);
    if (status.cancelled || status.error) return status;
    if (status.applied) { status.ok = true; status.already = true; return status; }
    return api(item, false, 1, force);
  }
  function slotLabel(entry) {
    if (!entry.slotKnown || entry.slot === undefined) return "槽位未知";
    return entry.slot === null ? "普通" : "📌" + entry.slot;
  }
  function protectedNow(result) {
    return !result.error && result.enabled && result.ip !== "未知" && result.matching.length > 0;
  }
  function describe(result, index, item, readonly, sharedIp) {
    var head = "#" + (index + 1) + " ";
    if (result.error) return head + "❌ 请求失败\n    " + result.error;
    var ok = readonly ? protectedNow(result) : result.applied;
    var state = !result.enabled ? "防火墙未启用" : result.ip === "未知" ? "出口未知" : !result.matching.length ? "不在白名单" :
      !readonly && !result.applied ? "目标槽位未生效" : "当前 " + result.matching.map(slotLabel).join("、");
    var lines = [head + (ok ? "✅ " : "⚠️ ") + result.list.length + "/" + result.limit + " · " + state +
      (result.already ? " · 已在白名单，未重复添加" : "")];
    if (!sharedIp) lines.push("    出口 " + result.ip);
    // 只读显示实际槽位；配置的目标槽位不同才额外提示，不把目标当作结果。
    if (item.slot !== null && !result.matching.some(function (entry) { return entry.slotKnown && entry.slot !== null && String(entry.slot) === String(item.slot); })) {
      lines.push("    目标 📌" + item.slot + (readonly ? " · 本次只读" : ""));
    }
    var list = result.list.slice().sort(function (a, b) {
      var sa = a.slotKnown && a.slot !== null ? Number(a.slot) : 99;
      var sb = b.slotKnown && b.slot !== null ? Number(b.slot) : 99;
      return sa - sb;
    });
    list.forEach(function (entry) {
      lines.push("    " + entry.ip + " " + slotLabel(entry) + (sameSubnet(entry.ip, result.ip) ? " ←" : ""));
    });
    if (!list.length) lines.push("    暂无白名单条目");
    return lines.join("\n");
  }
  function resultCard(results, entries, readonly, source) {
    var count = results.filter(function (r) { return readonly ? protectedNow(r) : !r.error && r.applied; }).length;
    var failed = results.some(function (r) { return r.error || !readonly && !r.ok; });
    var ips = results.filter(function (r) { return !r.error; }).map(function (r) { return r.ip; });
    var shared = ips.length > 0 && ips.every(function (ip) { return ip === ips[0]; });
    var body = (selectedNode ? "请求节点 " + selectedNode + "\n" : "") + (shared ? "出口 " + ips[0] + "\n" : "") + results.map(function (r, i) {
      return describe(r, i, entries[i], readonly, shared);
    }).join("\n\n");
    var result = messageCard("po0 " + (readonly ? "状态 " : "加白 ") + count + "/" + results.length + (readonly ? " · 只读" : ""), body,
      failed ? "error" : count === results.length ? "good" : "alert", readonly, source);
    result.signature = JSON.stringify(results);
    return result;
  }
  async function main() {
    if (action === "network_toggle") {
      var change = panel ? trigger === "button" : trigger === "intent" || trigger === "editor" || trigger === "button";
      done(await networkControl(change)); return;
    }
    if (action === "network_clear") {
      if (panel || scriptType !== "generic" || ["button", "intent", "editor", ""].indexOf(trigger) < 0) { done(); return; }
      if (!write(networkKey, { ssids: [], cellular: false, carriers: [] })) throw new Error("清空本地网络排除名单失败。");
      done(card("po0 网络排除 · 已清空", "仅清空面板添加的 Wi-Fi 和运营商；模块参数和挂起配置继续生效。")); return;
    }
    if (["auto", "add", "status"].indexOf(action) < 0) throw new Error("未知操作；未发送请求。");
    // 面板进入页面、周期更新或未确认的触发来源一律只显示缓存。
    if (panel && trigger !== "button") { done(cached()); return; }
    var isCron = scriptType === "cron";
    var supportedEvent = eventName === "network-changed" || eventName === "engine-started";
    var manual = trigger === "button" || trigger === "intent" || trigger === "editor" || eventName === "manually" || (scriptType === "generic" && !eventName && !trigger);
    if (!supportedEvent && !isCron && !manual) { done(cached()); return; }
    // 调度时刻由 Surge cron 决定；此处只检查开关，不进行每分钟计时。
    if (isCron) {
      var plan = fallbackPlan();
      if (action !== "auto" || plan.unit === "off" || (params.timer_unit && params.timer_unit !== plan.unit)) { done(); return; }
      // 防止旧映射规则仍引用新脚本时按错误频率执行。
      if (params.scheduled_minutes !== undefined && Number(params.scheduled_minutes) !== plan.totalMinutes) { done(); return; }
    }
    if (action === "auto" && !supportedEvent && !isCron && !manual) { done(); return; }
    var readonly = action === "status";
    // 「po0 手动加白」：跳过节点过滤、SSID Setting 和排除名单，只做「先查后加」。
    var force = action === "add" && manual && !isCron && !supportedEvent;
    if (!connected()) { done(card("po0 · 无网络", "未发送查询或加白请求。")); return; }
    var entries = tokens();
    var nodeChecked = false;
    if (!readonly) {
      attemptedWrite = true;
      generation = String(Date.now()) + "_" + Math.random().toString(36).slice(2);
      if (!write(key + "_generation", generation)) throw new Error("无法写入本地执行记录；本次不加白。");
      observeRequestNetwork();
      if (!force) {
        if (supportedEvent) await wait(2000);
        if (!current()) { done(); return; }
        var reason = networkExclusion() || await suspension();
        // 挂起/排除先行；节点检查放在配置读取之后，缩短判断与 POST 之间的时间。
        if (!reason) {
          reason = await nodeRestriction();
          // 换网络/启动后：在约 2、15、30、45 秒各看一次（只读本地记录，脚本 timeout 为 60 秒）。
          var later = supportedEvent ? [13000, 15000, 15000] : [];
          for (var round = 0; reason && reason !== DIRECT_MODE && round < later.length; round++) {
            await wait(later[round]);
            if (!current()) { done(); return; }
            reason = await nodeRestriction();
          }
          nodeChecked = !!nodeFilter();
        }
        if (!current()) { done(); return; }
        if (reason) {
          if (nodeChecked) markChecked();
          var skipped = messageCard("po0 加白 · 已跳过", networkLabel() + "\n" + reason, "info", false, "条件检查");
          write(key + "_add", skipped); done(decorate(skipped, false)); return;
        }
      }
    }
    var results = await Promise.all(entries.map(function (item) { return readonly ? api(item, true, 1) : ensure(item, force); }));
    if (!current() || results.some(function (r) { return r.cancelled; })) { done(); return; }
    var failed = results.some(function (r) { return r.error || !r.ok; });
    // 自动加白成功后才推进「上次检查」时间；失败时保留，下次检查还会算上这段时间的请求。
    if (nodeChecked && !failed) markChecked();
    var source = readonly ? "只读查询" : isCron ? "定时加白" : supportedEvent ? eventName === "engine-started" ? "启动加白" : "网络加白" : "手动加白";
    var result = resultCard(results, entries, readonly, source);
    var previous = read(key + "_snapshot");
    if (results.some(function (r) { return !r.error; })) write(key + "_snapshot", readonly ? result : resultCard(results, entries, true, source));
    if (!readonly) {
      write(key + "_add", result);
      if (manual || failed || !previous || previous.signature !== result.signature) notice(result);
    }
    done(result);
  }
  main().catch(function (error) {
    var result = messageCard("po0 " + (action.indexOf("network_") === 0 ? "网络排除" : action === "status" ? "查询" : "加白") + " · 未完成",
      redact(error && error.message || "脚本异常"), "error", action === "status", "执行失败");
    if (attemptedWrite && current()) write(key + "_add", result);
    // 自动错误只在变化时通知，避免同一配置问题反复打扰。
    if (!panel && current() && read(key + "_error") !== result.content) { notice(result); write(key + "_error", result.content); }
    done(result);
  });
})();
