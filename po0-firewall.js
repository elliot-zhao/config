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
  String(typeof $argument !== "undefined" ? $argument : "").split("&").forEach(function (pair) {
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
    return w.ssid ? "Wi-Fi：" + w.ssid : /^pdp_ip/.test(iface) ? "蜂窝网络" : "当前网络";
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
  function localAPI(path, body) {
    return new Promise(function (resolve, reject) {
      var ended = false;
      var timer = setTimeout(function () {
        if (!ended) { ended = true; reject(new Error("读取 Surge 当前配置超时；本次不加白。")); }
      }, 4000);
      function settle(error, value) {
        if (ended) return;
        ended = true; clearTimeout(timer);
        if (error) reject(error); else resolve(value);
      }
      try {
        if (typeof $httpAPI !== "function") throw new Error("此环境无法读取 Surge 当前配置；本次不加白。");
        $httpAPI("GET", path, body || {}, function (r) {
          if (!r || r.error) settle(new Error("无法读取 Surge 当前配置；本次不加白。"));
          else settle(null, r);
        });
      } catch (_) { settle(new Error("无法调用 Surge 配置读取接口；本次不加白。")); }
    });
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
  async function api(item, readonly, attempt) {
    if (!current()) return { cancelled: true };
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
    if (retry && attempt < 3) { await wait(1500 * attempt); return api(item, readonly, attempt + 1); }
    if (response.error || !response.status) return { error: "网络请求失败（共尝试 " + attempt + " 次）" };
    if (response.status < 200 || response.status >= 300) return { error: "HTTP " + response.status + (response.status === 403 ? "：请检查 token 权限/固定槽位冲突" : "") };
    return normalize(response.data, item, readonly);
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
    var lines = [head + (ok ? "✅ " : "⚠️ ") + result.list.length + "/" + result.limit + " · " + state];
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
    var body = (shared ? "出口 " + ips[0] + "\n" : "") + results.map(function (r, i) {
      return describe(r, i, entries[i], readonly, shared);
    }).join("\n\n");
    var result = messageCard("po0 " + (readonly ? "状态 " : "加白 ") + count + "/" + results.length + (readonly ? " · 只读" : ""), body,
      failed ? "error" : count === results.length ? "good" : "alert", readonly, source);
    result.signature = JSON.stringify(results);
    return result;
  }
  async function main() {
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
    if (!connected()) { done(card("po0 · 无网络", "未发送查询或加白请求。")); return; }
    var entries = tokens();
    if (!readonly) {
      attemptedWrite = true;
      generation = String(Date.now()) + "_" + Math.random().toString(36).slice(2);
      if (!write(key + "_generation", generation)) throw new Error("无法写入本地执行记录；本次不加白。");
      if (supportedEvent) await wait(2000);
      if (!current()) { done(); return; }
      var reason = await suspension();
      if (!current()) { done(); return; }
      if (reason) {
        var skipped = messageCard("po0 加白 · 已跳过", networkLabel() + "\n" + reason, "info", false, "挂起网络");
        write(key + "_add", skipped); done(skipped); return;
      }
    }
    var results = await Promise.all(entries.map(function (item) { return api(item, readonly, 1); }));
    if (!current() || results.some(function (r) { return r.cancelled; })) { done(); return; }
    var failed = results.some(function (r) { return r.error || !r.ok; });
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
    var result = messageCard("po0 " + (action === "status" ? "查询" : "加白") + " · 未完成",
      redact(error && error.message || "脚本异常"), "error", action === "status", "执行失败");
    if (attemptedWrite && current()) write(key + "_add", result);
    // 自动错误只在变化时通知，避免同一配置问题反复打扰。
    if (!panel && current() && read(key + "_error") !== result.content) { notice(result); write(key + "_error", result.content); }
    done(result);
  });
})();
