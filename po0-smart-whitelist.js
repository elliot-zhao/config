/**
 * po0 防火墙 · 按节点自动加白（Surge）
 * ------------------------------------------------------------------
 * 面板（与原版一致 + 新增一个）：
 *   po0 状态 · 只读      action=status   点击刷新 → 查询状态与槽位，不加白
 *   po0 手动加白         action=add      点击刷新 → 立即加白（不看节点，但遵守排除）
 *   po0 排除当前网络     action=exclude  点击刷新 → 把当前 Wi-Fi / 蜂窝加入或移出排除列表
 *
 * 自动加白：网络变化、Surge 启动、原版的分钟/小时定时器，以及打开策略页（iOS 面板自动刷新时，
 *   由「po0 排除当前网络」面板顺带检查）都会检查一次，
 *   只有 nodes 参数里的节点在 active_window 分钟内「有连接请求」才会加白；
 *   latency_test=1 时，节点延迟测试结果有变化也算。
 *   先 GET 查询，当前 /24 已在白名单就不再 POST（po0 白名单是 FIFO，多余的 add 会挤掉别的设备）。
 *
 * 不加白的网络：exclude 参数、「po0 排除当前网络」面板、配置里 [SSID Setting] 的 suspend=true。
 *
 * API：
 *   GET  https://124.221.69.228/api/firewall/<token>              只读状态
 *   POST https://124.221.69.228/api/firewall/<token>/add[?slot=N]  加白当前出口 /24
 */

const API = 'https://124.221.69.228/api/firewall/';
const K = {
  snap: 'po0wl_snapshot', // 状态面板缓存（最近一次查询 / 自动检查）
  add: 'po0wl_add', // 手动加白面板缓存
  excluded: 'po0wl_excluded', // 面板手动排除的网络
  gen: 'po0wl_gen', // 网络事件去抖
  err: 'po0wl_last_err', // 自动加白的上一次错误（避免重复通知）
  bench: 'po0wl_bench', // 节点延迟测试结果快照
  auto: 'po0wl_auto', // 最近一次自动检查的摘要（不会被查询覆盖）
  ok: 'po0wl_ok', // 各 token 在哪个网络下确认过已加白
};
const PANEL_THROTTLE_MS = 20 * 1000; // 打开策略页触发的检查，最短间隔
const PANEL_CACHE_MS = 10 * 60 * 1000; // 打开策略页触发时，同一网络 10 分钟内确认过就不再请求服务器
const NOTIFY_TITLE = 'po0 防火墙';
const COLOR = { good: '#34C759', info: '#007AFF', alert: '#FF9500', error: '#FF3B30', idle: '#8E8E93' };
const MIN_CORE = 6009000; // 与模块 #!requirement 一致

/* ============================== 基础工具 ============================== */

const now = () => Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function log() {
  try { console.log('[po0加白] ' + Array.prototype.slice.call(arguments).join(' ')); } catch (e) {}
}
function readJSON(key, def) {
  try {
    const s = $persistentStore.read(key);
    return s ? JSON.parse(s) : def;
  } catch (e) { return def; }
}
function writeJSON(key, v) {
  try { $persistentStore.write(v == null ? null : JSON.stringify(v), key); } catch (e) {}
}
function fnv(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(16);
}
function pad(n) { return (n < 10 ? '0' : '') + n; }
function hhmm(t) { const d = new Date(t); return pad(d.getHours()) + ':' + pad(d.getMinutes()); }
function ago(t) {
  const s = Math.max(0, Math.round((now() - t) / 1000));
  if (s < 60) return '刚刚';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  return Math.floor(s / 3600) + ' 小时前';
}
function digits(s) { return String(s || '').replace(/\D/g, ''); }
function int(v, def, min, max) {
  const n = parseInt(v, 10);
  if (isNaN(n)) return def;
  return Math.min(max, Math.max(min, n));
}
function truthy(v, def) {
  if (v == null || v === '') return def;
  return /^(1|true|on|yes)$/i.test(String(v).trim());
}

/* ============================== 参数解析 ============================== */

function parseArgs(raw) {
  const out = {};
  if (raw && typeof raw === 'object') {
    for (const k in raw) out[k] = raw[k] == null ? '' : String(raw[k]);
    return out;
  }
  String(raw || '').split('&').forEach((seg) => {
    const i = seg.indexOf('=');
    if (i < 0) return;
    const k = seg.slice(0, i).trim();
    let v = seg.slice(i + 1).trim();
    if (/%[0-9A-Fa-f]{2}/.test(v)) { try { v = decodeURIComponent(v); } catch (e) {} }
    if (/^(""|'')$/.test(v) || /^\{\{\{.*\}\}\}$/.test(v)) v = '';
    else if (/^".*"$/.test(v)) v = v.slice(1, -1);
    out[k] = v;
  });
  return out;
}

// 节点关键词：a|b|c（不区分大小写的包含匹配），也可以写 /正则/flags
function makeMatcher(spec) {
  spec = String(spec || '').trim();
  if (!spec) return null;
  const re = spec.match(/^\/(.+)\/([a-z]*)$/i);
  if (re) {
    try {
      const r = new RegExp(re[1], re[2].replace(/g/g, ''));
      return { test: (s) => r.test(String(s || '')), text: spec };
    } catch (e) { /* 正则写错就当普通关键词 */ }
  }
  const parts = spec.split(/[|｜]/).map((s) => s.trim()).filter(Boolean);
  if (!parts.length) return null;
  const lower = parts.map((s) => s.toLowerCase());
  return {
    test: (s) => { s = String(s || '').toLowerCase(); return lower.some((p) => s.indexOf(p) >= 0); },
    text: parts.join('|'),
  };
}

// pgnfw_xxx[@槽位][:该 token 专用的节点关键词]，多个用逗号分隔
function parseTokens(raw) {
  const valid = [];
  const invalid = [];
  const seen = {};
  String(raw || '')
    .split(/[,，;；、\r\n]+|\s+(?=pgnfw_)/)
    .forEach((item) => {
      item = item.trim();
      if (!item) return;
      const m = item.match(/^(pgnfw_[A-Za-z0-9_-]+)(?:@(\d+))?(?:\s*[:：]\s*(.+))?$/);
      if (!m) { invalid.push(item); return; }
      const slot = m[2] == null ? null : parseInt(m[2], 10);
      const id = fnv(m[1] + '@' + (slot == null ? '' : slot));
      if (seen[id]) return;
      seen[id] = 1;
      valid.push({
        token: m[1],
        slot: slot,
        id: id,
        match: m[3] ? makeMatcher(m[3]) : null,
        tag: '#' + (valid.length + 1) + ' …' + m[1].slice(-4) + (slot == null ? '' : ' 📌' + slot),
      });
    });
  return { valid: valid.slice(0, 32), invalid: invalid };
}

function parseList(raw) {
  return String(raw || '')
    .split(/[|｜,，\r\n]+/)
    .map((s) => s.trim().replace(/^"(.*)"$/, '$1'))
    .filter(Boolean);
}

const A = parseArgs(typeof $argument !== 'undefined' ? $argument : '');
const CFG = {
  action: (A.action || 'auto').toLowerCase(),
  trigger: (A.trigger || '').toLowerCase(),
  timerUnit: (A.timer_unit || '').toLowerCase(),
  tokens: parseTokens(A.tokens),
  nodes: makeMatcher(A.nodes),
  exclude: parseList(A.exclude),
  fbEnabled: truthy(A.fallback_enabled, true),
  fbMinutes: int(A.fallback_minutes, 30, 0, 59),
  fbHours: int(A.fallback_hours, 0, 0, 23),
  windowMin: int(A.active_window, 15, 1, 1440),
  latencyTest: truthy(A.latency_test, false),
};

const SYS = String((typeof $environment !== 'undefined' && $environment && $environment.system) || '');
const LANG = String((typeof $environment !== 'undefined' && $environment && $environment.language) || '');
const IS_MAC = /mac/i.test(SYS);
const TRIGGER = typeof $trigger !== 'undefined' ? String($trigger || '') : '';
const TAPPED = TRIGGER === 'button' || TRIGGER === 'editor' || TRIGGER === 'intent';

function timerPlan() {
  if (!CFG.fbEnabled) return 'off';
  if (CFG.fbMinutes > 0) return 'minutes';
  if (CFG.fbHours > 0) return 'hours';
  return 'off';
}

/* ============================== 网络识别 ============================== */

function getNet() {
  const n = (typeof $network !== 'undefined' && $network) || {};
  const wifi = n.wifi || {};
  const v4 = n.v4 || {};
  const v6 = n.v6 || {};
  const cell = n['cellular-data'] || {};
  const iface = v4.primaryInterface || v6.primaryInterface || '';
  const ssid = wifi.ssid || '';
  const bssid = wifi.bssid || '';
  const router = v4.primaryRouter || '';
  const carrier = String(cell.carrier || '');
  const radio = String(cell.radio || '');

  let type;
  if (ssid || bssid) type = 'WIFI';
  else if (/^pdp_ip/i.test(iface)) type = 'CELLULAR';
  else if (!iface && !v4.primaryAddress && !v6.primaryAddress) type = 'NONE';
  else if (/^en\d/i.test(iface)) type = IS_MAC ? 'WIRED' : 'WIFI';
  else type = 'OTHER';

  let label, short, key;
  if (type === 'WIFI') {
    short = ssid || bssid || (router ? '网关 ' + router : '未知 Wi-Fi');
    label = ssid ? 'Wi-Fi「' + ssid + '」' : 'Wi-Fi ' + (bssid || (router ? '网关 ' + router : '（未获取到名称）'));
    key = ssid ? 'SSID:' + ssid : bssid ? 'BSSID:' + bssid : router ? 'ROUTER:' + router : null;
  } else if (type === 'CELLULAR') {
    short = '蜂窝网络';
    label = '蜂窝网络' + (radio ? ' · ' + radio : '');
    key = 'TYPE:CELLULAR';
  } else if (type === 'WIRED') {
    short = router ? '有线 ' + router : '有线网络';
    label = '有线网络' + (router ? ' · 网关 ' + router : '');
    key = router ? 'ROUTER:' + router : 'TYPE:WIRED';
  } else if (type === 'OTHER') {
    short = (iface || '其它') + (router ? ' ' + router : '');
    label = (iface || '其它网络') + (router ? ' · 网关 ' + router : '');
    key = router ? 'ROUTER:' + router : null;
  } else {
    short = label = '无网络';
    key = null;
  }
  return {
    type, ssid, bssid, router, carrier, radio, iface, label, short, key,
    fp: [type, ssid, bssid, router, v4.primaryAddress || '', carrier].join('|'),
  };
}

const CELL_ALIAS = /^(cellular|蜂窝|蜂窝网络|蜂窝数据|移动数据|流量)$/i;
const WIRED_ALIAS = /^(wired|有线|有线网络)$/i;

function wild(pat, val) {
  if (!pat || !val) return false;
  if (!/[*?]/.test(pat)) return pat.toLowerCase() === String(val).toLowerCase();
  const re = new RegExp(
    '^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$',
    'i'
  );
  return re.test(String(val));
}

// 子网表达式：SSID:/BSSID:/ROUTER:/TYPE:/MCCMNC:，或裸值（匹配 SSID/BSSID/网关）
function matchExpr(expr, net) {
  expr = String(expr || '').trim();
  if (!expr || net.type === 'NONE') return false;
  if (CELL_ALIAS.test(expr)) return net.type === 'CELLULAR';
  if (WIRED_ALIAS.test(expr)) return net.type === 'WIRED';
  const m = expr.match(/^(SSID|BSSID|ROUTER|TYPE|MCCMNC)\s*:\s*(.*)$/i);
  if (!m) return wild(expr, net.ssid) || wild(expr, net.bssid) || (!!net.router && expr === net.router);
  const v = m[2].trim();
  switch (m[1].toUpperCase()) {
    case 'SSID': return wild(v, net.ssid);
    case 'BSSID': return wild(v, net.bssid);
    case 'ROUTER': return !!net.router && v === net.router;
    case 'TYPE': return v.toUpperCase() === net.type;
    case 'MCCMNC': return net.type === 'CELLULAR' && !!digits(v) && digits(v) === digits(net.carrier);
  }
  return false;
}

/* ============================== Surge 本地 API ============================== */

function surgeAPI(method, path, body, timeoutMs) {
  return new Promise((resolve) => {
    if (typeof $httpAPI !== 'function') return resolve(null);
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; resolve(null); } }, timeoutMs || 5000);
    try {
      $httpAPI(method, path, body || {}, (res) => {
        if (done) return;
        done = true;
        clearTimeout(t);
        if (typeof res === 'string') { try { res = JSON.parse(res); } catch (e) {} }
        resolve(res == null ? {} : res);
      });
    } catch (e) {
      done = true;
      clearTimeout(t);
      resolve(null);
    }
  });
}

/* ---------- 读取配置：[SSID Setting] suspend=true、proxy-test-url ---------- */

// 行级条件：只认 SYSTEM / LANGUAGE / CORE_VERSION，其它返回 null（无法判断）
function evalCmp(c) {
  const m = c.match(/^([A-Z_]+)\s*(==|!=|<>|>=|=>|<=|=<|=|>|<|\s+BEGINSWITH\s+|\s+CONTAINS\s+|\s+ENDSWITH\s+)\s*(.+)$/i);
  if (!m) return null;
  const name = m[1].toUpperCase();
  const op = m[2].trim().toUpperCase();
  const val = m[3].trim().replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
  if (name === 'SYSTEM' || name === 'LANGUAGE') {
    const cur = (name === 'SYSTEM' ? SYS : LANG).toLowerCase();
    if (!cur) return null;
    const b = val.toLowerCase();
    if (op === '=' || op === '==') return cur === b;
    if (op === '!=' || op === '<>') return cur !== b;
    if (op === 'BEGINSWITH') return cur.indexOf(b) === 0;
    if (op === 'CONTAINS') return cur.indexOf(b) >= 0;
    if (op === 'ENDSWITH') return cur.slice(-b.length) === b;
    return null;
  }
  if (name === 'CORE_VERSION') {
    const n = Number(val);
    if (!isFinite(n)) return null;
    if ((op === '>=' || op === '=>') && n <= MIN_CORE) return true;
    if (op === '>' && n < MIN_CORE) return true;
    if (op === '<' && n <= MIN_CORE) return false;
    if ((op === '<=' || op === '=<') && n < MIN_CORE) return false;
  }
  return null;
}
function evalRequirement(expr) {
  expr = String(expr || '').trim().replace(/^"(.*)"$/, '$1');
  if (!expr || /[()]/.test(expr)) return null;
  let unknown = false;
  const ors = expr.split(/\s+OR\s+|\s*\|\|\s*/i);
  for (let i = 0; i < ors.length; i++) {
    let all = true;
    let nul = false;
    const ands = ors[i].split(/\s+AND\s+|\s*&&\s*/i);
    for (let j = 0; j < ands.length; j++) {
      let c = ands[j].trim();
      let neg = false;
      const nm = c.match(/^(?:NOT\s+|!(?!=))(.*)$/i);
      if (nm) { neg = true; c = nm[1].trim(); }
      let v = evalCmp(c);
      if (v === null) { nul = true; continue; }
      if (neg) v = !v;
      if (!v) { all = false; break; }
    }
    if (all && !nul) return true;
    if (all && nul) unknown = true;
  }
  return unknown ? null : false;
}
function andCond(a, b) {
  if (a === false || b === false) return false;
  if (a === null || b === null) return null;
  return true;
}

function stripComment(s) {
  let q = false;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"' && s[i - 1] !== '\\') q = !q;
    if (!q && (i === 0 || /\s/.test(s[i - 1]))) {
      if (c === '#' || c === ';' || (c === '/' && s[i + 1] === '/')) break;
    }
    out += c;
  }
  return out.trim();
}

function parseSsidSetting(text, alreadyInSection) {
  const rules = [];
  if (!text) return rules;
  let inSec = !!alreadyInSection;
  String(text).split(/\r?\n/).forEach((raw) => {
    let line = raw.trim();
    const h = line.match(/^\[(.+)\]$/);
    if (h) { inSec = /^ssid\s+setting$/i.test(h[1].trim()); return; }
    if (!inSec || !line) return;

    let cond = true;
    let pm;
    while ((pm = line.match(/^#!(IOS-ONLY|MACOS-ONLY|MAC-ONLY|TVOS-ONLY)\s+(.*)$/i))) {
      const want = pm[1].toUpperCase();
      let ok;
      if (!SYS) ok = null;
      else if (want === 'IOS-ONLY') ok = /^ios$/i.test(SYS);
      else if (want === 'TVOS-ONLY') ok = /tvos/i.test(SYS);
      else ok = /mac/i.test(SYS);
      cond = andCond(cond, ok);
      line = pm[2].trim();
    }
    const rq = line.match(/^#!REQUIREMENT\s+(?:"([^"]*)"|(\S+))\s+(.*)$/i);
    if (rq) {
      cond = andCond(cond, evalRequirement(rq[1] != null ? rq[1] : rq[2]));
      line = rq[3].trim();
    }
    const sf = line.match(/^(.*?)\s*\/\/!REQUIREMENT\s+(.+)$/i);
    if (sf) {
      cond = andCond(cond, evalRequirement(sf[2]));
      line = sf[1].trim();
    }
    line = stripComment(line);
    if (!line) return;
    const m = line.match(/^(.*?)\s+([A-Za-z][\w-]*\s*=.*)$/);
    if (!m) return;
    let expr = m[1].trim();
    if (/^".*"$/.test(expr)) { try { expr = JSON.parse(expr); } catch (e) { expr = expr.slice(1, -1); } }
    const sm = m[2].match(/(?:^|[,\s])suspend\s*=\s*(true|false|1|0)\b/i);
    if (sm) rules.push({ expr: expr, suspend: /^(true|1)$/i.test(sm[1]), cond: cond });
  });
  return rules;
}

let PROFILE = null;
async function loadProfile() {
  if (PROFILE) return PROFILE;
  const res = await Promise.all([
    surgeAPI('GET', '/v1/profiles/current', { sensitive: 0 }, 5000),
    surgeAPI('GET', '/v1/profiles/section', { name: 'SSID Setting' }, 5000),
  ]);
  const cur = res[0];
  const sec = res[1];
  const p = { ok: false, rules: [], testUrls: [] };
  const texts = [];
  if (cur && typeof cur.profile === 'string') {
    p.ok = true;
    texts.push(cur.profile);
    if (typeof cur.originalProfile === 'string' && cur.originalProfile !== cur.profile) texts.push(cur.originalProfile);
  }
  texts.forEach((t) => {
    p.rules = p.rules.concat(parseSsidSetting(t, false));
    const m = t.match(/^\s*proxy-test-url\s*=\s*(\S+)/im);
    if (m) p.testUrls.push(m[1]);
  });
  if (sec && typeof sec === 'object') {
    p.ok = true; // 有响应即可，没有这个段落也算读取成功
    if (sec.content != null) {
      const c = Array.isArray(sec.content) ? sec.content.join('\n') : String(sec.content);
      p.rules = p.rules.concat(parseSsidSetting(c, !/^\s*\[/.test(c)));
    }
  }
  PROFILE = p;
  return p;
}

/* ---------- 排除判断 ---------- */

async function exclusionOf(net) {
  const r = { panel: null, arg: null, ssid: null, ssidUncertain: false, profileOk: true };
  if (net.type === 'NONE') return r;
  const d = readJSON(K.excluded, []).find((e) => matchExpr(e.expr, net));
  if (d) r.panel = d.label || d.expr;
  const a = CFG.exclude.find((e) => matchExpr(e, net));
  if (a) r.arg = a;
  const p = await loadProfile();
  r.profileOk = p.ok;
  const hits = p.rules.filter((x) => x.suspend && x.cond !== false && matchExpr(x.expr, net));
  const sure = hits.find((x) => x.cond === true);
  if (sure) r.ssid = sure.expr;
  else if (hits.length) { r.ssid = hits[0].expr; r.ssidUncertain = true; } // 条件判断不了，保守按挂起处理
  return r;
}
function isExcluded(ex) { return !!(ex && (ex.panel || ex.arg || ex.ssid)); }
function exclusionText(ex) {
  if (!ex) return '';
  if (ex.panel) return '已在排除面板中排除';
  if (ex.arg) return 'exclude 参数：' + ex.arg;
  if (ex.ssid) return 'SSID Setting 挂起' + (ex.ssidUncertain ? '（条件无法判断，保守跳过）' : '');
  return '';
}

/* ---------- 节点使用检测 ---------- */

function toMs(v) {
  if (v == null || v === '') return 0;
  if (typeof v === 'string' && !/^\d+(\.\d+)?$/.test(v)) {
    const t = Date.parse(v);
    return isNaN(t) ? 0 : t;
  }
  const n = Number(v);
  if (!isFinite(n) || n <= 0) return 0;
  if (n > 1e12) return n; // 毫秒
  if (n > 1e9) return n * 1000; // Unix 秒
  return (n + 978307200) * 1000; // 以 2001-01-01 为基准的秒
}

function getDecisions() {
  try {
    if (typeof $surge !== 'undefined' && $surge && typeof $surge.selectGroupDetails === 'function') {
      const d = $surge.selectGroupDetails();
      return (d && d.decisions) || {};
    }
  } catch (e) {}
  return {};
}

const TEST_URL_RE = [/\/generate_204\b/i, /\/library\/test\/success\.html/i];
function isTestRequest(r, testUrls) {
  const u = String(r.URL || r.url || '');
  if (!u) return false;
  if (TEST_URL_RE.some((re) => re.test(u))) return true;
  return testUrls.some((t) => {
    const s = String(t).replace(/^https?:\/\//i, '');
    return s && u.replace(/^https?:\/\//i, '').indexOf(s) === 0;
  });
}

// 延迟测试：Surge 只保存每个节点最近一次的测试结果，没有公开的测试时间，
// 所以用「结果和上次检查时不同」判断最近测过延迟；若结果里带时间字段则直接用时间。
async function detectLatencyTests() {
  const res = await Promise.all([
    surgeAPI('GET', '/v1/policy_groups', {}, 5000),
    surgeAPI('GET', '/v1/policies', {}, 5000),
    surgeAPI('GET', '/v1/policies/benchmark_results', {}, 5000),
  ]);
  const bench = res[2];
  if (!bench || typeof bench !== 'object') return null;

  const hashByName = {};
  const walk = (o, depth) => {
    if (!o || typeof o !== 'object' || depth > 6) return;
    if (Array.isArray(o)) { o.forEach((x) => walk(x, depth + 1)); return; }
    const nm = o.name || o.policyName;
    const h = o.lineHash || o.identifier;
    if (typeof nm === 'string' && h) hashByName[nm] = String(h);
    for (const k in o) if (o[k] && typeof o[k] === 'object') walk(o[k], depth + 1);
  };
  walk(res[0], 0);
  walk(res[1], 0);

  let entries = bench;
  if (Array.isArray(bench)) {
    entries = {};
    bench.forEach((e) => { if (e) entries[e.lineHash || e.identifier || e.name] = e; });
  } else if (bench.results && typeof bench.results === 'object') {
    entries = bench.results;
  }

  const t = now();
  const store = readJSON(K.bench, {});
  const out = [];
  Object.keys(hashByName).forEach((name) => {
    const h = hashByName[name];
    const b = entries[h] || entries[name];
    if (!b || typeof b !== 'object') return;
    const tsField = b.lastTestDate || b.lastTestTime || b.lastTestedAt || b.testDate || b.date || b.time;
    const sig = JSON.stringify([b.lastTestScoreInMS, b.lastTestErrorMessage, tsField || null]);
    const prev = store[h];
    let changedAt = 0;
    if (prev) changedAt = prev.sig !== sig ? t : prev.changedAt || 0;
    store[h] = { sig: sig, changedAt: changedAt };
    const ts = toMs(tsField) || changedAt;
    if (ts) out.push({ name: name, ts: ts, test: true });
  });
  writeJSON(K.bench, store);
  return out;
}

async function detectNodes() {
  const decisions = getDecisions();
  const chainOf = (name) => {
    const out = [];
    const seen = {};
    let cur = name;
    while (cur && !seen[cur] && out.length < 16) { seen[cur] = 1; out.push(cur); cur = decisions[cur]; }
    return out;
  };
  const prof = await loadProfile();
  const det = { traffic: null, tests: null, selected: null };
  const cutoff = now() - CFG.windowMin * 60000;

  const data = await surgeAPI('GET', '/v1/requests/recent', {}, 6000);
  const reqs = data && (Array.isArray(data) ? data : data.requests || data.items);
  if (Array.isArray(reqs)) {
    const used = {};
    reqs.forEach((r) => {
      if (!r || typeof r !== 'object') return;
      if (!CFG.latencyTest && isTestRequest(r, prof.testUrls)) return; // 只看真实连接
      const ts = toMs(r.startDate || r.completedDate);
      if (ts && ts < cutoff) return;
      const names = [];
      [r.policyName, r.policy, r.originalPolicyName].forEach((n) => {
        if (typeof n === 'string' && n) chainOf(n).forEach((x) => names.push(x));
      });
      const notes = Array.isArray(r.notes) ? r.notes : typeof r.notes === 'string' ? r.notes.split('\n') : [];
      notes.forEach((line) => {
        if (typeof line !== 'string' || !/(policy|策略)/i.test(line) || !/(->|→)/.test(line)) return;
        line.split(/->|→/).forEach((p, i) => {
          p = p.trim();
          if (i === 0) p = p.replace(/^.*[:：]\s*/, '');
          if (p) names.push(p);
        });
      });
      const t = ts || 0; // 0 = 时间未知（仍算在用，但面板显示「最近」而不是「刚刚」）
      names.forEach((n) => { if (!(n in used) || used[n] < t) used[n] = t; });
    });
    det.traffic = Object.keys(used).map((n) => ({ name: n, ts: used[n] }));
  }

  if (CFG.latencyTest) {
    const tests = await detectLatencyTests();
    if (tests) det.tests = tests.filter((x) => x.ts >= cutoff);
  }

  if (!det.traffic) {
    const groups = Object.keys(decisions);
    if (groups.length) {
      const set = {};
      groups.forEach((g) => chainOf(g).slice(1).forEach((n) => { set[n] = 1; }));
      det.selected = Object.keys(set);
    }
  }
  return det;
}

// 返回 null = 没在用；否则 {via: 'conn'|'test'|'selected'|'unknown', name, ts}
function hitFor(m, det) {
  const best = (list, via) => {
    const hits = (list || []).filter((e) => m.test(e.name)).sort((a, b) => b.ts - a.ts);
    return hits.length ? { via: via, name: hits[0].name, ts: hits[0].ts } : null;
  };
  const conn = best(det.traffic, 'conn');
  if (conn) return conn;
  const test = best(det.tests, 'test');
  if (test) return test;
  if (det.traffic) return null;
  if (det.selected) { // 读不到请求记录时，退回看策略组当前选中
    const n = det.selected.find((x) => m.test(x));
    return n ? { via: 'selected', name: n } : null;
  }
  return { via: 'unknown', name: '' };
}

/* ============================== po0 API ============================== */

function rawHttp(method, url) {
  return new Promise((resolve) => {
    const opts = {
      url: url,
      policy: 'DIRECT',
      timeout: 10,
      'auto-redirect': false,
      headers: { 'Cache-Control': 'no-cache' },
    };
    if (method === 'POST') {
      opts.body = '';
      opts.headers['Content-Type'] = 'application/json';
    }
    const cb = (err, resp, data) => resolve({
      err: err,
      status: resp ? Number(resp.status || resp.statusCode || 0) : 0,
      data: data,
    });
    try {
      if (method === 'POST') $httpClient.post(opts, cb);
      else $httpClient.get(opts, cb);
    } catch (e) { resolve({ err: String(e), status: 0, data: null }); }
  });
}

function parseIp(s) {
  const m = String(s || '').replace(/\\\//g, '/').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d+))?$/);
  if (!m) return null;
  return { three: m[1] + '.' + m[2] + '.' + m[3], full: m[1] + '.' + m[2] + '.' + m[3] + '.' + m[4], cidr: m[6] || '' };
}
function sameNet(a, b) {
  const x = parseIp(a);
  const y = parseIp(b);
  if (!x || !y) return false;
  if (x.cidr === '24' || y.cidr === '24') return x.three === y.three;
  return x.full === y.full;
}
function showIp(s) {
  const x = parseIp(s);
  if (!x) return '';
  return x.cidr ? x.full + '/' + x.cidr : x.full;
}

function normalize(r) {
  if (r.err) return { error: '网络错误：' + String(r.err).slice(0, 60) };
  let j = null;
  try { j = typeof r.data === 'string' ? JSON.parse(r.data) : r.data; } catch (e) {}
  const msg = j && (j.message || j.msg || j.error);
  if (r.status === 401 || r.status === 403 || r.status === 404) {
    return { error: 'token 无效或无权限（HTTP ' + r.status + '）' + (msg ? '：' + msg : '') };
  }
  if (r.status >= 400) return { error: 'HTTP ' + r.status + (msg ? '：' + msg : '') };
  if (!j || typeof j !== 'object') return { error: '响应不是 JSON（HTTP ' + r.status + '）' };
  if (typeof j.code === 'number' && j.code >= 400) return { error: msg || 'code ' + j.code };
  if (!Array.isArray(j.whitelist)) return { error: msg || '响应缺少 whitelist 字段' };
  return {
    wl: j.whitelist.map((e) =>
      typeof e === 'string' ? { ip: e, slot: null } : { ip: e && e.ip, slot: e && e.slot != null ? Number(e.slot) : null }
    ),
    enabled: j.enabled,
    currentIp: j.currentIp || null,
    limit: j.limit != null ? j.limit : null,
  };
}

async function callApi(method, url) {
  let r;
  for (let i = 1; i <= 3; i++) {
    r = await rawHttp(method, url);
    const retry = !!r.err || r.status >= 500 || (r.status === 400 && !r.data);
    if (!retry) break;
    if (i < 3) await sleep(1500 * i);
  }
  return normalize(r);
}

function inList(res, slot) {
  if (!res || !res.wl || !res.currentIp) return false;
  return res.wl.some((e) => sameNet(e.ip, res.currentIp) && (slot == null || e.slot === slot));
}
function remote(res) {
  return {
    ip: showIp(res.currentIp),
    count: res.wl ? res.wl.length : null,
    limit: res.limit,
    entries: res.wl ? res.wl.map((e) => ({ ip: showIp(e.ip) || String(e.ip || ''), slot: e.slot })) : null,
    remoteAt: now(),
  };
}

// 只读查询
async function queryToken(tok) {
  const st = await callApi('GET', API + encodeURIComponent(tok.token));
  if (st.error) return { status: 'error', msg: st.error };
  const r = remote(st);
  r.inList = inList(st, tok.slot);
  r.status = st.enabled === false ? 'disabled' : r.inList ? 'ok' : 'notin';
  return r;
}

// 先查后加
async function ensureToken(tok) {
  const url = API + encodeURIComponent(tok.token);
  const st = await callApi('GET', url);
  if (st.error) return { status: 'error', msg: st.error };
  if (st.enabled === false) return Object.assign(remote(st), { status: 'disabled' });
  if (inList(st, tok.slot)) return Object.assign(remote(st), { status: 'ok', inList: true });

  const ad = await callApi('POST', url + '/add' + (tok.slot == null ? '' : '?slot=' + tok.slot));
  if (ad.error) return Object.assign(remote(st), { status: 'error', msg: ad.error, inList: false });
  if (inList(ad, tok.slot)) return Object.assign(remote(ad), { status: 'added', inList: true });

  const st2 = await callApi('GET', url);
  if (!st2.error && inList(st2, tok.slot)) return Object.assign(remote(st2), { status: 'added', inList: true });
  return Object.assign(remote(ad), { status: 'error', msg: '已提交，但未能在白名单中确认', inList: false });
}

/* ============================== 快照 ============================== */

function newSnap(net, source) {
  return {
    at: now(),
    source: source,
    net: { label: net.label, type: net.type, fp: net.fp },
    excluded: '',
    note: '',
    node: null,
    tokens: [],
  };
}

// 没有新查询结果的 token，沿用同一网络下上次查到的白名单信息
function saveSnap(key, snap) {
  const prev = readJSON(key, null);
  if (prev && prev.net && prev.net.fp === snap.net.fp && Array.isArray(prev.tokens)) {
    snap.tokens.forEach((t) => {
      if (t.remoteAt) return;
      const p = prev.tokens.find((x) => x.id === t.id && x.remoteAt);
      if (p) ['ip', 'count', 'limit', 'entries', 'inList', 'remoteAt'].forEach((k) => { t[k] = p[k]; });
    });
  }
  writeJSON(key, snap);
  return snap;
}

function firstNode(tokens) {
  const hits = tokens.map((t) => t.node).filter(Boolean);
  return hits.find((h) => h.via !== 'unknown') || hits[0] || null;
}

/* ============================== 三种动作 ============================== */

// 一次自动检查的结果，写进状态面板缓存，并单独留一份摘要（不会被「查询」覆盖）
function autoSummary(snap) {
  if (snap.note) return snap.note.replace(/^⚠️\s*/, '');
  if (snap.excluded) return '本网络已排除，未加白';
  const t = snap.tokens;
  const ip = ipOf(snap);
  const err = t.find((x) => x.status === 'error');
  if (err) return '加白失败：' + err.msg;
  if (t.some((x) => x.status === 'added')) return '已自动加白 ' + ip;
  if (t.some((x) => x.status === 'ok' || x.status === 'cached')) return '已在白名单' + (ip ? ' ' + ip : '');
  if (t.some((x) => x.status === 'disabled')) return '防火墙未开启';
  if (t.length && t.every((x) => x.status === 'idle')) return '没有节点连接，未加白';
  return '完成';
}
function finishAuto(snap) {
  writeJSON(K.auto, { at: snap.at, reason: snap.reason, text: autoSummary(snap) });
  return saveSnap(K.snap, snap);
}
function rememberOk(snap, net) {
  const ok = readJSON(K.ok, {});
  snap.tokens.forEach((t) => {
    if (t.status === 'ok' || t.status === 'added') ok[t.id] = { fp: net.fp, at: now() };
    else if (t.status === 'notin' || t.status === 'error') delete ok[t.id];
  });
  writeJSON(K.ok, ok);
}

// 自动：网络变化 / 启动 / 定时 / 打开策略页
// opt.panel = true 表示由面板自动刷新触发：有节流，并且同一网络 10 分钟内确认过的 token 不再请求服务器
async function runAuto(reason, opt) {
  opt = opt || {};
  const last = readJSON(K.auto, null);
  if (opt.panel && last && now() - last.at < PANEL_THROTTLE_MS) return null;

  const net = getNet();
  const snap = newSnap(net, '自动检查 · ' + reason);
  snap.reason = reason;
  if (!CFG.tokens.valid.length) {
    snap.note = CFG.tokens.invalid.length ? '⚠️ token 格式不对：' + CFG.tokens.invalid[0].slice(0, 24) : '⚠️ 还没填写 tokens';
    return finishAuto(snap);
  }
  if (net.type === 'NONE') { snap.note = '无网络，跳过'; return finishAuto(snap); }

  const ex = await exclusionOf(net);
  if (isExcluded(ex)) {
    snap.excluded = exclusionText(ex);
    snap.tokens = CFG.tokens.valid.map((t) => ({ id: t.id, tag: t.tag, status: 'excluded' }));
    log('当前网络不加白：', net.label, snap.excluded);
    return finishAuto(snap);
  }
  if (!ex.profileOk) {
    snap.note = '⚠️ 读不到配置里的 SSID Setting，本次不自动加白';
    return finishAuto(snap);
  }
  if (!CFG.nodes && !CFG.tokens.valid.some((t) => t.match)) {
    snap.note = '⚠️ 还没填写 nodes（节点关键词），自动加白未启用';
    return finishAuto(snap);
  }

  const det = await detectNodes();
  const okCache = readJSON(K.ok, {});
  snap.tokens = await Promise.all(
    CFG.tokens.valid.map(async (tok) => {
      const m = tok.match || CFG.nodes;
      if (!m) return { id: tok.id, tag: tok.tag, status: 'nokw' };
      const hit = hitFor(m, det);
      if (!hit) return { id: tok.id, tag: tok.tag, status: 'idle', kw: m.text };
      const c = okCache[tok.id];
      if (opt.panel && c && c.fp === net.fp && now() - c.at < PANEL_CACHE_MS) {
        return { id: tok.id, tag: tok.tag, status: 'cached', okAt: c.at, node: hit };
      }
      const r = await ensureToken(tok);
      return Object.assign(r, { id: tok.id, tag: tok.tag, node: hit });
    })
  );
  snap.node = firstNode(snap.tokens);
  snap.tokens.forEach((t) => log(t.tag, t.status, t.msg || '', t.ip || '', t.node ? t.node.name : ''));
  rememberOk(snap, net);
  notifyAuto(snap);
  return finishAuto(snap);
}

// 「po0 状态 · 只读」：只查询，不加白
async function runStatus() {
  const net = getNet();
  const snap = newSnap(net, '查询');
  if (!CFG.tokens.valid.length) {
    snap.note = CFG.tokens.invalid.length ? '⚠️ token 格式不对：' + CFG.tokens.invalid[0].slice(0, 24) : '⚠️ 还没填写 tokens';
    return saveSnap(K.snap, snap);
  }
  const both = await Promise.all([exclusionOf(net), detectNodes()]);
  const ex = both[0];
  const det = both[1];
  if (isExcluded(ex)) snap.excluded = exclusionText(ex);
  if (!CFG.nodes && !CFG.tokens.valid.some((t) => t.match)) snap.note = '⚠️ 还没填写 nodes，自动加白未启用';
  snap.tokens = await Promise.all(
    CFG.tokens.valid.map(async (tok) => {
      const r = await queryToken(tok);
      const m = tok.match || CFG.nodes;
      return Object.assign(r, { id: tok.id, tag: tok.tag, node: m ? hitFor(m, det) : null, kw: m ? m.text : '' });
    })
  );
  snap.node = firstNode(snap.tokens);
  rememberOk(snap, net);
  return saveSnap(K.snap, snap);
}

// 「po0 手动加白」：不看节点，但遵守排除
async function runManualAdd() {
  const net = getNet();
  const snap = newSnap(net, '手动加白');
  if (!CFG.tokens.valid.length) {
    snap.note = CFG.tokens.invalid.length ? '⚠️ token 格式不对：' + CFG.tokens.invalid[0].slice(0, 24) : '⚠️ 还没填写 tokens';
    return snap;
  }
  const ex = await exclusionOf(net);
  if (isExcluded(ex)) {
    snap.excluded = exclusionText(ex);
    snap.note = '当前网络已排除，未加白。需要的话先在「po0 排除当前网络」面板恢复';
    snap.tokens = CFG.tokens.valid.map((t) => ({ id: t.id, tag: t.tag, status: 'excluded' }));
  } else {
    snap.tokens = await Promise.all(
      CFG.tokens.valid.map(async (tok) => Object.assign(await ensureToken(tok), { id: tok.id, tag: tok.tag }))
    );
    rememberOk(snap, net);
  }
  writeJSON(K.add, snap);
  saveSnap(K.snap, JSON.parse(JSON.stringify(snap)));
  notifyManual(snap);
  return snap;
}

/* ============================== 通知 ============================== */

function ipOf(snap) { return (snap.tokens.find((t) => t.ip) || {}).ip || ''; }

function notifyAuto(st) {
  if (typeof $notification === 'undefined') return;
  const added = st.tokens.filter((t) => t.status === 'added');
  const errs = st.tokens.filter((t) => t.status === 'error');
  if (added.length) {
    const n = firstNode(added);
    $notification.post(
      NOTIFY_TITLE,
      '✅ 已自动加白 ' + (ipOf(st) || '当前 IP'),
      [st.net.label, n && n.name ? '节点：' + n.name + (n.via === 'test' ? '（测过延迟）' : '') : '', added.map((t) => t.tag).join('  ')]
        .filter(Boolean).join('\n')
    );
  }
  if (errs.length) {
    const sig = errs.map((e) => e.tag + e.msg).join('|');
    if (sig !== $persistentStore.read(K.err)) {
      $notification.post(NOTIFY_TITLE, '❌ 自动加白失败', [st.net.label].concat(errs.map((e) => e.tag + '：' + e.msg)).join('\n'));
    }
    $persistentStore.write(sig, K.err);
  } else if (added.length || st.tokens.some((t) => t.status === 'ok')) {
    $persistentStore.write(null, K.err);
  }
}

function notifyManual(st) {
  if (typeof $notification === 'undefined') return;
  if (st.excluded || st.note) { $notification.post(NOTIFY_TITLE, '手动加白：已跳过', st.note || st.excluded); return; }
  const errs = st.tokens.filter((t) => t.status === 'error');
  $notification.post(
    NOTIFY_TITLE,
    errs.length ? '❌ 手动加白失败' : '✅ 手动加白完成 ' + ipOf(st),
    [st.net.label].concat(st.tokens.map((t) => t.tag + '  ' + statusText(t))).join('\n')
  );
}

/* ============================== 面板渲染 ============================== */

function statusText(t) {
  const cnt = t.count != null ? ' ' + t.count + '/' + (t.limit || '?') : '';
  switch (t.status) {
    case 'ok': return '✅ 已在白名单' + cnt;
    case 'added': return '➕ 已加入白名单' + cnt;
    case 'cached': return '✅ 已在白名单（' + ago(t.okAt) + '确认）';
    case 'notin': return '⚠️ 当前 IP 不在白名单' + cnt;
    case 'disabled': return '⚪ 防火墙未开启';
    case 'error': return '❌ ' + t.msg;
    case 'excluded': return '🚫 本网络不加白';
    case 'nokw': return '⚠️ 未设节点关键词';
    case 'idle': return '⏸ 未连接节点，未加白' + (t.remoteAt ? (t.inList ? '（IP 已在名单）' : '（IP 不在名单）') : '');
    default: return t.status || '';
  }
}

function nodeLine(snap) {
  const n = snap.node;
  const kw = CFG.nodes ? CFG.nodes.text : '';
  if (!n) return '节点：' + CFG.windowMin + ' 分钟内无 ' + (kw || '指定节点') + ' 的连接';
  if (n.via === 'unknown') return '节点：读不到请求记录，按「在用」处理';
  if (n.via === 'selected') return '节点：' + n.name + ' · 策略组当前选中';
  return '节点：' + n.name + ' · ' + (n.ts ? ago(n.ts) : '最近') + (n.via === 'test' ? '测过延迟' : '有连接');
}

function entriesLine(t) {
  if (!t.entries || !t.entries.length) return '';
  const list = t.entries.slice(0, 5).map((e) => e.ip + (e.slot != null ? ' 📌' + e.slot : ''));
  return '   ' + list.join(' · ') + (t.entries.length > 5 ? ' …' : '');
}

function renderSnap(snap, title, hint, withEntries, extra) {
  extra = (extra || []).filter(Boolean);
  if (!snap) {
    return { title: title, content: extra.concat([hint]).join('\n'), icon: 'checkmark.shield', 'icon-color': COLOR.info };
  }
  const ip = ipOf(snap);
  const L = [snap.net.label + (ip ? ' · ' + ip : '')];
  let tone = 'info';
  let icon = 'checkmark.shield';

  if (snap.excluded) { L.push('🚫 本网络不自动加白（' + snap.excluded + '）'); tone = 'idle'; icon = 'shield.slash'; }
  if (snap.note) L.push(snap.note);
  const showTokens = snap.tokens.length && !(snap.excluded && snap.tokens.every((t) => t.status === 'excluded'));
  if (showTokens) {
    if (snap.source !== '手动加白' && (CFG.nodes || snap.node)) L.push(nodeLine(snap));
    snap.tokens.forEach((t) => {
      L.push(t.tag + '  ' + statusText(t));
      if (withEntries) { const e = entriesLine(t); if (e) L.push(e); }
      if (t.status === 'notin' && t.node && t.node.via !== 'unknown' && !snap.excluded) {
        L.push('   ↳ 已连接但不在白名单，下次自动检查会加白');
      }
    });
    const s = snap.tokens.map((t) => t.status);
    if (s.indexOf('error') >= 0) { tone = 'error'; icon = 'exclamationmark.shield'; }
    else if (s.indexOf('notin') >= 0) { tone = 'alert'; icon = 'exclamationmark.shield'; }
    else if (s.some((x) => x === 'ok' || x === 'added' || x === 'cached')) { tone = 'good'; icon = 'checkmark.shield'; }
    else if (s.every((x) => x === 'idle')) { tone = 'idle'; icon = 'shield'; }
  } else if (snap.note && snap.note.indexOf('⚠️') === 0) {
    tone = 'alert';
    icon = 'exclamationmark.shield';
  }
  extra.forEach((x) => L.push(x));
  L.push(hhmm(snap.at) + ' ' + snap.source + ' · ' + hint);
  return { title: title, content: L.join('\n'), icon: icon, 'icon-color': COLOR[tone] };
}

// 下一次定时器触发的时间（与 cron 表达式一致：*/N 分钟，或 0 */N 小时）
function nextTimerAt() {
  const plan = timerPlan();
  if (plan === 'off') return 0;
  const base = new Date();
  base.setSeconds(0, 0);
  if (plan === 'minutes') {
    for (let i = 1; i <= 61; i++) {
      const t = new Date(base.getTime() + i * 60000);
      if (t.getMinutes() % CFG.fbMinutes === 0) return t.getTime();
    }
  } else {
    base.setMinutes(0);
    for (let i = 1; i <= 25; i++) {
      const t = new Date(base.getTime() + i * 3600000);
      if (t.getHours() % CFG.fbHours === 0) return t.getTime();
    }
  }
  return 0;
}

// 状态面板额外显示：上次自动检查做了什么、下次什么时候检查
function autoLines(snap) {
  const L = [];
  const a = readJSON(K.auto, null);
  if (a && !(snap && /^自动检查/.test(snap.source || '') && snap.at === a.at)) {
    L.push('自动：' + hhmm(a.at) + ' ' + a.reason + ' → ' + a.text);
  }
  const next = nextTimerAt();
  L.push((next ? '下次定时 ' + hhmm(next) : '定时已关闭') + ' · 打开策略页时也会检查');
  return L;
}

async function renderExcludePanel(tapped) {
  // 面板自动刷新（iOS 切到策略页时）顺带做一次自动检查：
  // 在同一网络里中途连上节点，不用等定时器
  if (!tapped) await runAuto('打开策略页', { panel: true });
  const net = getNet();
  let dyn = readJSON(K.excluded, []);
  let msg = '';
  let ex = await exclusionOf(net);

  if (tapped) {
    if (!net.key) {
      msg = '⚠️ 识别不到当前网络，无法排除';
    } else if (ex.panel) {
      const removed = dyn.filter((e) => matchExpr(e.expr, net));
      dyn = dyn.filter((e) => !matchExpr(e.expr, net));
      writeJSON(K.excluded, dyn);
      msg = '已恢复自动加白：' + removed.map((e) => e.label || e.expr).join('、');
      ex = await exclusionOf(net);
      if (!isExcluded(ex) && CFG.tokens.valid.length) {
        const st = await runAuto('恢复本网络');
        const t = st.tokens[0];
        if (st.note) msg += '\n' + st.note;
        else if (t) msg += '\n立即检查：' + statusText(t);
      }
    } else if (ex.arg || ex.ssid) {
      msg = '该网络已由' + (ex.arg ? ' exclude 参数' : ' [SSID Setting]') + '排除，需要在那里修改';
    } else {
      dyn.push({ expr: net.key, label: net.short, at: now() });
      writeJSON(K.excluded, dyn);
      msg = '已排除：' + net.short + '（以后在这个网络不自动加白）';
      ex = await exclusionOf(net);
    }
  }

  const excluded = isExcluded(ex);
  const L = [net.label];
  L.push(excluded ? '🚫 不自动加白 · ' + exclusionText(ex) : '✅ 连接 po0 节点时会自动加白');
  if (msg) L.push(msg);
  const a = readJSON(K.auto, null);
  if (a && !tapped) L.push('自动检查 ' + hhmm(a.at) + '：' + a.text);
  if (dyn.length) {
    const names = dyn.map((e) => e.label || e.expr);
    L.push('面板已排除：' + names.slice(0, 4).join('、') + (names.length > 4 ? ' 等 ' + names.length + ' 个' : ''));
  }
  if (net.key && ex.panel) L.push('点击刷新：恢复本网络的自动加白');
  else if (net.key && !excluded) L.push('点击刷新：排除本网络');

  let icon;
  if (net.type === 'CELLULAR') icon = excluded ? 'antenna.radiowaves.left.and.right.slash' : 'antenna.radiowaves.left.and.right';
  else if (net.type === 'WIFI') icon = excluded ? 'wifi.slash' : 'wifi';
  else icon = excluded ? 'nosign' : 'network';

  return {
    title: 'po0 排除当前网络',
    content: L.join('\n'),
    icon: icon,
    'icon-color': excluded ? COLOR.idle : COLOR.good,
  };
}

/* ============================== 入口 ============================== */

const REASON = { network: '网络变化', start: 'Surge 启动', minutes: '定时（分钟）', hours: '定时（小时）' };

async function main() {
  switch (CFG.action) {
    case 'status': {
      const snap = TAPPED ? await runStatus() : readJSON(K.snap, null);
      return renderSnap(snap, 'po0 状态 · 只读', '点击刷新查询状态与槽位，不加白', true, autoLines(snap));
    }

    case 'add':
      return renderSnap(TAPPED ? await runManualAdd() : readJSON(K.add, null), 'po0 手动加白', '点击刷新执行加白', false);

    case 'exclude':
      return await renderExcludePanel(TRIGGER === 'button');

    case 'clear':
      writeJSON(K.excluded, []);
      if (typeof $notification !== 'undefined') $notification.post(NOTIFY_TITLE, '已清空「排除当前网络」面板里的排除列表', '');
      return null;

    case 'auto': {
      // 定时器：与原版一致，分钟优先，分钟为 0 用小时，开关为 0 关闭
      if (CFG.timerUnit && CFG.timerUnit !== timerPlan()) return null;
      const reason = CFG.timerUnit ? REASON[CFG.timerUnit] : REASON[CFG.trigger] || '自动';
      if (CFG.trigger === 'network' || CFG.trigger === 'start') {
        const gen = now() + '-' + Math.random().toString(36).slice(2, 8);
        $persistentStore.write(gen, K.gen);
        await sleep(CFG.trigger === 'network' ? 2500 : 1500);
        if ($persistentStore.read(K.gen) !== gen) { log('有更新的网络事件，本次跳过'); return null; }
      }
      await runAuto(reason);
      return null;
    }
  }
  return null;
}

main()
  .then((out) => $done(out || {}))
  .catch((e) => {
    log('异常：', e && (e.stack || e));
    if (CFG.action === 'status' || CFG.action === 'add' || CFG.action === 'exclude') {
      $done({ title: 'po0 脚本异常', content: String((e && e.message) || e).slice(0, 120), icon: 'exclamationmark.triangle', 'icon-color': COLOR.error });
    } else {
      $done({});
    }
  });
