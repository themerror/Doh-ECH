/**
 * DOH-ECH — Simplified DoH Worker
 * - Dual upstream DNS (AdGuard + Cloudflare) with Promise.any race
 * - ECH injection from specified domain's HTTPS record
 * - Enhance mode (custom rules via rules param)
 * - ECS support, shuffle
 * - Web frontend + JSON API
 * - /ech and /doh endpoints
 *
 * *********自定义参数***************
 * - clientIp   ECS 支持，默认自动获取
 * - ech        ECH 配置来源域名，默认 cloudflare-ech.com
 * - shuffle    返回记录随机乱序开关 默认 true
 * - enhance    (off/rule/full): rule 按 rules 参数规则返回, full 为所有站点开启
 * - alpn       HTTPS 记录 ALPN 列表，增强模式时生效
 * - rules      仅在 enhance 开启时生效, 格式: *domain1,*domain2:ip1,ip2-noA-noAAAA
 * - mandatory  指定浏览器必须理解的 HTTPS 参数，否则忽略整条记录
 */
// ===================== 全局配置 =====================
const UPSTREAM_DNS_ADGUARD = 'https://dns.adguard-dns.com/dns-query';
const UPSTREAM_JSON_ADGUARD = 'https://dns.adguard-dns.com/resolve';
const UPSTREAM_DNS_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';
const UPSTREAM_JSON_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';
const SVC_PARAM_IDS = { mandatory: 0, alpn: 1, "no-default-alpn": 2, port: 3, ipv4hint: 4, ech: 5, ipv6hint: 6 };

// ===================== 缓存逻辑 =====================
const cacheMap = new Map();
const CACHE_TTL = 3600 * 1000;
const ECH_CACHE_TTL = 3600 * 1000;
const PREFIX_CACHE_TTL = 30 * 60 * 1000;
const prefixCache = new Map();
const MAX_PRESCREEN = 10;
const MAX_FINAL = 6;

// ===================== 参数构建 =====================
function buildConfig(url, headers = null) {
    const get = (p, h) => (url.searchParams.get(p) || (headers ? headers.get(h) : null)) || '';

    const config = {
        shuffle: get('shuffle', 'X-Shuffle') || 'true',
        enhance: get('enhance', 'X-Enhance') || 'rule',
        rules: get('rules', 'X-Rules'),
        alpn: get('alpn', 'X-Alpn') || 'h3,h2',
        ech: get('ech', 'X-ECH') || 'cloudflare-ech.com',
        clientIp: get('clientIp', 'X-ClientIP') || '',
        mandatory: get('mandatory', 'X-Mandatory') || 'alpn'
    };
    return config;
}

// ===================== Worker 入口 =====================
export default {
    async fetch(req, env, ctx) {
        const url = new URL(req.url);
        if (url.pathname === '/log') return handleLogsRequest();
        const clientIP = url.searchParams.get('clientIp') || req.headers.get('X-ClientIP') || req.headers.get('CF-Connecting-IP') || '1.2.4.8';
        if (url.pathname === '/api/query') return handleApiQuery(url, clientIP);
        // /ech and /doh are now identical — both DoH forward + enhance
        if (url.pathname === '/ech' || url.pathname === '/doh') return handleDoHRequest(req, ctx, clientIP);
        return new Response(getHtml(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
};

// ===================== DoH 处理 =====================
async function handleDoHRequest(req, ctx, clientIP) {
    const url = new URL(req.url);
    const config = buildConfig(url, req.headers);
    if (!config.clientIp) config.clientIp = clientIP;

    if (req.method === 'POST') {
        const buf = await req.arrayBuffer();
        return handleDnsQuery(buf, config, clientIP);
    }
    if (req.method === 'GET' && url.searchParams.get('dns')) {
        const raw = url.searchParams.get('dns').replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
        const buf = Uint8Array.from(atob(raw), c => c.charCodeAt(0)).buffer;
        return handleDnsQuery(buf, config, clientIP);
    }
    return new Response('OK', { status: 200, headers: { 'Access-Control-Allow-Origin': '*' } });
}

// ===================== DNS 查询入口 =====================
async function handleDnsQuery(rawBuffer, config, clientIP) {
    try {
        const query = parseDnsPacket(rawBuffer);
        if (!query?.questions?.length) return forwardQuery(rawBuffer);
        const { id, questions } = query;
        const qType = questions[0].type;
        const qName = questions[0].name.toLowerCase().replace(/\.$/, '');

        // HTTPS 无增强 → 透明转发
        if (qType === 65 && (!config.enhance || config.enhance === 'off')) {
            const res = await forwardQuery(rawBuffer);
            return dnsResponse(await res.arrayBuffer());
        }

        const resolved = await resolveDNS(qName, qType === 28 ? 'AAAA' : (qType === 65 ? 'HTTPS' : 'A'), config, clientIP);
        if (resolved.error) return forwardQuery(rawBuffer);
        return dnsResponseFromResult(id, qName, qType, resolved);
    } catch (e) {
        console.error(e);
        return forwardQuery(rawBuffer);
    }
}

function dnsResponseFromResult(id, qName, qType, result) {
    if (qType === 65) {
        const rdata = result.httpsRecord ? [result.httpsRecord] : [];
        return dnsResponse(createMultiAnsResponse(id, qName, 65, rdata, rdata.length ? 300 : 60));
    }
    const bytes = qType === 28 ? ipv6ToBytes : ipToBytes;
    const answers = (result.answers || []).map(bytes);
    return dnsResponse(createMultiAnsResponse(id, qName, qType, answers, 300));
}

// ===================== JSON API =====================
async function handleApiQuery(url, clientIP) {
    const domain = url.searchParams.get('domain');
    const type = url.searchParams.get('type')?.toUpperCase() || 'A';
    if (!domain) return json({ error: '缺少 domain' }, 400);
    if (!['A', 'AAAA', 'HTTPS', 'CNAME', 'TXT', 'MX', 'NS'].includes(type)) return json({ error: '类型不支持' }, 400);
    const config = buildConfig(url);
    if (!config.clientIp) config.clientIp = clientIP;

    try {
        const result = await resolveDNS(domain, type, config, config.clientIp);
        if (result.httpsRecord) delete result.httpsRecord;
        return json(result);
    } catch (e) {
        return json({ error: e.message }, 500);
    }
}

// ===================== 核心 DNS 调度 =====================
async function resolveDNS(domain, type, config, clientIP) {
    domain = domain.toLowerCase().replace(/\.$/, '');

    if (type === 'A' || type === 'AAAA') {
        // Enhance mode rule matching
        if (config.enhance === 'rule' || config.enhance === 'full') {
            const ruleObj = await matchRule(domain, config);
            if (ruleObj) {
                if (type === 'A' && ruleObj.ips.some(ip => !ip.includes(':'))) {
                    let ips = ruleObj.ips.filter(ip => !ip.includes(':'));
                    if (config.shuffle !== 'false') ips = shuffle(ips);
                    return { domain, type, answers: ips, ech: null };
                }
                if (type === 'AAAA' && ruleObj.ips.some(ip => ip.includes(':'))) {
                    let ips = ruleObj.ips.filter(ip => ip.includes(':'));
                    if (config.shuffle !== 'false') ips = shuffle(ips);
                    return { domain, type, answers: ips, ech: null };
                }
                if (type === 'A' && ruleObj.noA) return { domain, type, answers: [], ech: null };
                if (type === 'AAAA' && ruleObj.noAAAA) return { domain, type, answers: [], ech: null };
            }
        }

        // Upstream query
        const dnsType = type === 'AAAA' ? 28 : 1;
        const data = await queryUpstreamDNS(domain, dnsType, clientIP);
        const answers = data?.Answer?.filter(r => r.type === dnsType).map(r => r.data) || [];
        return { domain, type, answers, ech: null };
    }

    if (type === 'HTTPS') {
        if (config.enhance && config.enhance !== 'off') {
            const result = await buildEnhancedHttpsRecord(domain, config, clientIP);
            return cleanResult(result);
        }
        // Default: return raw upstream HTTPS record
        const data = await queryUpstreamDNS(domain, 65, clientIP);
        const result = { domain, type, answers: [] };
        if (data?.Answer) {
            const rec = data.Answer.find(r => r.type === 65);
            if (rec) {
                const parsed = parseHttpsRecordFull(rec.data);
                if (parsed) {
                    result.ech = parsed.ech || null;
                    if (parsed.ipv4hints && parsed.ipv4hints.length > 0) result.ipv4hints = parsed.ipv4hints;
                    if (parsed.ipv6hints && parsed.ipv6hints.length > 0) result.ipv6hints = parsed.ipv6hints;
                    result.alpn = parsed.alpn || '';
                }
            }
        }
        return result;
    }

    // Generic fallback for CNAME, TXT, MX, NS, etc.
    return await resolveFallbackRecord(domain, type, clientIP);
}

function cleanResult(result) {
    if (result.ipv4hints && result.ipv4hints.length === 0) delete result.ipv4hints;
    if (result.ipv6hints && result.ipv6hints.length === 0) delete result.ipv6hints;
    return result;
}

// ===================== HTTPS 记录构建（简化版） =====================
async function buildEnhancedHttpsRecord(domain, config, clientIP) {
    const alpn = config.alpn || 'h3,h2';
    const mode = config.enhance || 'off';
    const ruleObj = (mode === 'rule' || mode === 'full') ? await matchRule(domain, config) : null;

    let ipv4 = [], ipv6 = [];

    // Collect hints
    const hints = await collectIpHints(domain, config, clientIP, mode);
    ipv4 = hints.ipv4;
    ipv6 = hints.ipv6;

    // Apply block flags
    if (isTypeBlocked('A', ruleObj, config)) ipv4 = [];
    if (isTypeBlocked('AAAA', ruleObj, config)) ipv6 = [];

    // Safety fallback
    if (ipv4.length === 0 && !isTypeBlocked('A', ruleObj, config)) {
        ipv4 = await resolveRealHints(domain, 1, clientIP);
    }
    if (ipv6.length === 0 && !isTypeBlocked('AAAA', ruleObj, config)) {
        ipv6 = await resolveRealHints(domain, 28, clientIP);
    }

    // Build params from upstream HTTPS record
    const paramMap = new Map();
    try {
        const data = await queryUpstreamDNS(domain, 65, clientIP);
        if (data?.Answer) {
            const rec = data.Answer.find(r => r.type === 65);
            if (rec) {
                const upstreamParams = parseRawHttpsRecord(rec.data);
                for (const p of upstreamParams) {
                    if (p.key && p.val !== undefined) paramMap.set(p.key, p.val);
                }
            }
        }
    } catch (e) {}

    // Inject ECH config (fetched from specified domain's HTTPS record)
    if (!paramMap.has('ech')) {
        const ech = await fetchRealEch(config.ech || 'cloudflare-ech.com', clientIP);
        if (ech) paramMap.set('ech', ech);
    }

    paramMap.set('alpn', alpn);
    if (ipv4.length > 0) paramMap.set('ipv4hint', ipv4.join(','));
    else paramMap.delete('ipv4hint');
    if (ipv6.length > 0) paramMap.set('ipv6hint', ipv6.join(','));
    else paramMap.delete('ipv6hint');

    const finalParams = Array.from(paramMap, ([k, v]) => ({ key: k, val: v }));
    injectEnhanceDefaults(finalParams, config.mandatory || 'alpn');

    return buildHttpsRecordFromParams(domain, finalParams, ipv4, ipv6);
}

// ===================== 统一 IP hints 收集 =====================
async function collectIpHints(domain, config, clientIP, source) {
    let ipv4 = [], ipv6 = [];

    // Rule matching
    if (source === 'rule' || source === 'full') {
        const ruleObj = await matchRule(domain, config);
        if (ruleObj !== null) {
            const matchedIPs = ruleObj.ips;
            ipv4 = matchedIPs.filter(ip => !ip.includes(':'));
            ipv6 = matchedIPs.filter(ip => ip.includes(':'));
            if (ipv4.length === 0 && ipv6.length === 0) {
                [ipv4, ipv6] = await Promise.all([
                    resolveRealHints(domain, 1, clientIP),
                    resolveRealHints(domain, 28, clientIP)
                ]);
            }
        } else {
            // full mode, no rule match — get real hints
            [ipv4, ipv6] = await Promise.all([
                resolveRealHints(domain, 1, clientIP),
                resolveRealHints(domain, 28, clientIP)
            ]);
        }
    }

    ipv4 = [...new Set(ipv4)].slice(0, MAX_FINAL);
    ipv6 = [...new Set(ipv6)].slice(0, MAX_FINAL);
    if (config.shuffle !== 'false') {
        ipv4 = shuffle(ipv4);
        ipv6 = shuffle(ipv6);
    }
    return { ipv4, ipv6 };
}

// ===================== 规则匹配 =====================
async function matchRule(domain, config) {
    if (!config.rules) return null;
    const merged = parseRules(config.rules);
    for (const [key, rule] of merged) { rule.ips = rule.ips.flatMap(ip => ip.includes('/') ? getPrefixIPs(ip) : [ip]); }
    const matched = [];
    for (const [pattern, ruleObj] of merged) {
        if (matchDomainPattern(domain, pattern)) {
            matched.push({ pattern, ruleObj });
        }
    }
    if (matched.length === 0) return null;
    matched.sort((a, b) => b.pattern.length - a.pattern.length);
    return matched[0].ruleObj;
}

function matchDomainPattern(domain, pattern) {
    if (pattern.startsWith('*.')) {
        const suffix = pattern.substring(1);
        return domain.endsWith(suffix) || domain === suffix.substring(1);
    }
    return domain === pattern;
}

function parseRules(rulesStr) {
    const map = new Map();
    if (!rulesStr) return map;
    const entries = rulesStr.split(';');
    for (const entry of entries) {
        const colonIdx = entry.indexOf(':');
        if (colonIdx === -1) continue;
        const patternPart = entry.substring(0, colonIdx).trim();
        const rest = entry.substring(colonIdx + 1).trim();

        const dashIdx = rest.indexOf('-');
        let ips = [];
        let flags = new Set();

        if (dashIdx === -1) {
            ips = rest.split(',').map(s => s.trim()).filter(s => s);
            ips = ips.flatMap(ip => ip.includes('/') ? getPrefixIPs(ip) : [ip]);
        } else {
            const ipPart = rest.substring(0, dashIdx).trim();
            const flagPart = rest.substring(dashIdx + 1).trim();
            if (ipPart) {
                ips = ipPart.split(',').map(s => s.trim()).filter(s => s);
                ips = ips.flatMap(ip => ip.includes('/') ? getPrefixIPs(ip) : [ip]);
            }
            if (flagPart) {
                flagPart.split('-').map(s => s.trim().toLowerCase()).forEach(f => {
                    if (f === 'noa' || f === 'noaaaa') flags.add(f);
                });
            }
        }

        const ruleObj = { ips, noA: flags.has('noa'), noAAAA: flags.has('noaaaa') };
        const patterns = patternPart.split(',').map(s => s.trim()).filter(s => s);
        for (const pattern of patterns) {
            map.set(pattern, ruleObj);
        }
    }
    return map;
}

// ===================== HTTPS 记录打包 =====================
function buildHttpsRecordFromParams(domain, params, ipv4Hints, ipv6Hints) {
    const finalParams = sortAndDedupeParams([...params], ipv4Hints, ipv6Hints);
    const httpsRecord = packHttpsParams(1, '.', finalParams);
    const result = { domain, type: 'HTTPS', answers: [] };
    result.ech = finalParams.find(p => p.key === 'ech')?.val || null;
    result.httpsRecord = httpsRecord;
    if (ipv4Hints.length) result.ipv4hints = ipv4Hints;
    if (ipv6Hints.length) result.ipv6hints = ipv6Hints;
    return result;
}

function sortAndDedupeParams(params, ipv4Hints, ipv6Hints) {
    const keyOrder = {
        mandatory: SVC_PARAM_IDS.mandatory,
        alpn: SVC_PARAM_IDS.alpn,
        "no-default-alpn": SVC_PARAM_IDS["no-default-alpn"],
        port: SVC_PARAM_IDS.port,
        ipv4hint: SVC_PARAM_IDS.ipv4hint,
        ech: SVC_PARAM_IDS.ech,
        ipv6hint: SVC_PARAM_IDS.ipv6hint
    };
    const map = new Map();
    const booleanKeys = new Set(['no-default-alpn']);

    for (const p of params) {
        if (p.key && p.val !== undefined) {
            if (p.val !== '' || booleanKeys.has(p.key)) {
                map.set(p.key, p.val);
            }
        }
    }

    if (ipv4Hints.length > 0) map.set('ipv4hint', ipv4Hints.join(','));
    else map.delete('ipv4hint');
    if (ipv6Hints.length > 0) map.set('ipv6hint', ipv6Hints.join(','));
    else map.delete('ipv6hint');

    const sortedKeys = Array.from(map.keys()).sort(
        (a, b) => (keyOrder[a] ?? 999) - (keyOrder[b] ?? 999)
    );
    return sortedKeys.map(k => ({ key: k, val: map.get(k) }));
}

// ===================== 工具函数 =====================
function parseIpList(raw, doShuffle = true) {
    if (!raw) return [];
    raw = raw.trim();
    let arr;
    if (raw.startsWith('[') && raw.endsWith(']')) {
        try {
            arr = JSON.parse(raw).map(String).filter(s => s);
        } catch {
            arr = raw.split(',').map(s => s.trim()).filter(s => s);
        }
    } else {
        arr = raw.split(',').map(s => s.trim()).filter(s => s);
    }
    if (doShuffle) return shuffle(arr);
    return arr;
}

function prescreenIpList(raw) {
    if (!raw) return '';
    const ips = raw.split(',').map(s => s.trim()).filter(s => s);
    if (ips.length <= MAX_PRESCREEN) return raw;
    const shuffled = shuffle([...ips]);
    return shuffled.slice(0, MAX_PRESCREEN).join(',');
}

function injectEnhanceDefaults(params, mandatoryValue) {
    const existingKeys = new Set(params.map(p => p.key));
    if (!existingKeys.has('mandatory')) params.push({ key: 'mandatory', val: mandatoryValue || 'alpn' });
}

async function handleLogsRequest() {
    const now = Date.now();
    const globalDefaults = {
        _description: '全局参数默认值',
        shuffle: 'true (随机乱序 IP)',
        enhance: 'off (增强模式)',
        alpn: 'h3,h2 (ALPN 列表)',
        mandatory: 'alpn (强制参数)',
    };
    const startedTimestamp = Date.now();
    const uptimeMs = Date.now() - startedTimestamp;
    const uptimeSeconds = Math.floor(uptimeMs / 1000);
    const hours = Math.floor(uptimeSeconds / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;
    const uptimeFormatted = `${hours}h ${minutes}m ${seconds}s`;
    const runtime = {
        _description: 'Worker 运行信息',
        uptime: uptimeFormatted,
        startedAt: new Date(startedTimestamp).toISOString(),
    };
    const payload = {
        timestamp: new Date(now).toISOString(),
        runtime: runtime,
        globalDefaults: globalDefaults
    };
    return json(payload);
}

function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

async function resolveMultiDomainToIps(domainsStr, type, clientIP, doShuffle = true, limit = 0) {
    const domains = domainsStr.split(',').map(s => s.trim()).filter(s => s);
    if (domains.length === 0) return [];
    const promises = domains.map(d => resolveDomainToIp(d, type, clientIP));
    const results = await Promise.allSettled(promises);
    const allIps = new Set();
    for (const res of results) {
        if (res.status === 'fulfilled') {
            for (const ip of res.value) allIps.add(ip);
        }
    }
    let ipArray = Array.from(allIps);
    if (doShuffle) shuffle(ipArray);
    if (limit > 0 && ipArray.length > limit) {
        ipArray = ipArray.slice(0, limit);
    }
    if (type === 1) return ipArray.map(ipToBytes);
    else return ipArray.map(ipv6ToBytes);
}

async function resolveDomainToIp(domain, type = 1, clientIP) {
    const data = await queryUpstreamDNS(domain, type, clientIP);
    if (data && data.Answer) {
        return data.Answer.filter(r => r.type === type).map(r => r.data);
    }
    return [];
}

async function queryUpstreamDNS(name, type, clientIP = '', upstreamUrl = null) {
    const params = new URLSearchParams({ name, type: String(type) });
    let ecsCacheSuffix = '';
    if (clientIP) {
        if (clientIP.includes(':')) {
            const prefix = clientIP.split(':').slice(0, 4).join(':') + '::/56';
            params.set('edns_client_subnet', clientIP + '/56');
            ecsCacheSuffix = '/56-' + prefix;
        } else {
            const parts = clientIP.split('.');
            const prefix = parts.slice(0, 3).join('.') + '.0/24';
            params.set('edns_client_subnet', clientIP + '/24');
            ecsCacheSuffix = '/24-' + prefix;
        }
    }

    const cacheKey = new Request(`https://dns-cache/${encodeURIComponent(name)}/${type}${ecsCacheSuffix}`);
    try {
        if (typeof caches !== 'undefined' && caches.default) {
            const cachedRes = await caches.default.match(cacheKey);
            if (cachedRes) return cachedRes.json();
        }
    } catch (e) {}

    const urls = upstreamUrl
        ? [upstreamUrl + '?' + params.toString()]
        : [UPSTREAM_JSON_ADGUARD + '?' + params.toString(), UPSTREAM_JSON_CLOUDFLARE + '?' + params.toString()];

    let result;
    // For HTTPS (type 65), prefer AdGuard which returns text-format ech=... data;
    // Cloudflare DNS JSON API returns hex wire format that lacks readable ech field
    if (type === 65) {
        try {
            const res = await fetch(urls[0], { headers: { 'Accept': 'application/dns-json' } });
            if (res.ok) result = await res.json();
            else throw new Error('AdGuard failed');
        } catch {
            try {
                const res = await fetch(urls[1], { headers: { 'Accept': 'application/dns-json' } });
                if (res.ok) result = await res.json();
                else return null;
            } catch { return null; }
        }
    } else {
        try {
            result = await Promise.any(urls.map(url =>
                fetch(url, { headers: { 'Accept': 'application/dns-json' } })
                    .then(res => res.ok ? res.json() : Promise.reject())
            ));
        } catch {
            try {
                const res = await fetch(urls[0], { headers: { 'Accept': 'application/dns-json' } });
                if (res.ok) result = await res.json();
                else return null;
            } catch { return null; }
        }
    }

    if (result && typeof caches !== 'undefined' && caches.default) {
        try {
            const maxAge = (type === 65) ? 600 : 300;
            const resToCache = new Response(JSON.stringify(result), {
                headers: { 'Cache-Control': `public, max-age=${maxAge}` }
            });
            caches.default.put(cacheKey, resToCache).catch(() => {});
        } catch (e) {}
    }
    return result;
}

function parseHttpsRecord(dataStr) {
    const parts = dataStr.split(/\s+/);
    if (parts.length < 3) return null;
    const result = {};
    for (let i = 2; i < parts.length; i++) {
        const eqIdx = parts[i].indexOf('=');
        if (eqIdx === -1) continue;
        const k = parts[i].substring(0, eqIdx);
        const v = parts[i].substring(eqIdx + 1);
        if (k === 'ech') result.ech = v;
        else if (k === 'alpn') result.alpn = v;
    }
    return result;
}

function packHttpsParamsWithHints(priority, target, params, ipv4Hints, ipv6Hints) {
    if (ipv4Hints && ipv4Hints.length > 0) {
        const unique = [...new Set(ipv4Hints)].slice(0, MAX_FINAL);
        if (unique.length > 0) params.push({ key: 'ipv4hint', val: unique.join(',') });
    }
    if (ipv6Hints && ipv6Hints.length > 0) {
        const unique = [...new Set(ipv6Hints)].slice(0, MAX_FINAL);
        if (unique.length > 0) params.push({ key: 'ipv6hint', val: unique.join(',') });
    }
    return packHttpsParams(priority, target, params);
}

function packHttpsParams(priority, target, params) {
    const targetBuf = target === '.' ? new Uint8Array([0]) : encodeDnsName(target);
    const paramBufs = params.map(p => encodeSvcParam(p.key, p.val)).filter(b => b);
    paramBufs.sort((a, b) => new DataView(a.buffer).getUint16(0) - new DataView(b.buffer).getUint16(0));
    let totalLen = 2 + targetBuf.length;
    for (const b of paramBufs) totalLen += b.length;
    const res = new Uint8Array(totalLen);
    const v = new DataView(res.buffer);
    v.setUint16(0, priority);
    res.set(targetBuf, 2);
    let offset = 2 + targetBuf.length;
    for (const b of paramBufs) { res.set(b, offset); offset += b.length; }
    return res;
}

function encodeSvcParam(key, value) {
    const id = SVC_PARAM_IDS[key];
    if (id === undefined) return null;
    let valBuf;

    if (key === 'mandatory') {
        const keys = [...new Set(
            value.split(',')
                .map(s => s.trim())
                .filter(Boolean)
                .map(k => SVC_PARAM_IDS[k])
                .filter(v => v !== undefined)
        )].sort((a, b) => a - b);

        if (keys.length === 0) return null;
        valBuf = new Uint8Array(keys.length * 2);
        const dv = new DataView(valBuf.buffer);
        keys.forEach((id, i) => dv.setUint16(i * 2, id));
    }
    else if (key === 'no-default-alpn') {
        valBuf = new Uint8Array(0);
    }
    else if (key === 'alpn') {
        const parts = value.split(',').map(s => s.trim()).filter(s => s);
        if (parts.length === 0) return null;
        for (const p of parts) {
            if (p.length > 255) return null;
        }
        valBuf = new Uint8Array(parts.reduce((a, b) => a + b.length + 1, 0));
        let o = 0;
        for (const p of parts) {
            valBuf[o++] = p.length;
            for (let i = 0; i < p.length; i++) valBuf[o++] = p.charCodeAt(i);
        }
    }
    else if (key === 'port') {
        const portNum = Number(value);
        if (!Number.isInteger(portNum) || portNum < 0 || portNum > 65535) return null;
        valBuf = new Uint8Array(2);
        new DataView(valBuf.buffer).setUint16(0, portNum);
    }
    else if (key === 'ipv4hint') {
        const parts = value.split(',').map(s => s.trim()).filter(s => s);
        if (parts.length === 0) return null;
        valBuf = new Uint8Array(parts.length * 4);
        let offset = 0;
        for (const ip of parts) {
            const bytes = ipToBytes(ip);
            if (!bytes) return null;
            valBuf.set(bytes, offset);
            offset += 4;
        }
    }
    else if (key === 'ipv6hint') {
        const parts = value.split(',').map(s => s.trim()).filter(s => s);
        if (parts.length === 0) return null;
        valBuf = new Uint8Array(parts.length * 16);
        let offset = 0;
        for (const ip of parts) {
            const bytes = ipv6ToBytes(ip);
            if (!bytes) return null;
            valBuf.set(bytes, offset);
            offset += 16;
        }
    }
    else {
        try {
            let b64 = value.replace(/^"|"$/g, '').replace(/-/g, '+').replace(/_/g, '/');
            while (b64.length % 4) b64 += '=';
            const s = atob(b64);
            valBuf = new Uint8Array(s.length);
            for (let i = 0; i < s.length; i++) valBuf[i] = s.charCodeAt(i);
        } catch (e) {
            console.error('encodeSvcParam base64 error:', e);
            return null;
        }
    }

    const res = new Uint8Array(4 + valBuf.length);
    const dv = new DataView(res.buffer);
    dv.setUint16(0, id);
    dv.setUint16(2, valBuf.length);
    res.set(valBuf, 4);
    return res;
}

function encodeDnsName(domain) {
    const parts = domain.split('.');
    const buf = new Uint8Array(domain.length + 2);
    let offset = 0;
    for (const part of parts) {
        buf[offset++] = part.length;
        for (let i = 0; i < part.length; i++) buf[offset++] = part.charCodeAt(i);
    }
    buf[offset++] = 0;
    return buf.slice(0, offset);
}

function parseDnsPacket(buf) {
    const v = new DataView(buf);
    if (buf.byteLength < 12) return null;
    let offset = 12;
    const labels = [];
    while (offset < buf.byteLength) {
        const len = v.getUint8(offset);
        if (len === 0) { offset++; break; }
        if ((len & 0xC0) === 0xC0) { offset += 2; break; }
        offset++;
        labels.push(new TextDecoder().decode(buf.slice(offset, offset + len)));
        offset += len;
    }
    return {
        id: v.getUint16(0),
        questions: [{ name: labels.join('.'), type: v.getUint16(offset) }]
    };
}

function createMultiAnsResponse(id, qn, qt, rds, ttl = 3600) {
    const encodedName = encodeDnsName(qn);
    const questionLen = 12 + encodedName.length + 4;
    const pointer = 0xC000 | 12;
    let totalLen = questionLen;
    for (const r of rds) totalLen += 2 + 2 + 2 + 4 + 2 + r.length;
    const buf = new Uint8Array(totalLen);
    const v = new DataView(buf.buffer);
    v.setUint16(0, id);
    v.setUint16(2, 0x8180);
    v.setUint16(4, 1);
    v.setUint16(6, rds.length);
    v.setUint16(8, 0);
    v.setUint16(10, 0);
    let offset = 12;
    buf.set(encodedName, offset); offset += encodedName.length;
    v.setUint16(offset, qt); offset += 2;
    v.setUint16(offset, 1); offset += 2;
    for (const r of rds) {
        v.setUint16(offset, pointer); offset += 2;
        v.setUint16(offset, qt); offset += 2;
        v.setUint16(offset, 1); offset += 2;
        v.setUint32(offset, ttl); offset += 4;
        v.setUint16(offset, r.length); offset += 2;
        buf.set(r, offset); offset += r.length;
    }
    return buf.buffer;
}

async function forwardQuery(body) {
    const reqInit = {
        method: 'POST',
        headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
        body
    };
    const pAdguard = fetch(UPSTREAM_DNS_ADGUARD, reqInit).then(res => res.ok ? res : Promise.reject());
    const pCloudflare = fetch(UPSTREAM_DNS_CLOUDFLARE, reqInit).then(res => res.ok ? res : Promise.reject());
    try { return await Promise.any([pAdguard, pCloudflare]); } catch { return fetch(UPSTREAM_DNS_ADGUARD, reqInit); }
}

function dnsResponse(buffer) {
    return new Response(buffer, {
        headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' }
    });
}

async function resolveFallbackRecord(domain, type, clientIP) {
    const typeMap = {
        'A': 1, 'AAAA': 28, 'CNAME': 5, 'TXT': 16, 'MX': 15, 'NS': 2, 'HTTPS': 65
    };
    const dnsType = typeMap[type] || 1;

    const data = await queryUpstreamDNS(domain, dnsType, clientIP);
    if (!data) return { domain, type, error: '上游查询失败' };

    if (type === 'HTTPS') {
        const result = { domain, type, answers: [] };
        if (data?.Answer) {
            const rec = data.Answer.find(r => r.type === 65);
            if (rec) {
                const parsed = parseHttpsRecordFull(rec.data);
                if (parsed) {
                    result.ech = parsed.ech || null;
                    result.ipv4hints = parsed.ipv4hints || [];
                    result.ipv6hints = parsed.ipv6hints || [];
                }
            }
        }
        return result;
    }

    const answers = data?.Answer?.filter(r => r.type === dnsType).map(r => r.data) || [];
    return { domain, type, answers, ech: null };
}

function generateRandomIPv6(prefixStr) {
    const [addrStr, bitsStr] = prefixStr.split('/');
    const prefixLen = parseInt(bitsStr, 10);
    if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 128) return [];

    const baseIP = ipv6ToBigInt(addrStr);
    const hostBits = 128 - prefixLen;
    const maxHost = (1n << BigInt(hostBits)) - 1n;

    const minHost = 1n;
    const maxValidHost = maxHost - 1n;

    const ips = [];
    for (let i = 0; i < 2; i++) {
        const randomHost = randomBigInt(minHost, maxValidHost);
        const fullIP = baseIP | randomHost;
        ips.push(bigIntToIPv6(fullIP));
    }
    return ips;
}

function randomBigInt(min, max) {
    const range = max - min + BigInt(1);
    const bits = range.toString(2).length;
    let rand;
    const maxAttempts = 10;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        rand = 0n;
        for (let i = 0; i < 16; i++) {
            rand = (rand << 8n) | BigInt(bytes[i]);
        }
        const mask = (1n << BigInt(bits)) - 1n;
        rand = rand & mask;
        if (rand <= range) {
            return min + rand;
        }
    }
    return min;
}

function bigIntToIPv6(big) {
    const segments = [];
    for (let i = 0; i < 8; i++) {
        segments.unshift(Number((big >> BigInt(i * 16)) & 0xFFFFn).toString(16));
    }
    let maxStart = -1, maxLen = 0;
    let curStart = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
        if (segments[i] === '0') {
            if (curStart === -1) curStart = i;
            curLen++;
            if (curLen > maxLen) {
                maxLen = curLen;
                maxStart = curStart;
            }
        } else {
            curStart = -1;
            curLen = 0;
        }
    }
    if (maxLen > 1) {
        const head = segments.slice(0, maxStart).join(':');
        const tail = segments.slice(maxStart + maxLen).join(':');
        return `${head}::${tail}`;
    }
    return segments.join(':');
}

function getPrefixIPs(prefixStr) {
    const cached = prefixCache.get(prefixStr);
    if (cached && Date.now() < cached.expire) {
        return cached.ips;
    }
    const ips = generateRandomIPv6(prefixStr);
    prefixCache.set(prefixStr, { ips, expire: Date.now() + PREFIX_CACHE_TTL });
    return ips;
}

// ===================== IP 转换 =====================
function extractIpsFromPacket(buffer) {
    const ips = [];
    const view = new DataView(buffer);
    if (buffer.byteLength < 12) return [];
    const ancount = view.getUint16(6);
    const totalRecords = ancount + view.getUint16(8) + view.getUint16(10);
    let offset = 12;
    try {
        for (let i = 0; i < view.getUint16(4); i++) {
            while (view.getUint8(offset) !== 0) {
                if ((view.getUint8(offset) & 0xC0) === 0xC0) { offset += 1; break; }
                offset += view.getUint8(offset) + 1;
            }
            offset += 5;
        }
        for (let i = 0; i < totalRecords; i++) {
            while (view.getUint8(offset) !== 0) {
                if ((view.getUint8(offset) & 0xC0) === 0xC0) { offset += 1; break; }
                offset += view.getUint8(offset) + 1;
            }
            offset += 1;
            const type = view.getUint16(offset); offset += 8;
            const rdlen = view.getUint16(offset); offset += 2;
            if (type === 1 && rdlen === 4) {
                ips.push(Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.'));
            } else if (type === 28 && rdlen === 16) {
                const raw = new Uint8Array(buffer.slice(offset, offset + 16));
                ips.push(formatIPv6(raw));
            }
            offset += rdlen;
        }
    } catch (e) {}
    return ips;
}

function formatIPv6(bytes) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
        parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    let longestStart = -1, longestLen = 0;
    let currentStart = -1, currentLen = 0;
    for (let i = 0; i < parts.length; i++) {
        if (parts[i] === '0') {
            if (currentStart === -1) currentStart = i;
            currentLen++;
            if (currentLen > longestLen) { longestLen = currentLen; longestStart = currentStart; }
        } else {
            currentStart = -1; currentLen = 0;
        }
    }
    if (longestLen > 1) {
        parts.splice(longestStart, longestLen, '');
        if (longestStart === 0) parts.unshift('');
        if (longestStart + longestLen === 8) parts.push('');
    }
    return parts.join(':').replace(/:{3,}/, '::');
}

function formatIPv6FromBytes(bytes) { return formatIPv6(bytes); }

function ipToLong(ip) {
    return ip.split('.').reduce((a, b) => (a << 8) + parseInt(b, 10), 0) >>> 0;
}

function ipv6ToBigInt(ip) {
    let p = ip.split(':');
    if (ip.includes('::')) {
        const [f, s] = ip.split('::');
        const fP = f ? f.split(':') : [];
        const sP = s ? s.split(':') : [];
        p = [...fP, ...Array(8 - fP.length - sP.length).fill('0'), ...sP];
    }
    return p.reduce((a, b) => (a << 16n) + BigInt(parseInt(b || '0', 16)), 0n);
}

function ipToBytes(ip) { return new Uint8Array(ip.split('.').map(Number)); }

function ipv6ToBytes(ip) {
    let p = ip.split(':');
    if (ip.includes('::')) {
        const [l, r] = ip.split('::');
        const lp = l ? l.split(':') : [];
        const rp = r ? r.split(':') : [];
        p = [...lp, ...Array(8 - lp.length - rp.length).fill('0'), ...rp];
    }
    const b = new Uint8Array(16);
    p.forEach((v, i) => {
        const val = parseInt(v, 16) || 0;
        b[i * 2] = val >> 8;
        b[i * 2 + 1] = val & 0xFF;
    });
    return b;
}

function bytesToIp(bytes) { return Array.from(bytes).join('.'); }
function bytesToIp6(bytes) { return formatIPv6(bytes); }

// ===================== 辅助函数 =====================
async function resolveRealHints(domain, type, clientIP) {
    try {
        const data = await queryUpstreamDNS(domain, type, clientIP);
        if (data && data.Answer) {
            return data.Answer.filter(r => r.type === type).map(r => r.data);
        }
    } catch (e) {}
    return [];
}

/**
 * 获取 ECH 公钥（从指定域名的 HTTPS 记录中提取，带缓存）
 */
async function fetchRealEch(echDomain, clientIP) {
    const cacheKey = `ech:${echDomain}`;
    const cached = cacheMap.get(cacheKey);
    if (cached && Date.now() < cached.expire) return cached.value;
    try {
        let data = await queryUpstreamDNS(echDomain, 65, clientIP);
        if (!data) {
            await new Promise(r => setTimeout(r, 500));
            data = await queryUpstreamDNS(echDomain, 65, clientIP);
        }
        if (data && data.Answer) {
            const rec = data.Answer.find(r => r.type === 65);
            if (rec) {
                const parsed = parseHttpsRecord(rec.data);
                if (parsed && parsed.ech) {
                    cacheMap.set(cacheKey, { value: parsed.ech, expire: Date.now() + ECH_CACHE_TTL });
                    return parsed.ech;
                }
            }
        }
    } catch {}
    return null;
}

function parseRawHttpsRecord(dataStr) {
    const parts = dataStr.split(/\s+/);
    if (parts.length < 3) return [];
    const params = [];
    for (let i = 2; i < parts.length; i++) {
        const eqIdx = parts[i].indexOf('=');
        if (eqIdx === -1) continue;
        params.push({ key: parts[i].substring(0, eqIdx), val: parts[i].substring(eqIdx + 1) });
    }
    return params;
}

function parseHttpsRecordFull(dataStr) {
    const parts = dataStr.split(/\s+/);
    if (parts.length < 3) return null;
    const result = {};
    for (let i = 2; i < parts.length; i++) {
        const eqIdx = parts[i].indexOf('=');
        if (eqIdx === -1) continue;
        const k = parts[i].substring(0, eqIdx);
        const v = parts[i].substring(eqIdx + 1);
        if (!k || !v) continue;
        if (k === 'ech') result.ech = v;
        else if (k === 'alpn') result.alpn = v;
        else if (k === 'ipv4hint') result.ipv4hints = v.split(',').map(s => s.trim());
        else if (k === 'ipv6hint') result.ipv6hints = v.split(',').map(s => s.trim());
    }
    return result;
}

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
}

function isTypeBlocked(type, ruleObj, config) {
    if (ruleObj) {
        if (type === 'A' && ruleObj.noA) return true;
        if (type === 'AAAA') {
            if (ruleObj.hasOwnProperty('noAAAA')) {
                return ruleObj.noAAAA;
            }
        }
    }
    return false;
}

// ===================== HTML 前端 =====================
function getHtml() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOH-ECH 查询</title>
    <style>
        :root {
            --bg: #0a0e17;
            --card: #111827;
            --text: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent: #0A84FF;
            --accent-glow: rgba(10, 132, 255, 0.3);
            --border: #1e293b;
            --input-bg: #0f172a;
            --enhance: #30D158;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, 'Inter', system-ui, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
            background-image: radial-gradient(ellipse at top, rgba(10, 132, 255, 0.25) 0%, transparent 60%),
                              radial-gradient(ellipse at bottom, rgba(48, 209, 88, 0.1) 0%, transparent 60%);
            -webkit-tap-highlight-color: transparent;
        }
        .container {
            background: rgba(30, 30, 30, 0.6);
            backdrop-filter: blur(25px) saturate(140%);
            -webkit-backdrop-filter: blur(25px) saturate(140%);
            border-radius: 32px;
            padding: 2rem;
            width: 100%;
            max-width: 600px;
            border: 1px solid rgba(255, 255, 255, 0.15);
            box-shadow: 0 20px 60px rgba(0,0,0,0.5), inset 0 0 0 1px rgba(255,255,255,0.08);
            position: relative;
            overflow: hidden;
        }
        .container::before {
            content: '';
            position: absolute;
            top: -50%; left: -30%; width: 160%; height: 160%;
            background: radial-gradient(circle at 30% 20%, rgba(255,255,255,0.12) 0%, transparent 50%);
            pointer-events: none;
        }
        .header {
            display: flex; align-items: center; gap: 12px; margin-bottom: 1rem;
            position: relative; z-index: 1;
        }
        .logo {
            width: 44px; height: 44px;
            background: linear-gradient(135deg, var(--accent), #5E5CE6);
            border-radius: 14px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.4rem;
            box-shadow: 0 4px 12px rgba(10, 132, 255, 0.4);
        }
        h1 { font-size: 1.5rem; font-weight: 600; letter-spacing: -0.02em; }
        .subtitle {
            color: var(--text-secondary); font-size: 0.75rem; margin-bottom: 1.8rem;
            margin-left: 56px; position: relative; z-index: 1;
        }
        label {
            font-size: 0.8rem; font-weight: 500; display: block; margin-bottom: 0.4rem;
            color: var(--text-secondary); text-transform: uppercase;
            letter-spacing: 0.05em; position: relative; z-index: 1;
        }
        input, select {
            width: 100%; padding: 0.7rem 1rem; margin-bottom: 1rem;
            background: rgba(255, 255, 255, 0.06);
            backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 14px;
            color: var(--text); font-size: 0.79rem; transition: all 0.2s;
            font-family: inherit; outline: none; position: relative; z-index: 1;
        }
        input:focus, select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 4px var(--accent-glow);
            background: rgba(255, 255, 255, 0.12);
        }
        select {
            cursor: pointer; appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%23ffffff' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10l-5 5z'/%3E%3C/svg%3E");
            background-repeat: no-repeat; background-position: right 1rem center;
            padding-right: 2.5rem;
        }
        .row { display: flex; gap: 1rem; margin-bottom: 0.5rem; position: relative; z-index: 1; }
        .row > div { flex: 1; }
        .param-grid {
            display: grid; grid-template-columns: 1fr 1fr;
            gap: 0 1.5rem; position: relative; z-index: 1;
        }
        @media (max-width: 400px) { .param-grid { grid-template-columns: 1fr; } }
        .badge {
            display: inline-block; padding: 0.15rem 0.5rem; border-radius: 8px;
            font-size: 0.5rem; font-weight: 600; margin-left: 0.4px;
            margin-bottom: 3.8px; background: rgba(255,255,255,0.15);
            vertical-align: middle;
        }
        .badge-enhance { color: var(--enhance); }
        .toggle-row { display: flex; align-items: center; gap: 12px; position: relative; z-index: 1; }
        .checkbox-container {
            display: inline-flex; align-items: center; gap: 8px;
            cursor: pointer; user-select: none; position: relative; z-index: 1;
        }
        .checkbox-container input { display: none; }
        .checkmark {
            width: 24px; height: 24px; border-radius: 50%;
            background: rgba(255, 255, 255, 0.1);
            border: 2px solid rgba(255, 255, 255, 0.25);
            display: inline-block; position: relative; transition: all 0.2s;
            backdrop-filter: blur(5px); -webkit-backdrop-filter: blur(5px);
            box-shadow: 0 0 8px rgba(255,255,255,0.1);
        }
        .checkbox-container input:checked + .checkmark {
            background: var(--accent); border-color: var(--accent);
            box-shadow: 0 0 14px var(--accent-glow);
        }
        .checkmark::after {
            content: ''; position: absolute; top: 50%; left: 50%;
            width: 12px; height: 12px; border-radius: 50%; background: white;
            transform: translate(-50%, -50%) scale(0); transition: transform 0.2s ease;
        }
        .checkbox-container input:checked + .checkmark::after {
            transform: translate(-50%, -50%) scale(1);
        }
        button {
            width: 100%; padding: 0.9rem 1rem; background: var(--accent);
            color: #fff; font-weight: 600; font-size: 1rem; border: none;
            border-radius: 14px; cursor: pointer; transition: all 0.2s;
            margin-top: 1rem; backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            box-shadow: 0 4px 16px rgba(10, 132, 255, 0.4);
            position: relative; z-index: 1;
        }
        button:hover { background: #2a93ff; box-shadow: 0 6px 24px rgba(10, 132, 255, 0.6); transform: translateY(-1px); }
        button:active { transform: translateY(0); }
        button:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
        .result-box {
            background: rgba(255, 255, 255, 0.05); border-radius: 14px;
            padding: 1.2rem; margin-top: 1.2rem; word-break: break-all;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem; min-height: 60px;
            border: 1px solid rgba(255, 255, 255, 0.1); white-space: pre-wrap;
            max-height: 400px; overflow-y: auto; position: relative; z-index: 1;
        }
        .result-box.loading { color: var(--accent); display: flex; align-items: center; justify-content: center; gap: 8px; }
        .result-box.loading::before {
            content: ''; width: 18px; height: 18px;
            border: 2px solid rgba(255,255,255,0.2); border-top-color: var(--accent);
            border-radius: 50%; animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .result-box.error { color: #FF453A; border-color: rgba(255,69,58,0.3); }
        .advanced-section {
            margin: 1.2rem 0; padding: 1.2rem;
            background: rgba(255, 255, 255, 0.04); border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1); display: none;
            position: relative; z-index: 1;
        }
        .advanced-section.show { display: block; }
        .footer {
            text-align: center; margin-top: 1.5rem; color: var(--text-secondary);
            font-size: 0.75rem; display: flex; align-items: center; justify-content: center;
            gap: 6px; position: relative; z-index: 1;
        }
        .footer a { color: var(--text-secondary); text-decoration: none; display: inline-flex; align-items: center; gap: 4px; }
        .footer a:hover { color: var(--accent); }
        .global-section {
            margin: 1rem 0; padding: 1rem; background: rgba(255, 255, 255, 0.04);
            border-radius: 14px; border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative; z-index: 1;
        }
        .request-url-box {
            margin-top: 1rem; padding: 0.8rem 1rem;
            background: rgba(10, 132, 255, 0.1);
            border: 1px solid rgba(10, 132, 255, 0.3); border-radius: 12px;
            display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem;
            position: relative; z-index: 1; overflow-x: auto; white-space: nowrap;
        }
        .request-url-box span { flex-shrink: 0; }
        .request-url-box code {
            background: transparent; color: var(--accent); flex: 1;
            overflow-x: auto; white-space: nowrap; display: inline-block; padding-right: 0.5rem;
        }
        .copy-btn {
            padding: 0.4rem 1rem; background: var(--accent); border: none;
            border-radius: 8px; color: white; font-size: 0.8rem; cursor: pointer;
            white-space: nowrap; box-shadow: none; margin: 0; width: auto; flex-shrink: 0;
        }
        .copy-btn:active { background: #2a93ff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><div class="logo">?</div><h1>DOH-ECH 查询测试</h1></div>
        <p class="subtitle">双上游竞速 · ECS 就近解析 · 增强规则</p>

        <div class="row">
            <div>
                <label for="domain">查询域名</label>
                <input type="text" id="domain" placeholder="输入域名，例如 twitter.com" value="twitter.com" autofocus style="margin-bottom:0">
            </div>
            <div>
                <label for="type">记录类型</label>
                <select id="type" style="margin-bottom:0">
                    <option value="A">A (IPv4)</option>
                    <option value="AAAA">AAAA (IPv6)</option>
                    <option value="HTTPS">HTTPS (ECH)</option>
                </select>
            </div>
        </div>

        <!-- HTTPS 增强参数 -->
        <div class="global-section">
            <div class="param-grid">
                <div>
                    <label>增强模式 <span class="badge badge-enhance">enhance</span></label>
                    <select id="enhance">
                        <option value="off">关闭</option>
                        <option value="rule">规则模式</option>
                        <option value="full">全局模式</option>
                    </select>
                </div>
                <div>
                    <label>规则 <span class="badge badge-enhance">rules</span></label>
                    <input type="text" id="rules" placeholder="*.reddit.com:ip1,ip2-noA-noAAAA">
                </div>
            </div>
        </div>

        <!-- 全局设置 -->
        <div class="global-section">
            <div class="param-grid">
                <div>
                    <label>ALPN 列表 <span class="badge">alpn</span></label>
                    <input type="text" id="alpn" placeholder="h3,h2" value="h3,h2">
                </div>
                <div>
                    <label>ECS <span class="badge">clientIp</span></label>
                    <input type="text" id="clientIp" placeholder="1.2.4.8" value="">
                </div>
                <div>
                    <label>ECH 来源 <span class="badge">ech</span></label>
                    <input type="text" id="ech" placeholder="cloudflare-ech.com">
                </div>
                <div class="toggle-row" style="margin-top: 0.5rem;">
                    <label class="checkbox-container">
                        <input type="checkbox" id="shuffle" checked>
                        <span class="checkmark"></span>
                        <span>随机乱序 IP</span>
                    </label>
                </div>
            </div>
        </div>

        <button id="queryBtn" onclick="doQuery()">
            <span id="btnText">? 开始查询</span>
        </button>

        <div id="result" class="result-box" style="display: none;"></div>
        <div class="footer">
            <span>DOH-ECH · Cloudflare Pages · </span>
            <a href="https://github.com/rosenii/doh-ech" target="_blank" rel="noopener noreferrer">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                GitHub
            </a>
        </div>
    </div>
    <script>
        async function doQuery() {
            const domain = document.getElementById('domain').value.trim();
            const type = document.getElementById('type').value;
            const btn = document.getElementById('queryBtn');
            const btnText = document.getElementById('btnText');
            const resultDiv = document.getElementById('result');

            if (!domain) {
                resultDiv.innerHTML = '<span class="error">请输入域名</span>';
                resultDiv.className = 'result-box error';
                resultDiv.style.display = 'block';
                return;
            }

            const params = new URLSearchParams();
            params.set('domain', domain);
            params.set('type', type);

            const enhance = document.getElementById('enhance').value;
            if (enhance !== 'off') params.set('enhance', enhance);

            const rules = document.getElementById('rules').value.trim();
            if (rules) params.set('rules', rules);

            const alpn = document.getElementById('alpn').value.trim();
            if (alpn) params.set('alpn', alpn);

            const clientIp = document.getElementById('clientIp').value.trim();
            if (clientIp) params.set('clientIp', clientIp);

            const ech = document.getElementById('ech').value.trim();
            if (ech) params.set('ech', ech);

            const shuffleChecked = document.getElementById('shuffle').checked;
            if (!shuffleChecked) params.set('shuffle', 'false');

            btn.disabled = true;
            btnText.textContent = '? 查询中...';
            resultDiv.className = 'result-box loading';
            resultDiv.textContent = '';
            resultDiv.style.display = 'block';
            try {
                const res = await fetch('/api/query?' + params.toString());
                const data = await res.json();
                if (data.error) {
                    resultDiv.textContent = '错误：' + data.error;
                    resultDiv.className = 'result-box error';
                } else {
                    resultDiv.textContent = JSON.stringify(data, null, 2);
                    resultDiv.className = 'result-box';
                }
            } catch (err) {
                resultDiv.textContent = '网络错误：' + err.message;
                resultDiv.className = 'result-box error';
            } finally {
                btn.disabled = false;
                btnText.textContent = '? 开始查询';
            }
        }
    </script>
</body>
</html>`;
}
