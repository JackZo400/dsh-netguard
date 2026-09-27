/**
 * 纯逻辑自检 —— **完全离线**：不查 DNS、不发请求、不装包、不碰任何私人目录。
 *   node test/selftest.mjs
 *
 * 覆盖的是这张表（每一条都对应一个真实的 SSRF 形态）：
 *
 *   A. IPv4 字面量的各种写法        127.0.0.1 / 127.1 / 2130706433 / 0177.0.0.1 / 0x7f.1 …
 *   B. IPv6 与"包着 IPv4 的 IPv6"   ::1 / fc00::/7 / fe80::/10 / ::ffff:127.0.0.1 / 6to4 / NAT64
 *   C. 主机名                        localhost / *.internal / 单段名字 / 畸形 IP 写法
 *   D. URL 层                        协议 / 凭据 / 端口 / 域名解析到内网（含"一条公网一条内网"）
 *   E. 重定向                        302 → 内网 / 相对跳转 / 环 / 跳数上限 / 协议降级
 *   F. 大小上限                      Content-Length 预检、流式读到一半停、截断 vs 报错
 *   G. 超时与中止                    整条链共用一个预算、调用方中止
 *
 * 所有断言都"真的会失败"：把 src/ 里任何一条防护删掉，这个脚本都会红。
 */
import { classifyIp, ipv4ToString, isPublicIp, normalizeHost, parseIpv4, parseIpv6 } from '../src/ip.js'
import { assertPublicUrl, checkHost, checkHostSyntax, isPublicHost } from '../src/guard.js'
import { fetchPublic, fetchPublicBytes } from '../src/fetch.js'
import { isBlocked, NetguardError } from '../src/errors.js'
import { mergeConfig } from '../src/config.js'

let pass = 0
const fails = []
function ok(label, cond, extra) {
  if (cond) pass++
  else fails.push(label + (extra ? '  → ' + extra : ''))
}
function eq(label, got, want) {
  ok(label, got === want, `got=${JSON.stringify(got)} want=${JSON.stringify(want)}`)
}
/** 跑一段应当抛错的代码，返回 error.code。 */
async function codeOf(fn) {
  try {
    await fn()
    return 'NO_ERROR'
  } catch (error) {
    return error?.code || `NO_CODE(${error?.message})`
  }
}
async function messageOf(fn) {
  try {
    await fn()
    return ''
  } catch (error) {
    return String(error?.message || error)
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const config = mergeConfig({ timeoutMs: 3000, maxBytes: 1024 * 1024 })

// ===========================================================================
// A. IPv4：私网/保留 + 各种变形写法
// ===========================================================================

/** 必须全部拒掉的 IPv4 写法。第二个值是期望的原因（只挑几个断言，全断言太脆）。 */
const BAD_V4 = [
  ['127.0.0.1', 'LOOPBACK'],
  ['127.1', 'LOOPBACK'], // 经典简写 = 127.0.0.1
  ['127.0.1', 'LOOPBACK'],
  ['127.255.255.255', 'LOOPBACK'],
  ['0.0.0.0', 'UNSPECIFIED'],
  ['0', 'UNSPECIFIED'],
  ['0.1.2.3', 'UNSPECIFIED'],
  ['10.0.0.1', 'PRIVATE'],
  ['10.255.255.254', 'PRIVATE'],
  ['172.16.0.1', 'PRIVATE'],
  ['172.31.255.255', 'PRIVATE'],
  ['192.168.0.1', 'PRIVATE'],
  ['192.168.1.1', 'PRIVATE'],
  ['169.254.169.254', 'METADATA'], // 云元数据，SSRF 的头号目标
  ['169.254.0.1', 'LINK_LOCAL'],
  ['100.64.0.1', 'CGNAT'],
  ['100.100.100.200', 'METADATA'],
  ['192.0.0.1', 'RESERVED'],
  ['192.0.2.5', 'DOCUMENTATION'],
  ['198.18.0.1', 'BENCHMARK'],
  ['198.51.100.7', 'DOCUMENTATION'],
  ['203.0.113.9', 'DOCUMENTATION'],
  ['192.88.99.1', 'TUNNEL'],
  ['224.0.0.1', 'MULTICAST'],
  ['239.255.255.250', 'MULTICAST'],
  ['240.0.0.1', 'RESERVED'],
  ['255.255.255.255', 'RESERVED'],
  // ↓ 变形：正则时代漏得最惨的一批
  ['2130706433', 'LOOPBACK'], // 十进制整数
  ['0x7f000001', 'LOOPBACK'], // 十六进制整数
  ['017700000001', 'LOOPBACK'], // 八进制整数
  ['0177.0.0.1', 'LOOPBACK'], // 八进制段
  ['0x7f.0.0.1', 'LOOPBACK'], // 十六进制段
  ['0x7f.1', 'LOOPBACK'], // 两种变形混着写
  ['127.0.0.1', 'LOOPBACK'],
]
for (const [ip, reason] of BAD_V4) {
  const c = classifyIp(ip)
  ok(`拒 IPv4 ${ip}`, c.isIp === true && c.public === false, JSON.stringify(c))
  ok(`  原因对得上 ${ip}`, c.reason === reason, `got=${c.reason} want=${reason}`)
}
eq('变形写法解析出的数值就是 127.0.0.1', ipv4ToString(parseIpv4('0x7f.1')), '127.0.0.1')
eq('八进制写法解析出的数值就是 127.0.0.1', ipv4ToString(parseIpv4('0177.0.0.1')), '127.0.0.1')
eq('十进制整数写法解析出的数值就是 127.0.0.1', ipv4ToString(parseIpv4('2130706433')), '127.0.0.1')
eq('127.1 不是 127.0.1.0（inet_aton 的低位语义）', ipv4ToString(parseIpv4('127.1')), '127.0.0.1')
eq('10.1 也不是 10.0.1.0', ipv4ToString(parseIpv4('10.1')), '10.0.0.1')
eq('0178 这种非法八进制解不出来', parseIpv4('0178.0.0.1'), null)
eq('1.2.3.4.5 解不出来', parseIpv4('1.2.3.4.5'), null)

const GOOD_V4 = ['93.184.216.34', '1.1.1.1', '8.8.8.8', '11.0.0.1', '126.255.255.255', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1', '192.167.1.1']
for (const ip of GOOD_V4) {
  const c = classifyIp(ip)
  ok(`放行公网 IPv4 ${ip}`, c.isIp === true && c.public === true, JSON.stringify(c))
}

// ===========================================================================
// B. IPv6：回环 / ULA / 链路本地 / 包着 IPv4 的壳
// ===========================================================================

const BAD_V6 = [
  ['::1', 'LOOPBACK'],
  ['::', 'UNSPECIFIED'],
  ['fc00::1', 'PRIVATE'], // ULA
  ['fd12:3456:789a::1', 'PRIVATE'],
  ['fe80::1', 'LINK_LOCAL'],
  ['febf:ffff::1', 'LINK_LOCAL'],
  ['fec0::1', 'RESERVED'], // 废弃的站点本地
  ['ff02::1', 'MULTICAST'],
  ['2001:db8::1', 'DOCUMENTATION'],
  ['::ffff:127.0.0.1', 'LOOPBACK'], // IPv4-mapped：内核当 IPv4 用
  ['::ffff:7f00:1', 'LOOPBACK'], // 同上，纯十六进制写法
  ['::ffff:10.0.0.1', 'PRIVATE'],
  ['::ffff:169.254.169.254', 'METADATA'],
  ['::ffff:192.168.1.1', 'PRIVATE'],
  ['::127.0.0.1', 'LOOPBACK'], // IPv4-compatible（已废弃但照样连得上）
  ['2002:7f00:1::', 'TUNNEL'], // 6to4 里塞着 127.0.0.1
  ['2002:a00:1::', 'TUNNEL'], // 6to4 里塞着 10.0.0.1
  ['2001:0:0:0:0:0:0:1', 'TUNNEL'], // Teredo
  ['64:ff9b::7f00:1', 'LOOPBACK'], // NAT64 里塞着 127.0.0.1
]
for (const [ip, reason] of BAD_V6) {
  const c = classifyIp(ip)
  ok(`拒 IPv6 ${ip}`, c.isIp === true && c.public === false, JSON.stringify(c))
  ok(`  原因对得上 ${ip}`, c.reason === reason, `got=${c.reason} want=${reason}`)
}
const GOOD_V6 = ['2606:4700:4700::1111', '2001:4860:4860::8888', '2a00:1450:4001:80e::200e', '::ffff:93.184.216.34']
for (const ip of GOOD_V6) {
  ok(`放行公网 IPv6 ${ip}`, isPublicIp(ip) === true, JSON.stringify(classifyIp(ip)))
}
eq('mapped 地址会把里面的 IPv4 报出来（错误文案更有用）', classifyIp('::ffff:10.1.2.3').mapped, '10.1.2.3')
ok('带 zone id 的地址直接判为不合法（拒绝）', classifyIp('fe80::1%eth0').public === false)
eq('8 段非法写法不当合法处理', parseIpv6('1:2:3:4:5:6:7:8::'), null)
eq('缺段的写法不合法', parseIpv6('1:2:3:4:5:6:7'), null)

// ===========================================================================
// C. 主机名（不查 DNS 的那一层）
// ===========================================================================

const BAD_NAMES = [
  'localhost',
  'localhost.',
  'LOCALHOST',
  'foo.localhost',
  'a.local',
  'db.internal',
  'metadata.google.internal',
  'printer.lan',
  'x.intranet',
  'box.corp',
  'nas.home.arpa',
  'example.localdomain',
  'intranet', // 单段
  'redis',
  'metadata',
  '999.1.1.1', // 想写成 IP 却写坏了
  '1.2.3.4.5',
  '0178.0.0.1',
  '1234.5',
]
for (const host of BAD_NAMES) ok(`拒主机名 ${host}`, isPublicHost(host, config) === false, JSON.stringify(checkHostSyntax(host, config)))
for (const host of ['example.com', 'demo.example.org', 'cdn.example.net', 'xn--fsqu00a.xn--0zwm56d'])
  ok(`放行域名写法 ${host}`, isPublicHost(host, config) === true, JSON.stringify(checkHostSyntax(host, config)))

eq('末尾的点会被归一化掉（localhost. 也是 localhost）', normalizeHost('LOCALHOST.'), 'localhost')
eq('方括号会被剥掉', normalizeHost('[::1]'), '::1')
eq('国际化域名转成 punycode', normalizeHost('例子.测试'), 'xn--fsqu00a.xn--0zwm56d')
eq('空主机名给得出原因', checkHostSyntax('', config).reason, 'EMPTY_HOST')
eq('畸形 IP 写法给的是 BAD_IP', checkHostSyntax('1.2.3.4.5', config).reason, 'BAD_IP')
eq('单段名字给的是 SINGLE_LABEL', checkHostSyntax('redis', config).reason, 'SINGLE_LABEL')
eq('allowSingleLabel 打开后单段名字不再被这一层挡', checkHostSyntax('redis', mergeConfig({ allowSingleLabel: true })).reason, null)
eq('isPublicHost 对公网 IP 字面量返回 true', isPublicHost('93.184.216.34', config), true)
eq('isPublicHost 对内网 IP 字面量返回 false', isPublicHost('10.0.0.1', config), false)

// ===========================================================================
// D. URL 层（含"域名解析到内网"）
// ===========================================================================

const lookupCalls = []
const HOST_TABLE = {
  'example.com': ['93.184.216.34'],
  'dual.example.org': ['93.184.216.34', '2606:4700:4700::1111'],
  'to-private.example.com': ['10.1.2.3'],
  'to-loopback.example.com': ['127.0.0.1'],
  'to-mapped.example.com': ['::ffff:10.0.0.1'],
  'to-ula.example.com': ['fd00::1'],
  'to-linklocal.example.com': ['fe80::1'],
  'to-metadata.example.com': ['169.254.169.254'],
  'mixed.example.com': ['93.184.216.34', '192.168.1.10'], // 一条公网一条内网
  'garbage.example.com': ['not-an-ip'],
  'empty.example.com': [],
}
const resolver = async (host) => {
  lookupCalls.push(host)
  const rows = HOST_TABLE[host]
  if (!rows) {
    const error = new Error('queryA ENOTFOUND ' + host)
    error.code = 'ENOTFOUND'
    throw error
  }
  return rows.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }))
}
const urlCase = (raw, extra) => assertPublicUrl(raw, { config: mergeConfig(extra ? { ...config, ...extra } : config), resolver })

// D1. 协议
for (const bad of ['file:///etc/passwd', 'gopher://example.com/', 'ftp://example.com/x', 'data:text/plain,hi', 'javascript:alert(1)', 'ws://example.com/'])
  eq(`拒协议 ${bad.split(':')[0]}:`, await codeOf(() => urlCase(bad)), 'BAD_PROTOCOL')
eq('不是完整 URL（没有协议头）', await codeOf(() => urlCase('example.com/x')), 'BAD_URL')
eq('空字符串', await codeOf(() => urlCase('')), 'BAD_URL')
eq('https 照常放行', await codeOf(() => urlCase('https://example.com/a.png')), 'NO_ERROR')

// D2. 凭据与端口
eq('URL 里带 user:pass 一律拒', await codeOf(() => urlCase('http://user:pass@example.com/')), 'BAD_CREDENTIALS')
eq(
  'http://某域名@内网IP/ 这种伪装：先被凭据规则拦下',
  await codeOf(() => urlCase('http://trusted.example.com@127.0.0.1:8080/')),
  'BAD_CREDENTIALS',
)
eq(
  '即使放开凭据，@ 后面那个内网 IP 一样被地址判定拦下（两层都拦）',
  await codeOf(() => urlCase('http://trusted.example.com@127.0.0.1:8080/', { allowUrlCredentials: true })),
  'PRIVATE_ADDRESS',
)
eq('默认端口黑名单里的 6379 被拒', await codeOf(() => urlCase('http://example.com:6379/')), 'BLOCKED_PORT')
eq('端口 0 不合法', await codeOf(() => urlCase('http://example.com:0/')), 'BAD_PORT')
eq('8080 不在黑名单里，正常放行', await codeOf(() => urlCase('http://example.com:8080/')), 'NO_ERROR')

// D3. 直连内网：一次 DNS 都不查
lookupCalls.length = 0
for (const bad of ['http://127.0.0.1:5099/api/secret', 'http://127.1/', 'http://2130706433/', 'http://0177.0.0.1/', 'http://0x7f000001/', 'http://0.0.0.0/', 'http://192.168.1.1/', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[fd00::1]/', 'http://10.0.0.5/'])
  eq(`拒直连内网 ${bad}`, await codeOf(() => urlCase(bad)), 'PRIVATE_ADDRESS')
eq('直连内网地址时一次 DNS 都没查（不给出侧信道）', lookupCalls.length, 0)

// D4. 域名解析到内网
eq('域名解析到 10.x → 拒', await codeOf(() => urlCase('http://to-private.example.com/')), 'DNS_PRIVATE')
eq('域名解析到 127.0.0.1（DNS rebinding 常见形态）→ 拒', await codeOf(() => urlCase('http://to-loopback.example.com/')), 'DNS_PRIVATE')
eq('域名解析到 IPv4-mapped 内网 → 拒', await codeOf(() => urlCase('http://to-mapped.example.com/')), 'DNS_PRIVATE')
eq('域名解析到 ULA → 拒', await codeOf(() => urlCase('http://to-ula.example.com/')), 'DNS_PRIVATE')
eq('域名解析到 fe80::/10 → 拒', await codeOf(() => urlCase('http://to-linklocal.example.com/')), 'DNS_PRIVATE')
eq('域名解析到元数据地址 → 拒', await codeOf(() => urlCase('http://to-metadata.example.com/')), 'DNS_PRIVATE')
eq('一条公网一条内网也拒（不取第一条）', await codeOf(() => urlCase('http://mixed.example.com/')), 'DNS_PRIVATE')
eq('解析出垃圾结果 → 拒', await codeOf(() => urlCase('http://garbage.example.com/')), 'DNS_PRIVATE')
eq('解析不出地址 → 拒（不是放行）', await codeOf(() => urlCase('http://empty.example.com/')), 'DNS_FAILED')
eq('解析抛错 → 拒（不是放行）', await codeOf(() => urlCase('http://nx.example.com/')), 'DNS_FAILED')
eq('正常公网域名放行', await codeOf(() => urlCase('http://example.com/a.png')), 'NO_ERROR')
eq('双栈公网域名放行', await codeOf(() => urlCase('https://dual.example.org/')), 'NO_ERROR')
ok('错误文案里带着主机名和原因', /to-loopback\.example\.com/.test(await messageOf(() => urlCase('http://to-loopback.example.com/'))))
ok('错误是 NetguardError 且算"被安全策略挡"', (await (async () => {
  try {
    await urlCase('http://10.0.0.1/')
    return false
  } catch (error) {
    return error instanceof NetguardError && isBlocked(error)
  }
})()))

const checked = await checkHost('dual.example.org', { config, resolver })
eq('checkHost 把解析出来的地址都带回来', checked.addresses.join(','), '93.184.216.34,2606:4700:4700::1111')
eq('checkHost 对字面量 IP 不查 DNS', (await checkHost('93.184.216.34', { config, resolver })).addresses.join(','), '93.184.216.34')

// ===========================================================================
// E~G. 假 fetch：重定向、大小上限、超时
// ===========================================================================

/** 假的 fetch：按 URL 查表，记下每一次真实被请求的地址。 */
function fakeFetch(routes) {
  const calls = []
  const fn = async (url, init) => {
    calls.push(String(url))
    if (init?.signal?.aborted) throw init.signal.reason ?? new DOMException('aborted', 'AbortError')
    const route = routes[String(url)]
    if (route === undefined) throw new Error('假 fetch 没有这条路由：' + url)
    return typeof route === 'function' ? await route(url, init) : route
  }
  fn.calls = calls
  return fn
}
const text = (body, headers = {}) => new Response(body, { status: 200, headers: { 'content-type': 'text/plain', ...headers } })
const redirectTo = (location, status = 302) => new Response(null, { status, headers: { location } })
/** 永不 resolve 的响应，只在被 abort 时 reject —— 用来测超时。 */
const hang = (url, init) =>
  new Promise((_resolve, reject) => {
    const signal = init?.signal
    const bail = () => reject(signal?.reason ?? new DOMException('aborted', 'AbortError'))
    if (!signal) return
    if (signal.aborted) bail()
    else signal.addEventListener('abort', bail, { once: true })
  })
/** 造一个分块流：每块 8 字节，最多 n 块，记录被拉取/取消的次数。 */
function chunkStream(n, size = 8) {
  let pulled = 0
  let cancelled = false
  const stream = new ReadableStream({
    pull(controller) {
      if (pulled >= n) return controller.close()
      pulled++
      controller.enqueue(new Uint8Array(size).fill(0x41))
    },
    cancel() {
      cancelled = true
    },
  })
  return { stream, pulls: () => pulled, cancelled: () => cancelled }
}

const F = 'http://example.com'

// ---- E. 重定向 -------------------------------------------------------------
{
  // 最关键的一条：302 之后那个内网地址，**一次都不许被请求**
  const fetchImpl = fakeFetch({
    [`${F}/to-loopback`]: () => redirectTo('http://127.0.0.1:5099/api/secret'),
    [`${F}/to-metadata`]: () => redirectTo('http://169.254.169.254/latest/meta-data/iam/security-credentials/'),
    [`${F}/to-private-host`]: () => redirectTo('http://to-private.example.com/'),
    [`${F}/to-file`]: () => redirectTo('file:///etc/passwd'),
    [`${F}/to-port`]: () => redirectTo('http://example.com:6379/'),
    [`${F}/to-noloc`]: () => new Response(null, { status: 302 }),
    [`${F}/loop-a`]: () => redirectTo(`${F}/loop-b`),
    [`${F}/loop-b`]: () => redirectTo(`${F}/loop-a`),
    [`${F}/rel`]: () => redirectTo('/target'),
    [`${F}/target`]: () => text('到了'),
    [`${F}/long1`]: () => redirectTo(`${F}/long2`),
    [`${F}/long2`]: () => redirectTo(`${F}/long3`),
    [`${F}/long3`]: () => redirectTo(`${F}/long4`),
    [`${F}/long4`]: () => redirectTo(`${F}/long5`),
    [`${F}/long5`]: () => text('不该到这'),
    [`${F}/gone`]: () => new Response('nope', { status: 404 }),
    [`${F}/boom`]: () => new Response('nope', { status: 500 }),
    [`${F}/ok`]: () => text('hello netguard'),
  })
  const run = (path, extra) => fetchPublic(`${F}${path}`, { config: mergeConfig({ ...config, ...extra }), resolver, fetch: fetchImpl })

  eq('302 跳到 127.0.0.1 → 拒', await codeOf(() => run('/to-loopback')), 'PRIVATE_ADDRESS')
  eq('302 跳到内网时，内网那一次**没有被请求过**（只请求了公网那一跳）', fetchImpl.calls.length, 1)
  fetchImpl.calls.length = 0
  eq('302 跳元数据地址（经典 SSRF）→ 拒', await codeOf(() => run('/to-metadata')), 'PRIVATE_ADDRESS')
  eq('元数据地址也没被请求过', fetchImpl.calls.length, 1)
  fetchImpl.calls.length = 0
  eq('302 跳到一个解析进内网的域名 → 拒（每一跳都重新查 DNS）', await codeOf(() => run('/to-private-host')), 'DNS_PRIVATE')
  eq('内网域名也没被请求', fetchImpl.calls.length, 1)
  fetchImpl.calls.length = 0
  eq('302 跳到 file:// → 拒（协议检查在每一跳都生效）', await codeOf(() => run('/to-file')), 'BAD_PROTOCOL')
  eq('302 跳到黑名单端口 → 拒', await codeOf(() => run('/to-port')), 'BLOCKED_PORT')
  eq('302 没有 Location → 拒', await codeOf(() => run('/to-noloc')), 'BAD_REDIRECT')
  eq('重定向成环 → 拒', await codeOf(() => run('/loop-a')), 'REDIRECT_LOOP')
  eq('跳数超过上限 → 拒', await codeOf(() => run('/long1')), 'TOO_MANY_REDIRECTS')
  eq('关掉重定向后 302 直接拒', await codeOf(() => run('/rel', { allowRedirects: false })), 'REDIRECT_DISABLED')

  const followed = await run('/rel')
  eq('跟随相对路径跳转（Location 按当前地址补全）', followed.finalUrl, `${F}/target`)
  eq('跟了几跳能被数出来', followed.redirects, 1)
  eq('内容拿到了', followed.bytes.toString(), '到了')
  eq('hops 记着走过的地址', followed.hops.join(' → '), `${F}/rel → ${F}/target`)

  eq('404 → HTTP_ERROR', await codeOf(() => run('/gone')), 'HTTP_ERROR')
  eq('500 → HTTP_ERROR', await codeOf(() => run('/boom')), 'HTTP_ERROR')
  const good = await run('/ok')
  eq('正常响应能拿到正文', good.bytes.toString(), 'hello netguard')
  eq('带回了 content-type', good.contentType, 'text/plain')
  eq('status 是 200', good.status, 200)
}

// ---- F. 大小上限 -----------------------------------------------------------
{
  // 每次请求都要造一条新的流（流是一次性的，不能复用）
  const streams = []
  const newBig = () => {
    const s = chunkStream(500) // 500 * 8 = 4000 字节
    streams.push(s)
    return s
  }
  const fetchImpl = fakeFetch({
    [`${F}/stream`]: () => new Response(newBig().stream, { status: 200, headers: { 'content-type': 'application/octet-stream' } }),
    [`${F}/declared`]: () => text('x'.repeat(100), { 'content-length': '999999' }),
    [`${F}/exact`]: () => text('y'.repeat(100)),
    [`${F}/small`]: () => text('z'.repeat(10)),
  })
  const run = (path, extra) => fetchPublic(`${F}${path}`, { config: mergeConfig({ ...config, ...extra }), resolver, fetch: fetchImpl })

  eq('流式内容超上限 → 报错', await codeOf(() => run('/stream', { maxBytes: 100 })), 'TOO_LARGE')
  ok('超上限时读流被主动取消（不是把整个流读完）', streams[0].cancelled() === true)
  ok('而且真的只读了一点点就停了', streams[0].pulls() <= 14, `pulls=${streams[0].pulls()}`)

  const trunc = await run('/stream', { maxBytes: 100, onOverflow: 'truncate' })
  eq('onOverflow=truncate 时字节数正好等于上限', trunc.bytes.length, 100)
  eq('并标明被截断过', trunc.truncated, true)
  ok('截断模式下同样是读到上限就停（不是读完再切）', streams[1].pulls() <= 14, `pulls=${streams[1].pulls()}`)
  ok('截断的那条流也被取消掉了，不再占着连接', streams[1].cancelled() === true)

  eq('Content-Length 就超了 → 直接不下载（报错）', await codeOf(() => run('/declared', { maxBytes: 50 })), 'TOO_LARGE')
  eq('正好等于上限不算超', (await run('/exact', { maxBytes: 100 })).truncated, false)
  eq('小于上限也不截断', (await run('/small', { maxBytes: 100 })).bytes.length, 10)

  // 没有流式 body 的响应（有些运行时/adapter 只给 arrayBuffer）：
  // 只能整块读下来再截，行为必须一致
  const noStream = (size) => ({
    status: 200,
    ok: true,
    headers: new Headers({ 'content-type': 'application/octet-stream' }),
    body: null,
    arrayBuffer: async () => new Uint8Array(size).fill(7).buffer,
  })
  const fetchNoStream = fakeFetch({ [`${F}/nostream`]: () => noStream(300) })
  const runNo = (extra) => fetchPublic(`${F}/nostream`, { config: mergeConfig({ ...config, ...extra }), resolver, fetch: fetchNoStream })
  eq('没有流式 body 时一样守得住上限', await codeOf(() => runNo({ maxBytes: 100 })), 'TOO_LARGE')
  eq('没有流式 body 时 truncate 一样只给到上限', (await runNo({ maxBytes: 100, onOverflow: 'truncate' })).bytes.length, 100)

  const empty = await fetchPublic(`${F}/ok`, { config, resolver, fetch: fakeFetch({ [`${F}/ok`]: () => new Response(null, { status: 200 }) }) })
  eq('空响应体不炸', empty.bytes.length, 0)
  ok('fetchPublicBytes 给的是 Buffer', Buffer.isBuffer(await fetchPublicBytes(`${F}/ok`, { config, resolver, fetch: fakeFetch({ [`${F}/ok`]: () => text('abc') }) })))
}

// ---- G. 超时 / 中止 --------------------------------------------------------
{
  const fetchImpl = fakeFetch({ [`${F}/hang`]: hang })
  // 注意 extra 要同时进 config 和 options —— 这是"配置能覆盖"和"单次调用能覆盖"两条路
  const run = (extra = {}) => fetchPublic(`${F}/hang`, { config: mergeConfig({ ...config, timeoutMs: 40, ...extra }), resolver, fetch: fetchImpl, ...extra })

  eq('挂住的请求会超时（不是一直等）', await codeOf(() => run({})), 'TIMEOUT')
  const msg = await messageOf(() => run({}))
  ok('超时错误是可读的人话', /超时/.test(msg) && /example\.com/.test(msg), msg)

  // 调用方自己的 AbortSignal
  const ac = new AbortController()
  ac.abort()
  eq('调用方已经中止过 → ABORTED（不是 TIMEOUT）', await codeOf(() => run({ timeoutMs: 5000, signal: ac.signal })), 'ABORTED')

  const ac2 = new AbortController()
  setTimeout(() => ac2.abort(), 20)
  eq('请求途中被中止 → ABORTED', await codeOf(() => run({ timeoutMs: 5000, signal: ac2.signal })), 'ABORTED')

  // 整条链共用一个时间预算：跳一次就花掉大半，第二跳不许再各拿一份
  const slowChain = fakeFetch({
    [`${F}/slow1`]: async () => {
      await sleep(30)
      return redirectTo(`${F}/slow2`)
    },
    [`${F}/slow2`]: hang,
  })
  const started = Date.now()
  const code = await codeOf(() => fetchPublic(`${F}/slow1`, { config: mergeConfig({ ...config, timeoutMs: 60 }), resolver, fetch: slowChain }))
  const elapsed = Date.now() - started
  eq('一串重定向共用同一个时间预算', code, 'TIMEOUT')
  ok('总耗时没有变成"每跳各一份"（60ms 的预算不该拖到 1 秒以上）', elapsed < 1000, `elapsed=${elapsed}ms`)
  ok('第一跳的等待也算进预算里了', elapsed >= 55, `elapsed=${elapsed}ms`)
}

// ===========================================================================
console.log(fails.length === 0 ? `\n全过：${pass} 条断言` : `\n挂了 ${fails.length} 项（共 ${pass + fails.length} 条断言）：\n  - ${fails.join('\n  - ')}`)
process.exit(fails.length === 0 ? 0 : 1)
