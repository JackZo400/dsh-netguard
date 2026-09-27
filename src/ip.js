/**
 * ip.js —— 地址判定的纯逻辑：**不碰网络、不碰配置、可单独测**。
 *
 * 为什么要自己写一份，而不是用 URL + 几个正则：
 * 1. 正则挡不住变形。`http://2130706433/`、`http://0177.0.0.1/`、`http://0x7f.1/`
 *    都是 `127.0.0.1`（inet_aton 的老语法，浏览器/Node 的 URL 都认），
 *    只写 /^127\./ 的话这三种全部漏过去。
 * 2. 黑名单天生漏项。原实现只列了 7 个私网段，`192.0.0.0/24`、`198.18.0.0/15`、
 *    `240.0.0.0/4`、多播段都不在里面。这里改成按 RFC 6890 的"特殊用途地址表"做**白名单式**判定：
 *    没被明确认定是公网可路由的，一律不放。
 * 3. IPv6 不能靠字符串前缀。`::ffff:127.0.0.1`（IPv4-mapped）、`2002:7f00:1::`（6to4 隧道）、
 *    `64:ff9b::7f00:1`（NAT64）都能把内网 IPv4 藏进一个"看起来是 IPv6"的地址里。
 *    必须先把地址**解成 16 个字节**，再按位看。
 *
 * 判定结果里的 reason 是给错误文案用的（也会被自检断言），不是给人猜的。
 */
import { domainToASCII } from 'node:url'

/** reason → 人话。错误文案统一从这里取，省得每个调用点自己编。 */
export const REASON_TEXT = {
  EMPTY: '地址是空的',
  BAD_IP: '这个写法像个 IP，但解析不出来（不猜，直接拒）',
  NOT_IP: '不是 IP 字面量',
  UNSPECIFIED: '未指定地址（0.0.0.0 / ::）—— 在很多系统里它等于"本机"',
  LOOPBACK: '回环地址',
  PRIVATE: '私有网段',
  LINK_LOCAL: '链路本地地址',
  CGNAT: '运营商级 NAT 网段（100.64/10）',
  METADATA: '云厂商的元数据地址（拿到它等于拿到临时凭据）',
  RESERVED: '保留段，公网不可路由',
  DOCUMENTATION: '文档示例段，公网不可路由',
  BENCHMARK: '基准测试段，公网不可路由',
  MULTICAST: '多播地址',
  TUNNEL: '隧道/转换地址（6to4、Teredo），能把内网 IPv4 藏在 IPv6 里',
  MAPPED: 'IPv4-mapped 的 IPv6 地址（按里面的 IPv4 判）',
}

/** reason → 人话，认不出来就原样返回。 */
export function describeReason(reason) {
  return REASON_TEXT[reason] || String(reason || '可疑地址')
}

// ---------------------------------------------------------------------------
// 主机名归一化
// ---------------------------------------------------------------------------

/**
 * 把主机名折成可判定的形式：
 *   '[::1]' → '::1'（URL 里的 IPv6 带方括号）
 *   'Example.COM.' → 'example.com'（大小写、末尾的点都是合法写法，`localhost.` 也得挡住）
 *   '例子.测试' → 'xn--fsqu00a.xn--0zwm56d'（国际化域名走 punycode，
 *                避免"看着不是 IP"的 Unicode 变形混过字符串比较）
 * 归一化失败（空、非 ASCII 又转不出来）返回空串，调用方按"不合法"处理。
 */
export function normalizeHost(raw) {
  let s = String(raw ?? '').trim().toLowerCase()
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  while (s.endsWith('.')) s = s.slice(0, -1)
  if (!s) return ''
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(s)) {
    const ascii = domainToASCII(s)
    s = ascii ? ascii.toLowerCase() : ''
  }
  return s
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/**
 * 解析点分段。老规矩（inet_aton）允许三种进制：
 *   十进制 `127` / 八进制 `0177` / 十六进制 `0x7f`
 * 非法（含 8 的八进制、空段、字母）返回 NaN。
 */
function parseV4Part(part) {
  if (/^0[xX][0-9a-fA-F]+$/.test(part)) return parseInt(part.slice(2), 16)
  if (/^0[0-7]*$/.test(part)) return parseInt(part.slice(1) || '0', 8) // '0' → 0，'0177' → 127
  if (/^[1-9][0-9]*$/.test(part)) return parseInt(part, 10)
  return NaN
}

/**
 * 把各种写法的 IPv4 字面量解成 32 位无符号整数；不像 IPv4 就返回 null。
 *
 * 覆盖 1~4 段的所有写法（这是变形的重灾区）：
 *   '127.0.0.1'      → 127.0.0.1
 *   '127.1'          → 127.0.0.1   （最后一段吃掉剩下的字节）
 *   '2130706433'     → 127.0.0.1   （整个 32 位写成一个数）
 *   '0177.0.0.1'     → 127.0.0.1   （八进制）
 *   '0x7f.1'         → 127.0.0.1   （十六进制）
 *   '0x7f000001'     → 127.0.0.1
 * 解析不出来的一律 null，由上层按"要么是域名、要么是坏 IP"处理 —— 绝不放过。
 */
export function parseIpv4(text) {
  const s = String(text ?? '').trim()
  if (!s || s.length > 64) return null
  if (!/^[0-9a-fA-FxX.]+$/.test(s)) return null // 快速排除正常域名（里面有 g-z 之类）
  const parts = s.split('.')
  if (parts.length > 4) return null
  const nums = []
  for (const p of parts) {
    if (!p) return null
    const n = parseV4Part(p)
    if (!Number.isSafeInteger(n) || n < 0) return null
    nums.push(n)
  }
  // 单段：整个 32 位
  if (nums.length === 1) return nums[0] > 0xffffffff ? null : nums[0] >>> 0
  // 多段：前 n-1 段各占一个字节，最后一段直接吃掉剩下的 8*(5-n) 个低位
  // （`127.1` → 127<<24 | 1 = 127.0.0.1；`10.1` → 10.0.0.1 —— 经典写法，别按十进制位移理解）
  for (let i = 0; i < nums.length - 1; i++) if (nums[i] > 0xff) return null
  const last = nums[nums.length - 1]
  if (last > 2 ** (8 * (5 - nums.length)) - 1) return null
  let value = last
  for (let i = 0; i < nums.length - 1; i++) value += nums[i] * 256 ** (3 - i)
  return value >>> 0
}

/** 32 位整数 → 点分十进制（只用于错误文案和断言）。 */
export function ipv4ToString(value) {
  const v = value >>> 0
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff].join('.')
}

/** [四段, 掩码位数, reason]，顺序有意义：更具体的块必须排在它所属的大块前面。 */
const V4_BLOCKS = [
  [[169, 254, 169, 254], 32, 'METADATA'], // AWS / GCP / Azure / DigitalOcean 的 169.254.169.254
  [[100, 100, 100, 200], 32, 'METADATA'], // 另一家云的内网元数据
  [[192, 0, 0, 192], 32, 'METADATA'], // Oracle Cloud
  [[0, 0, 0, 0], 8, 'UNSPECIFIED'], // 0.0.0.0/8：在不少系统上 0.0.0.0 会被当成本机
  [[10, 0, 0, 0], 8, 'PRIVATE'],
  [[100, 64, 0, 0], 10, 'CGNAT'], // 100.64/10：家里/机房的运营商 NAT，也不是公网
  [[127, 0, 0, 0], 8, 'LOOPBACK'],
  [[169, 254, 0, 0], 16, 'LINK_LOCAL'],
  [[172, 16, 0, 0], 12, 'PRIVATE'],
  [[192, 0, 0, 0], 24, 'RESERVED'], // IETF 协议专用（含 192.0.0.0/29、NAT64 发现地址）
  [[192, 0, 2, 0], 24, 'DOCUMENTATION'], // TEST-NET-1
  [[192, 88, 99, 0], 24, 'TUNNEL'], // 6to4 中继 anycast
  [[192, 168, 0, 0], 16, 'PRIVATE'],
  [[198, 18, 0, 0], 15, 'BENCHMARK'],
  [[198, 51, 100, 0], 24, 'DOCUMENTATION'], // TEST-NET-2
  [[203, 0, 113, 0], 24, 'DOCUMENTATION'], // TEST-NET-3
  [[224, 0, 0, 0], 4, 'MULTICAST'],
  [[240, 0, 0, 0], 4, 'RESERVED'], // 含 255.255.255.255 广播
]

const v4Base = ([a, b, c, d]) => (((a << 24) | (b << 16) | (c << 8) | d) >>> 0)

/** 判一个 32 位 IPv4：不是公网可路由的就返回 reason，是公网返回 null。 */
export function classifyIpv4(value) {
  const v = value >>> 0
  for (const [bytes, bits, reason] of V4_BLOCKS) {
    const base = v4Base(bytes)
    const shift = 32 - bits
    if (shift === 0 ? v === base : v >>> shift === base >>> shift) return reason
  }
  return null
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/**
 * 解 IPv6 字面量 → 16 字节；不合法返回 null。
 * 支持 `::` 压缩、末尾内嵌 IPv4（`::ffff:127.0.0.1`）、以及纯十六进制写法。
 * 带 zone id（`fe80::1%eth0`）的一律拒绝：多一个语法维度就多一类绕过，
 * 而 zone 只在内网里有意义，公网抓取永远用不上。
 */
export function parseIpv6(text) {
  let s = String(text ?? '').trim().toLowerCase()
  if (!s || s.includes('%')) return null
  // 末尾内嵌 IPv4：先折成两段十六进制，后面只剩一种语法要处理。
  const m = /^(.*):(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s)
  if (m) {
    const v4 = parseIpv4(m[2])
    if (v4 === null) return null
    s = `${m[1]}:${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : []
  const missing = 8 - head.length - tail.length
  // 有 '::' 时必须真的压缩掉至少一段（`1:2:3:4:5:6:7:8::` 是非法写法，不当 8 段处理）
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null
  const groups = [...head, ...new Array(Math.max(0, missing)).fill('0'), ...tail]
  if (groups.length !== 8) return null
  const bytes = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    const g = groups[i]
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null
    const n = parseInt(g, 16)
    bytes[i * 2] = (n >> 8) & 0xff
    bytes[i * 2 + 1] = n & 0xff
  }
  return bytes
}

const allZero = (arr) => arr.every((b) => b === 0)
const bytesToV4 = (b, i) => (((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0)

/**
 * 判 16 字节 IPv6。
 * 返回 `{ reason, mappedV4 }`：reason 为 null = 公网；
 * reason 为 'MAPPED' 时表示"这其实是包着 IPv4 的壳"，要按 mappedV4 再判一次。
 */
export function classifyIpv6(bytes) {
  const b = bytes
  // ::ffff:a.b.c.d —— IPv4-mapped。内核会把这种地址当 IPv4 用（连的就是那个 IPv4），
  // 所以字符串上"看起来是 IPv6"毫无意义，必须拆出来按 IPv4 判。
  if (allZero(b.subarray(0, 10)) && b[10] === 0xff && b[11] === 0xff) {
    return { reason: 'MAPPED', mappedV4: bytesToV4(b, 12) }
  }
  // ::a.b.c.d（IPv4-compatible，已废弃但照样能连）—— 同样拆出来判
  if (allZero(b.subarray(0, 12)) && !(allZero(b) || (allZero(b.subarray(0, 15)) && b[15] === 1))) {
    return { reason: 'MAPPED', mappedV4: bytesToV4(b, 12) }
  }
  if (allZero(b)) return { reason: 'UNSPECIFIED' }
  if (allZero(b.subarray(0, 15)) && b[15] === 1) return { reason: 'LOOPBACK' }
  // 2002::/16 —— 6to4：把 IPv4 塞在第 3~6 字节。`http://[2002:7f00:1::]/` 就是 127.0.0.1。
  if (b[0] === 0x20 && b[1] === 0x02) return { reason: 'TUNNEL' }
  // 2001:0000::/32 —— Teredo，同样是个能把流量导进内网的隧道
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return { reason: 'TUNNEL' }
  // 64:ff9b::/96 —— NAT64：最后 4 字节就是目标 IPv4
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
    return { reason: 'MAPPED', mappedV4: bytesToV4(b, 12) }
  }
  if ((b[0] & 0xfe) === 0xfc) return { reason: 'PRIVATE' } // fc00::/7 唯一本地地址
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return { reason: 'LINK_LOCAL' } // fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return { reason: 'RESERVED' } // fec0::/10 站点本地（废弃）
  if (b[0] === 0xff) return { reason: 'MULTICAST' } // ff00::/8
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return { reason: 'DOCUMENTATION' } // 2001:db8::/32
  if (b[0] === 0x01 && b[1] === 0x00 && allZero(b.subarray(2, 8))) return { reason: 'RESERVED' } // 100::/64 丢弃前缀
  // 只剩 2000::/3 是真正全球可路由的单播段。别的（含各种没列到的特殊段）一律不放 ——
  // 这就是"白名单式"的意思：漏掉一条规则只会更严，不会更松。
  if ((b[0] & 0xe0) === 0x20) return { reason: null }
  return { reason: 'RESERVED' }
}

// ---------------------------------------------------------------------------
// 统一入口
// ---------------------------------------------------------------------------

/**
 * 判一个"可能是 IP、可能不是"的字符串。
 * @returns {{ isIp: boolean, family: 0|4|6, public: boolean, reason: string|null, mapped?: string, value?: number }}
 *   - `isIp:false` + `reason:'NOT_IP'` → 它是个域名，交给 DNS 那条线
 *   - `isIp:false` + `reason:'BAD_IP'` → 像 IP 但解不出来，**必须拒**（fail closed）
 *   - `isIp:true` + `public:false` → 内网/保留地址，拒
 */
export function classifyIp(raw) {
  const host = normalizeHost(raw)
  if (!host) return { isIp: false, family: 0, public: false, reason: 'EMPTY' }

  if (host.includes(':')) {
    const bytes = parseIpv6(host)
    if (!bytes) return { isIp: false, family: 6, public: false, reason: 'BAD_IP' }
    const c = classifyIpv6(bytes)
    if (c.reason === 'MAPPED') {
      const inner = classifyIpv4(c.mappedV4)
      return {
        isIp: true,
        family: 6,
        public: inner === null,
        reason: inner === null ? null : inner, // 报的是里面那个 IPv4 的原因，最好懂
        mapped: ipv4ToString(c.mappedV4),
        value: c.mappedV4,
      }
    }
    return { isIp: true, family: 6, public: c.reason === null, reason: c.reason }
  }

  // 只有"全由数字/点/十六进制字符组成"的才可能是 IPv4 字面量。
  // 这里不要直接指望 parseIpv4 返回 null 就一定是域名 —— 见下面的 BAD_IP 逻辑。
  const looksNumeric = /^[0-9.]+$/.test(host) || /^0[xX][0-9a-fA-F]*(\.[0-9a-fA-FxX]+)*$/.test(host)
  const value = parseIpv4(host)
  if (value !== null) {
    const reason = classifyIpv4(value)
    return { isIp: true, family: 4, public: reason === null, reason, value }
  }
  if (looksNumeric) return { isIp: false, family: 4, public: false, reason: 'BAD_IP' }
  return { isIp: false, family: 0, public: false, reason: 'NOT_IP' }
}

/** 便利函数：是不是"公网 IP 字面量"。域名一律 false（它得先解析，用 checkHost）。 */
export function isPublicIp(raw) {
  const c = classifyIp(raw)
  return c.isIp === true && c.public === true
}
