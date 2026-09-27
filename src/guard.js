/**
 * guard.js —— 一次完整的"出网前体检"：URL 语法 → 协议 → 端口 → 主机名 → DNS 结果。
 *
 * 顺序是刻意的：**先做不需要网络的检查**（语法/协议/端口/字面量 IP），
 * 只有走到最后才查 DNS。这样常见的内网直连（`http://127.0.0.1:5099/…`）
 * 一次网络请求都不会发出去，也不会被拿去做 DNS 侧信道。
 *
 * 这里也是"域名解析到内网"这条线的落点：解析出来的**每一条**地址都要过一遍
 * `classifyIp`，只要有一条是内网就整体拒绝 —— 不是取第一条、也不是"取最像公网的那条"。
 * 攻击者控制 DNS 时可以随便给多条记录（一条正常、一条内网），取第一条的实现在这种时候就废了。
 */
import { NetguardError } from './errors.js'
import { classifyIp, describeReason, normalizeHost } from './ip.js'
import { resolveHost } from './resolve.js'
import { mergeConfig } from './config.js'

/**
 * 名字层面就该挡的顶级标签。这些都不是"公网域名"：
 * localhost / *.local（mDNS、开发机）/ *.internal（云厂商内网，含元数据主机）
 * *.localdomain / *.lan / *.intranet / *.corp / *.private / *.home
 * 都是 RFC 6761/6762 和 ICANN 留给"只在局域网里有意义"的。
 * （*.home.arpa 要连着两段看，单独判，见 checkHostSyntax）
 */
const BLOCKED_TLDS = ['localhost', 'local', 'localdomain', 'internal', 'lan', 'intranet', 'corp', 'private', 'home', 'onion']

/** 末段是纯数字/0x 写法 → 它本来是想写成 IP 的。 */
const IPISH_LABEL = /^(?:0[xX][0-9a-fA-F]+|\d+)$/

const shortHost = (h) => String(h ?? '').slice(0, 60)

/**
 * 只做**不需要网络**的主机名检查。
 * @returns {{ ok: boolean, kind: 'ip'|'name', host: string, reason: string|null }}
 *   ok=false 时 reason 是机器可读的原因；ok=true 且 kind='name' 时**还没查 DNS**，
 *   别拿它当"这个域名安全"用（用 checkHost / assertPublicUrl）。
 */
export function checkHostSyntax(raw, partialConfig) {
  const config = mergeConfig(partialConfig)
  const host = normalizeHost(raw)
  if (!host) return { ok: false, kind: 'name', host: '', reason: 'EMPTY_HOST' }

  const cls = classifyIp(host)
  if (cls.isIp) {
    return { ok: cls.public, kind: 'ip', host, reason: cls.public ? null : cls.reason || 'RESERVED' }
  }
  if (cls.reason === 'BAD_IP') return { ok: false, kind: 'name', host, reason: 'BAD_IP' }

  const labels = host.split('.')
  const lastLabel = labels[labels.length - 1]
  // 末段是数字/0x 写法却没被解析成 IP → 说明这是个"想伪装成 IP"的畸形写法。
  // 例：`999.1.1.1`、`1.2.3.4.5`、`0178.0.0.1` —— 它们不一定连得上，
  // 但每个系统的解析行为都不一样（有的当域名、有的自己补全），不猜，直接拒。
  if (IPISH_LABEL.test(lastLabel)) return { ok: false, kind: 'name', host, reason: 'BAD_IP' }

  if (labels.length === 1 && !config.allowSingleLabel) return { ok: false, kind: 'name', host, reason: 'SINGLE_LABEL' }
  // home.arpa 要连着看两段（单看顶级标签只会看到 'arpa'）
  if (host === 'home.arpa' || host.endsWith('.home.arpa')) return { ok: false, kind: 'name', host, reason: 'INTERNAL_NAME' }
  if (BLOCKED_TLDS.includes(lastLabel)) return { ok: false, kind: 'name', host, reason: 'INTERNAL_NAME' }
  if (labels.includes('localhost')) return { ok: false, kind: 'name', host, reason: 'INTERNAL_NAME' }
  return { ok: true, kind: 'name', host, reason: null }
}

/** reason → 人话（域名那几种）。 */
function nameReasonText(reason) {
  switch (reason) {
    case 'EMPTY_HOST':
      return '地址里没有主机名'
    case 'BAD_IP':
      return '主机名写成了一副 IP 的样子却解析不出来（不猜，直接拒）'
    case 'SINGLE_LABEL':
      return '单段主机名（没有点）几乎只在内网有意义，公网站点一定是域名'
    case 'INTERNAL_NAME':
      return '这是局域网/保留域名（localhost、*.local、*.internal 之类）'
    default:
      return describeReason(reason)
  }
}

/** 同步、**不做 DNS** 的粗筛：命中的直接拒，没命中的还得再做完整检查。 */
export function isPublicHost(raw, partialConfig) {
  return checkHostSyntax(raw, partialConfig).ok
}

/**
 * 完整的主机名检查（含 DNS）。
 * @returns {Promise<{ ok: boolean, host: string, kind: 'ip'|'name', addresses: string[], reason: string|null }>}
 *   解析失败会抛 NetguardError（DNS_FAILED）—— 因为"查不到"和"查到了但不安全"对调用方
 *   都只有一个正确反应：别连。
 */
export async function checkHost(raw, options = {}) {
  const config = mergeConfig(options.config)
  const syntax = checkHostSyntax(raw, config)
  if (!syntax.ok) return { ...syntax, addresses: [] }

  if (syntax.kind === 'ip') {
    const cls = classifyIp(syntax.host)
    return { ok: true, host: syntax.host, kind: 'ip', addresses: cls.mapped ? [cls.mapped] : [syntax.host], reason: null }
  }

  const rows = await resolveHost(syntax.host, options.resolver ?? config.lookup)
  for (const row of rows) {
    const cls = classifyIp(row.address)
    // 解析出来的东西连 IP 都不是 → 解析器有问题/被投毒，同样 fail closed
    if (!cls.isIp || !cls.public) {
      return {
        ok: false,
        host: syntax.host,
        kind: 'name',
        addresses: rows.map((r) => r.address),
        offender: row.address,
        reason: cls.isIp ? cls.reason || 'RESERVED' : 'BAD_IP',
      }
    }
  }
  return { ok: true, host: syntax.host, kind: 'name', addresses: rows.map((r) => r.address), reason: null }
}

/**
 * 只检查 URL 的形状（协议、凭据、端口）并返回 URL 对象。
 * 不含主机名判定 —— 那是 checkHost / assertPublicUrl 的事。
 */
export function parseHttpUrl(raw, partialConfig) {
  const config = mergeConfig(partialConfig)
  const text = String(raw ?? '').trim()
  let url
  try {
    url = new URL(text)
  } catch {
    // 只给"不是合法 URL"，不回显输入 —— 输入里可能带着 token
    throw new NetguardError('这不像一个完整的 URL（需要 http:// 或 https:// 开头）', 'BAD_URL')
  }
  if (!config.allowedProtocols.includes(url.protocol)) {
    throw new NetguardError(`只允许 ${config.allowedProtocols.join(' / ')} 协议，拿到的是「${url.protocol.replace(':', '') || '空'}」`, 'BAD_PROTOCOL')
  }
  if ((url.username || url.password) && !config.allowUrlCredentials) {
    throw new NetguardError('URL 里带了用户名/密码，不收 —— 这种写法还会被用来伪装真实主机（http://某域名@内网IP/）', 'BAD_CREDENTIALS')
  }
  const port = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new NetguardError(`端口不合法：${shortHost(url.port)}`, 'BAD_PORT')
  }
  if (config.blockedPorts.includes(port)) {
    throw new NetguardError(`端口 ${port} 在黑名单里 —— 这类端口几乎不对外提供公网内容，却是内网服务的常客`, 'BLOCKED_PORT')
  }
  return url
}

/**
 * 完整体检通过返回 URL 对象（和旧实现的 assertPublicUrl 同签名，可以直接换过来用），
 * 否则抛 NetguardError。fail closed：任何一步没通过都不返回。
 * @param {string} raw
 * @param {{ config?: object, resolver?: Function }} [options]
 */
export async function assertPublicUrl(raw, options = {}) {
  const config = mergeConfig(options.config)
  const url = parseHttpUrl(raw, config)
  const checked = await checkHost(url.hostname, { config, resolver: options.resolver })
  if (!checked.ok) {
    const host = shortHost(checked.host || url.hostname)
    // DNS 那条线单独给一句更具体的 —— 出问题的不是域名写法，是它解析出来的地址。
    // （offender 存在就说明"域名写法没问题、解析结果有问题"，包括解析出个不是 IP 的垃圾）
    if (checked.kind === 'name' && checked.offender) {
      throw new NetguardError(dnsPrivateMessage(host, checked.offender, checked.reason), 'DNS_PRIVATE')
    }
    const why = checked.kind === 'ip' ? describeReason(checked.reason) : nameReasonText(checked.reason)
    const code = checked.kind === 'ip' ? 'PRIVATE_ADDRESS' : 'BAD_HOST'
    throw new NetguardError(`不允许访问这个地址：${host}（${why}）`, code)
  }
  return url
}

/** DNS 那条线单独的错误文案（assertPublicUrl 内部用 checkHost 时走不到这里，留给调用方复用）。 */
export function dnsPrivateMessage(host, address, reason) {
  return `域名 ${shortHost(host)} 解析到了 ${address}（${describeReason(reason)}）—— 「域名看着正常、解析进内网」是最常见的 SSRF 形态，挡掉`
}
