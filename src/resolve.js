/**
 * resolve.js —— DNS 解析的薄壳，**解析器可注入**。
 *
 * 为什么要有这一层（而不是直接在 guard.js 里调 lookup）：
 * 1. 测试必须离线。域名解析到内网是 SSRF 最常见的形态之一，
 *    它必须被自检覆盖，但自检不该真去查 DNS（CI 里没网、也会抖动）。
 *    所以 `resolveHost(host, resolver)` 把解析器当参数传，测试塞个查表函数进去。
 * 2. 宿主可能有自己的解析器（走 DoH / 走内网 DNS / 带缓存）。
 *
 * 解析失败 = 拒绝，不是"放行"。这条很重要：解析失败的域名如果被放过，
 * 攻击者只要让解析超时就能把请求交给后面的逻辑去碰运气。
 */
import { lookup } from 'node:dns/promises'
import { NetguardError } from './errors.js'
import { normalizeHost } from './ip.js'

/** 默认解析器：一次要回**所有** A/AAAA 记录，而不是第一条。 */
export async function nativeLookup(host) {
  const rows = await lookup(host, { all: true, verbatim: true })
  return rows.map((r) => ({ address: r.address, family: r.family }))
}

/**
 * 解析一个域名 → `[{ address, family }]`。解析不出来就抛（fail closed）。
 * @param {string} host
 * @param {(host: string) => Promise<Array<{address: string, family?: number}|string>>} [resolver]
 */
export async function resolveHost(host, resolver) {
  const name = normalizeHost(host)
  const short = String(host ?? '').slice(0, 60)
  if (!name) throw new NetguardError('域名是空的，解析不了', 'DNS_FAILED')
  const fn = typeof resolver === 'function' ? resolver : nativeLookup
  let rows
  try {
    rows = await fn(name)
  } catch (error) {
    const detail = String(error?.code || error?.message || error || '').slice(0, 80)
    throw new NetguardError(`域名 ${short} 解析失败${detail ? `（${detail}）` : ''}`, 'DNS_FAILED', { cause: error })
  }
  const list = (Array.isArray(rows) ? rows : [])
    .map((r) => (typeof r === 'string' ? { address: r, family: r.includes(':') ? 6 : 4 } : { address: r?.address, family: r?.family }))
    .filter((r) => typeof r.address === 'string' && r.address)
  if (list.length === 0) throw new NetguardError(`域名 ${short} 解析不出任何地址`, 'DNS_FAILED')
  return list
}
