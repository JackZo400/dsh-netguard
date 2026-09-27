/**
 * fetch.js —— 真正出去拉东西的那一层。三件事必须在这里做掉：
 *   1. **重定向每一跳都复查**：这是"302 跳到内网"唯一的挡法。
 *      只检查入口 URL 的实现在 302 面前等于没有 —— 攻击者只要让自己的公网服务器
 *      回一个 `Location: http://169.254.169.254/latest/meta-data/`，请求就跟着过去了。
 *      所以这里用 `redirect: 'manual'`（自己接管跳转），每拿到一个 Location
 *      就当成一个全新的 URL 重新走一遍体检。
 *   2. **大小上限**：边读边数，超了就停。不能等 `arrayBuffer()` 读完再判断 ——
 *      那时候内存已经吃进去了（对面完全可以挂个 50GB 的流）。
 *      而且 Content-Length 报得太大就干脆不下载（省流量也省时间）。
 *   3. **超时**：整条链（含所有跳）共用**一个**时间预算。
 *      每跳各给一份超时的实现，会被"跳 10 次、每次卡 19 秒"拖死。
 *
 * fetch 和解析器都能注入：测试里换成假实现就完全离线了。
 */
import { NetguardError } from './errors.js'
import { assertPublicUrl } from './guard.js'
import { mergeConfig } from './config.js'

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308])

const shortHost = (h) => String(h ?? '').slice(0, 60)

/** 把网络层抛出来的杂七杂八，翻译成"能直接上屏"的 NetguardError。 */
function wrapNetworkError(error, ctx) {
  if (error instanceof NetguardError) return error
  if (ctx.expired()) {
    return new NetguardError(`请求超时（超过 ${ctx.timeoutMs}ms），已中止 —— ${shortHost(ctx.host)}`, 'TIMEOUT', { cause: error })
  }
  if (ctx.signal?.aborted) return new NetguardError('这次请求被调用方中止了', 'ABORTED', { cause: error })
  const detail = String(error?.message || error || '').slice(0, 160)
  return new NetguardError(`网络请求失败：${detail || '原因不明'}`, 'NETWORK', { cause: error })
}

/** 丢掉还没读的响应体。不读也不 cancel 的话连接会一直挂着（keep-alive 池里越积越多）。 */
async function discard(response) {
  try {
    await response?.body?.cancel?.()
  } catch {
    // 假响应/已关闭的流/已经被 reader 锁住的流，忽略
  }
}

/**
 * 边读边数，守住 maxBytes。
 * @returns {Promise<{ bytes: Buffer, truncated: boolean }>}
 */
async function readCapped(response, maxBytes, onOverflow) {
  const tooLarge = () =>
    new NetguardError(`内容超过大小上限（${maxBytes} 字节），已中止下载 —— 多出来的部分不要了`, 'TOO_LARGE')

  const body = response.body
  if (!body || typeof body.getReader !== 'function') {
    // 没有流式 body（有些运行时/垫片/adapter 就只有 arrayBuffer）。
    // 这条路上没法"读到一半就停"，只能整块读下来再截 —— 所以能走流就一定走流。
    const buf = Buffer.from(await response.arrayBuffer())
    if (buf.length > maxBytes) {
      if (onOverflow === 'truncate') return { bytes: buf.subarray(0, maxBytes), truncated: true }
      throw tooLarge()
    }
    return { bytes: buf, truncated: false }
  }

  const reader = body.getReader()
  const chunks = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = Buffer.from(value)
      if (total + chunk.length > maxBytes) {
        if (onOverflow === 'truncate') {
          // 截断：留前 maxBytes 个字节，主动断掉后面的下载（不是把整条流读完再切）
          if (maxBytes > total) chunks.push(chunk.subarray(0, maxBytes - total))
          // 注意必须用 reader.cancel() 而不是 response.body.cancel()：
          // 流被 reader 锁住之后，body.cancel() 会直接抛（而且很容易被 catch 吞掉），
          // 结果就是"以为断了，其实对面的字节还在往这边灌"。
          await reader.cancel().catch(() => {})
          return { bytes: Buffer.concat(chunks), truncated: true }
        }
        await reader.cancel().catch(() => {})
        throw tooLarge()
      }
      chunks.push(chunk)
      total += chunk.length
    }
  } finally {
    try {
      reader.releaseLock?.()
    } catch {
      // 已经关掉了，无所谓
    }
  }
  return { bytes: Buffer.concat(chunks), truncated: false }
}

/**
 * 拉一个公网 URL。**每一跳都体检**，超限按配置报错或截断。
 *
 * @param {string} rawUrl
 * @param {{
 *   config?: object, resolver?: Function, fetch?: Function,
 *   maxBytes?: number, timeoutMs?: number, onOverflow?: 'error'|'truncate', signal?: AbortSignal,
 * }} [options]
 * @returns {Promise<{ finalUrl: string, status: number, contentType: string, headers: Record<string,string>, bytes: Buffer, truncated: boolean, redirects: number, hops: string[] }>}
 */
export async function fetchPublic(rawUrl, options = {}) {
  const config = mergeConfig(options.config)
  const doFetch = options.fetch ?? config.fetchImpl ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new NetguardError('这个运行时没有全局 fetch，请在配置里注入 fetchImpl', 'NO_FETCH')
  }
  const maxBytes = Number.isFinite(Number(options.maxBytes)) ? Number(options.maxBytes) : config.maxBytes
  const onOverflow = options.onOverflow === 'truncate' ? 'truncate' : options.onOverflow === 'error' ? 'error' : config.onOverflow
  const timeoutMs = Number.isFinite(Number(options.timeoutMs)) ? Number(options.timeoutMs) : config.timeoutMs

  // 整条链共用的一个截止时间 + 一个 AbortController。
  //
  // 为什么不用 AbortSignal.timeout()（它看起来更省事）：
  //   1. 它每条信号是**各自**计时的，写起来很容易变成"每跳各给一份超时"，
  //      于是一串重定向能把总时间拖成 N 倍。这里一个定时器管整条链。
  //   2. Node 里它的定时器是 unref 的：在没有别的活动句柄的进程里（脚本、CLI、
  //      一次性任务），事件循环会先空掉，超时信号根本来不及炸 —— 请求就永远挂在 await 上。
  //      实测过：只有 AbortSignal.timeout 的时候 `node x.mjs` 直接以
  //      "Detected unsettled top-level await" 退出。
  // 所以超时用自己这个**不 unref** 的定时器保证；它会在 finally 里 clear 掉，
  // 不会给宿主留句柄。
  const deadline = Date.now() + timeoutMs
  let timedOut = false
  const controller = new AbortController()
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort(new Error('netguard deadline exceeded'))
  }, timeoutMs)
  const expired = () => timedOut || Date.now() >= deadline
  // 调用方自己的 signal 也接进来（取消一条链，而不是只取消当前那一跳）
  const callerSignal = options.signal
  const onCallerAbort = () => controller.abort(callerSignal?.reason ?? new Error('aborted by caller'))
  if (callerSignal) {
    if (callerSignal.aborted) onCallerAbort()
    else callerSignal.addEventListener('abort', onCallerAbort, { once: true })
  }

  const headers = {
    Accept: '*/*',
    'User-Agent': config.userAgent,
    ...config.headers,
    ...(options.headers || {}),
  }

  try {
    const hops = []
    let url = String(rawUrl ?? '').trim()
    let redirects = 0

    for (;;) {
      // ← 关键：不是只查入口，而是每一跳都从头走一遍完整检查（协议/端口/主机/DNS）
      const target = await assertPublicUrl(url, { config, resolver: options.resolver })
      hops.push(target.href)

      let response
      try {
        response = await doFetch(target.href, { method: 'GET', redirect: 'manual', headers, signal: controller.signal })
      } catch (error) {
        throw wrapNetworkError(error, { expired, signal: callerSignal, timeoutMs, host: target.hostname })
      }

      if (REDIRECT_STATUS.has(response.status)) {
        const location = response.headers.get('location')
        await discard(response)
        if (!config.allowRedirects) {
          throw new NetguardError(`对方要求跳转（HTTP ${response.status}），但配置里关掉了重定向`, 'REDIRECT_DISABLED')
        }
        if (!location) throw new NetguardError(`HTTP ${response.status} 说要跳转，却没给 Location`, 'BAD_REDIRECT')
        if (redirects >= config.maxRedirects) {
          throw new NetguardError(`重定向次数超过上限（${config.maxRedirects} 跳），不跟了`, 'TOO_MANY_REDIRECTS')
        }
        redirects++
        let next
        try {
          next = new URL(location, target) // Location 可以是相对路径，按当前 URL 补全
        } catch {
          throw new NetguardError('重定向给的地址不合法', 'BAD_REDIRECT')
        }
        if (hops.includes(next.href)) throw new NetguardError('重定向绕回已经访问过的地址（成环）', 'REDIRECT_LOOP')
        url = next.href
        continue
      }

      if (!response.ok) {
        await discard(response)
        throw new NetguardError(`对方返回 HTTP ${response.status}`, 'HTTP_ERROR', { status: response.status })
      }

      // Content-Length 说超了就先不下载了 —— 报错模式下没必要把流量花完再报错。
      // 注意 Number(null) === 0，所以必须先判空。
      const declared = response.headers.get('content-length')
      const declaredNum = declared === null || declared === '' ? NaN : Number(declared)
      if (Number.isFinite(declaredNum) && declaredNum > maxBytes && onOverflow !== 'truncate') {
        await discard(response)
        throw new NetguardError(`Content-Length 就有 ${declaredNum} 字节，超过上限 ${maxBytes} 字节 —— 直接不下载了`, 'TOO_LARGE')
      }

      const { bytes, truncated } = await readCapped(response, maxBytes, onOverflow)
      return {
        finalUrl: target.href,
        status: response.status,
        contentType: response.headers.get('content-type') || '',
        headers: Object.fromEntries(response.headers.entries()),
        bytes,
        truncated,
        redirects,
        hops,
      }
    }
  } finally {
    clearTimeout(timer)
    if (callerSignal) callerSignal.removeEventListener?.('abort', onCallerAbort)
  }
}

/**
 * 只要字节的版本。签名刻意和别的插件里那份 `fetchPublicBytes` 一致
 * （`(url, { timeoutMs, maxBytes })` → Buffer），这样老代码换 import 就能接上。
 */
export async function fetchPublicBytes(rawUrl, options = {}) {
  const result = await fetchPublic(rawUrl, options)
  return result.bytes
}
