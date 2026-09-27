/**
 * 插件接线自检 —— **不需要 dsh、不联网、不装包**：拿一个假 ctx 把 `apply()` 跑起来，
 * 检查注册出来的东西，再把工具真调一遍。
 *
 *   node test/plugin-selftest.mjs
 *
 * 测的是接线：服务暴露了没、工具默认关着没、参数不合法/被挡下来时会不会炸、
 * 配置能不能覆盖默认值。判定逻辑本身归 test/selftest.mjs。
 *
 * 离线靠注入：`config.fetchImpl` 和 `config.lookup` 换上假实现，
 * 所以这里**一个字节都不会真的出网**（也就不可能顺手把内网探测一遍）。
 */
import { apply, inject, name as pluginName } from '../index.js'

let pass = 0
const fails = []
const ok = (label, cond, extra) => {
  if (cond) pass++
  else fails.push(label + (extra ? '  → ' + extra : ''))
}
const eq = (label, got, want) => ok(label, got === want, `got=${JSON.stringify(got)} want=${JSON.stringify(want)}`)
async function codeOf(fn) {
  try {
    await fn()
    return 'NO_ERROR'
  } catch (error) {
    return error?.code || `NO_CODE(${error?.message})`
  }
}

// ---- 假的 ctx --------------------------------------------------------------
function makeCtx() {
  const registered = []
  const provided = {}
  return {
    registered,
    provided,
    ctx: {
      logger: { info: () => {} },
      tools: {
        register: (def) => {
          registered.push(def)
          return () => {}
        },
      },
      provide: (key, value) => {
        provided[key] = value
      },
      effect: () => {},
    },
  }
}

// ---- 假的解析器 / 假的 fetch ------------------------------------------------
const HOSTS = {
  'example.com': ['93.184.216.34'],
  'to-private.example.com': ['10.1.2.3'],
}
const lookups = []
const lookup = async (host) => {
  lookups.push(host)
  const rows = HOSTS[host]
  if (!rows) {
    const error = new Error('queryA ENOTFOUND ' + host)
    error.code = 'ENOTFOUND'
    throw error
  }
  return rows.map((address) => ({ address, family: 4 }))
}

function makeFetch(routes) {
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
const text = (body, headers = {}) => new Response(body, { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8', ...headers } })
const redirectTo = (location, status = 302) => new Response(null, { status, headers: { location } })
const hang = (url, init) =>
  new Promise((_resolve, reject) => {
    const signal = init?.signal
    const bail = () => reject(signal?.reason ?? new DOMException('aborted', 'AbortError'))
    if (!signal) return
    if (signal.aborted) bail()
    else signal.addEventListener('abort', bail, { once: true })
  })

const F = 'http://example.com'
const routes = {
  [`${F}/ok`]: () => text('hello netguard'),
  [`${F}/long`]: () => text('啊'.repeat(500)),
  [`${F}/binary`]: () => new Response(Buffer.from([1, 0, 2, 3]), { status: 200, headers: { 'content-type': 'application/octet-stream' } }),
  [`${F}/to-metadata`]: () => redirectTo('http://169.254.169.254/latest/meta-data/iam/security-credentials/'),
  [`${F}/hang`]: hang,
  [`${F}/404`]: () => new Response('nope', { status: 404 }),
}

// ===========================================================================
// 1. 默认（工具关着）
// ===========================================================================
{
  const { ctx, registered, provided } = makeCtx()
  apply(ctx, { fetchImpl: makeFetch(routes), lookup })

  eq('插件名对', pluginName, 'dsh-netguard')
  eq('要 tools 能力', JSON.stringify(inject), JSON.stringify(['tools']))
  ok('暴露了 netguard 服务', Boolean(provided.netguard))
  ok('默认**不**登记工具（避免把外部内容直接喂给模型）', registered.length === 0, `registered=${registered.map((t) => t.name)}`)

  const svc = provided.netguard
  for (const fn of ['fetchPublic', 'fetchPublicBytes', 'assertPublicUrl', 'checkHost', 'isPublicHost', 'classifyIp'])
    ok(`服务上有 ${fn}`, typeof svc[fn] === 'function')
  eq('服务带着生效的配置', svc.config.maxBytes, 8 * 1024 * 1024)
  eq('默认 UA 是插件自己的（不是宿主的）', svc.config.userAgent, 'dsh-netguard/0.1.0')
  eq('isPublicHost 挡内网 IP', svc.isPublicHost('127.0.0.1'), false)
  eq('isPublicHost 放公网名字', svc.isPublicHost('example.com'), true)
  eq('assertPublicUrl 挡元数据地址', await codeOf(() => svc.assertPublicUrl('http://169.254.169.254/latest/meta-data/')), 'PRIVATE_ADDRESS')
  eq('checkHost 用的是注入的解析器', (await svc.checkHost('example.com')).addresses.join(','), '93.184.216.34')
  eq('checkHost 挡解析到内网的域名', (await svc.checkHost('to-private.example.com')).ok, false)
  const bytes = await svc.fetchPublicBytes(`${F}/ok`)
  ok('fetchPublicBytes 给的是 Buffer', Buffer.isBuffer(bytes))
  eq('拿到的正文对', bytes.toString(), 'hello netguard')
  eq('服务级 fetchPublic 会拒绝内网域名', await codeOf(() => svc.fetchPublic('http://to-private.example.com/')), 'DNS_PRIVATE')
}

// ===========================================================================
// 2. 打开工具
// ===========================================================================
{
  const { ctx, registered } = makeCtx()
  const fetchImpl = makeFetch(routes)
  apply(ctx, { enableTool: true, fetchImpl, lookup })
  const tool = registered.find((t) => t.name === 'fetch_url')
  ok('打开后登记了 fetch_url', Boolean(tool))
  eq('工具名对', registered.length, 1)
  ok('工具声明了参数 schema', Boolean(tool.parameters?.properties?.url))
  ok('url 是必填', JSON.stringify(tool.parameters.required) === JSON.stringify(['url']))
  ok('工具声明了输出 schema', Boolean(tool.output?.schema?.properties?.ok))
  eq('工具声明了自己是并发安全的', tool.isConcurrencySafe(), true)

  // ---- 正常路径 ----
  const value = await tool.execute({ url: `${F}/ok` }, {})
  eq('抓成功', value.ok, true)
  eq('状态码带回来', value.status, 200)
  eq('最终地址带回来', value.finalUrl, `${F}/ok`)
  eq('大小带回来', value.size, 'hello netguard'.length)
  ok('正文带回来（说明注入的 fetch 真被用了）', value.text === 'hello netguard', value.text)
  eq('没有被截断', value.truncated, false)

  const rendered = tool.output.render({}, value)
  eq('render 给的是文本块', rendered[0]?.type, 'text')
  ok('render 里有地址和正文', rendered[0].text.includes(`${F}/ok`) && rendered[0].text.includes('hello netguard'))
  ok('render 里提醒了"这是外部内容"', /外部内容/.test(rendered[0].text))

  // ---- 长正文被裁到 toolMaxChars（另起一个插件实例，配置只影响它）----
  const { ctx: clipCtx, registered: clipRegistered } = makeCtx()
  apply(clipCtx, { enableTool: true, fetchImpl, lookup, toolMaxChars: 12 })
  const clipped = clipRegistered[0]
  const long = await clipped.execute({ url: `${F}/long` }, {})
  eq('长正文按 toolMaxChars 裁短', long.text.length, 12)
  eq('但大小报的是真实字节数', long.size, 1500) // '啊' 是 3 字节，500 个 = 1500
  eq('正文被裁这件事会明说', long.textTruncated, true)
  eq('字节没被截断（截断的只是给模型的文本）', long.truncated, false)
  const longRendered = clipped.output.render({}, long)
  ok('render 里也提醒了正文被裁短', /正文太长/.test(longRendered[0].text), longRendered[0].text.slice(0, 60))

  // ---- 二进制不给文本 ----
  const bin = await tool.execute({ url: `${F}/binary` }, {})
  eq('二进制内容不给 text（塞乱码进上下文没意义）', bin.text, undefined)
  eq('但字节数照样报', bin.size, 4)

  // ---- 被挡下来时不抛，而是如实报错 ----
  const blocked = await tool.execute({ url: 'http://127.0.0.1:5099/api/secret' }, {})
  eq('内网直连 → ok:false', blocked.ok, false)
  eq('原因码带回来', blocked.code, 'PRIVATE_ADDRESS')
  ok('错误文案是人话', /不允许访问这个地址/.test(blocked.error || ''), blocked.error)
  const renderedBad = tool.output.render({}, blocked)
  ok('失败也能 render 出人话', /没拉下来/.test(renderedBad[0].text))

  const redirectBlocked = await tool.execute({ url: `${F}/to-metadata` }, {})
  eq('302 跳元数据 → ok:false', redirectBlocked.ok, false)
  eq('302 那条的原因码对', redirectBlocked.code, 'PRIVATE_ADDRESS')

  const http404 = await tool.execute({ url: `${F}/404` }, {})
  eq('对方 404 → ok:false + HTTP_ERROR', `${http404.ok}/${http404.code}`, 'false/HTTP_ERROR')

  const timeout = await tool.execute({ url: `${F}/hang`, timeoutMs: 40 }, {})
  eq('超时 → ok:false + TIMEOUT', `${timeout.ok}/${timeout.code}`, 'false/TIMEOUT')
  ok('超时文案里写了"超时"', /超时/.test(timeout.error || ''), timeout.error)

  const noUrl = await tool.execute({}, {})
  eq('不给 url 直接说没给', `${noUrl.ok}/${noUrl.code}`, 'false/BAD_URL')

  const garbage = await tool.execute({ url: 'not a url' }, {})
  eq('不是 URL → BAD_URL', garbage.code, 'BAD_URL')
  ok('工具执行全程没有把异常抛出去（不会炸掉整轮）', true)
}

// ===========================================================================
// 3. 配置能被覆盖（默认值不是写死的）
// ===========================================================================
{
  const { ctx, provided } = makeCtx()
  const fetchImpl = makeFetch(routes)
  apply(ctx, { enableTool: false, fetchImpl, lookup, maxBytes: 8, blockedPorts: [8080], allowRedirects: false, userAgent: 'probe/9' })
  const svc = provided.netguard
  eq('maxBytes 覆盖生效', svc.config.maxBytes, 8)
  eq('blockedPorts 覆盖生效', await codeOf(() => svc.assertPublicUrl('http://example.com:8080/')), 'BLOCKED_PORT')
  eq('8080 之外照常放行', await codeOf(() => svc.assertPublicUrl('http://example.com:9090/')), 'NO_ERROR')
  eq('allowRedirects=false 生效', await codeOf(() => svc.fetchPublic(`${F}/to-metadata`)), 'REDIRECT_DISABLED')
  eq('maxBytes 在真实下载时生效', await codeOf(() => svc.fetchPublic(`${F}/ok`)), 'TOO_LARGE')
  eq('userAgent 覆盖生效', svc.config.userAgent, 'probe/9')

  const { ctx: ctx2, provided: p2, registered: r2 } = makeCtx()
  const spy = []
  apply(ctx2, {
    enableTool: true,
    lookup,
    userAgent: 'probe/9',
    fetchImpl: async (url, init) => {
      spy.push(init.headers['User-Agent'])
      return text('x')
    },
  })
  await r2[0].execute({ url: `${F}/ok` }, {})
  eq('自定义 UA 真发出去了', spy[0], 'probe/9')
  eq('服务里也看得到这个 UA', p2.netguard.config.userAgent, 'probe/9')
}

// ===========================================================================
// 4. 服务暴露失败不能把插件带下水
// ===========================================================================
{
  const registered = []
  let logged = ''
  const ctx = {
    logger: { info: () => {} },
    tools: { register: (def) => registered.push(def) },
    provide: () => {
      throw new Error('已经有别的插件提供 netguard 了')
    },
  }
  const originalWrite = process.stderr.write.bind(process.stderr)
  process.stderr.write = (chunk) => {
    logged += String(chunk)
    return true
  }
  try {
    apply(ctx, { enableTool: true })
  } finally {
    process.stderr.write = originalWrite
  }
  eq('服务提供失败时工具照样登记', registered.length, 1)
  ok('并且把原因写到了 stderr（不是静默吞掉）', /暴露 netguard 服务失败/.test(logged), logged.slice(0, 80))
  ok('就绪日志里带着关键配置（上限/超时/工具开关）', /上限=/.test(logged) && /超时=/.test(logged) && /工具=开/.test(logged))
}

console.log(fails.length === 0 ? `\n全过：${pass} 条断言` : `\n挂了 ${fails.length} 项（共 ${pass + fails.length} 条断言）：\n  - ${fails.join('\n  - ')}`)
process.exit(fails.length === 0 ? 0 : 1)
