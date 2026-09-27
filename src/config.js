/**
 * config.js —— 一份默认配置 + 合并函数。
 *
 * 所有默认值都选了**保守**的那一头：宁可挡住一个本来无辜的地址，
 * 也不要放过一个内网地址。被挡住的人至少能看见一句人话（去哪改配置也写在 README 里），
 * 被放过的人什么都不会看见 —— 内网内容已经顺着回复正文流出去了。
 */

/** 默认配置。注释里写的是"为什么是这个数"。 */
export const DEFAULT_CONFIG = {
  // 整个请求链（含每一跳重定向）共用的时间预算。
  // 20 秒：比常见图片/网页慢一点点的都还能拉下来，但一个被挂住的连接不会把
  // Agent 那一轮拖死（工具调用是有整体时限的）。
  timeoutMs: 20_000,

  // 默认 8 MiB —— 和通道插件里单张图的上限对齐。再大的东西也不该塞进模型上下文。
  maxBytes: 8 * 1024 * 1024,

  // 超上限怎么办：'error'（默认，报错）或 'truncate'（截断到上限继续用）。
  // 默认报错是因为调用方大多是"拉图/拉音频"，截断的字节是**坏数据**：
  // 半张 JPEG 解不出图，可流量已经花掉、附件也存下了，最后报的还是个更难查的错。
  // 但只要调用方明确说"我只要前面一段"（比如抓网页正文前 64KB），'truncate' 更省事。
  onOverflow: 'error',

  // 最多跟几跳重定向。3 跳覆盖了绝大多数正经站点；再长多半是在绕圈。
  maxRedirects: 3,

  // 允不允许跟随重定向。**关掉最安全**（完全不跟），但很多 CDN 靠 301/302 工作，
  // 所以默认开；开着的每一跳都会重新体检（见 fetch.js），这才是关键。
  allowRedirects: true,

  // 只放这两种协议。file: / gopher: / dict: / ftp: / data: 都是经典的 SSRF 跳板，
  // 它们能读到的东西比 http 更离谱（file:// 直接读本地文件）。
  allowedProtocols: ['http:', 'https:'],

  // 端口黑名单：这些端口几乎不会用来对外提供"公网内容"，却是内网服务的常客。
  // SSH / telnet / SMTP 还能被拿来当协议的跳板（发信、探测 banner）。
  // 想拉 8080、3000 这些开发端口？它们不在名单里，照常放行。
  // 想全放行就把这里设成 []（README 里写了这么做的代价）。
  blockedPorts: [22, 23, 25, 110, 143, 445, 993, 995, 3306, 5432, 6379, 11211, 27017],

  // 允许 URL 里带 user:pass@ 吗？默认不允许。
  // 除了"把凭据写进日志"这件事本身很难看，还有一种老骗术：
  //   http://trusted.example.com@127.0.0.1:8080/   —— 人眼盯着前面那个域名，
  //   解析器真正连的却是 @ 后面的主机。挡掉凭据，这类"看着像别人"的地址就没了伪装空间。
  allowUrlCredentials: false,

  // 允许单段主机名吗（http://intranet/ 这种没有点的）？默认不允许。
  // 内网服务名几乎都是单段的（redis、metadata、db…），而公网站点必然有域名。
  allowSingleLabel: false,

  // 出网的 User-Agent。别用宿主自己的 UA —— 对外要能看出这是谁在拉。
  userAgent: 'dsh-netguard/0.1.0',

  // 额外的请求头（Accept 之类）。**不要在这里放密钥**：重定向会带着它去别的域名。
  headers: {},

  // 注入点：留空就用运行时的全局 fetch / node:dns。
  // 这两个存在的意义是**让测试完全离线**（假 fetch + 假解析器），
  // 顺便也让宿主能接自己的连接池 / 代理。
  fetchImpl: null,
  lookup: null,
}

/** 合并用户配置。数组类字段直接覆盖，不做合并 —— 想放宽就写全。 */
export function mergeConfig(partial) {
  const cfg = { ...DEFAULT_CONFIG, ...(partial || {}) }
  cfg.timeoutMs = Number.isFinite(Number(cfg.timeoutMs)) && Number(cfg.timeoutMs) > 0 ? Number(cfg.timeoutMs) : DEFAULT_CONFIG.timeoutMs
  cfg.maxBytes = Number.isFinite(Number(cfg.maxBytes)) && Number(cfg.maxBytes) >= 0 ? Number(cfg.maxBytes) : DEFAULT_CONFIG.maxBytes
  cfg.maxRedirects = Number.isFinite(Number(cfg.maxRedirects)) && Number(cfg.maxRedirects) >= 0 ? Number(cfg.maxRedirects) : DEFAULT_CONFIG.maxRedirects
  cfg.onOverflow = cfg.onOverflow === 'truncate' ? 'truncate' : 'error'
  cfg.allowedProtocols = Array.isArray(cfg.allowedProtocols) && cfg.allowedProtocols.length ? cfg.allowedProtocols.map((p) => String(p).toLowerCase()) : DEFAULT_CONFIG.allowedProtocols
  cfg.blockedPorts = Array.isArray(cfg.blockedPorts) ? cfg.blockedPorts.map(Number).filter((n) => Number.isInteger(n)) : DEFAULT_CONFIG.blockedPorts
  cfg.headers = cfg.headers && typeof cfg.headers === 'object' ? { ...cfg.headers } : {}
  return cfg
}
