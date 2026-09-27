/**
 * errors.js —— 一种错误类型，带一个机器可读的 `code`。
 *
 * 为什么非要 code：调用方（通道插件、Agent 工具）要能分类处理 ——
 * 「被安全策略挡了」和「对面 404 了」和「网断了」是三种完全不同的处境，
 * 但它们的 message 都是给人看的中文。让调用方去正则匹配中文是不负责任的。
 *
 * message 的规矩：**只放能安全写进日志的东西**。不带完整 URL（可能有 token 之类的
 * 查询串）、不带请求头、不带响应体。要定位问题给主机名就够。
 */
export class NetguardError extends Error {
  /**
   * @param {string} message 给人看的中文说明（可直接上屏、可落日志）
   * @param {string} code 机器可读的原因，例如 PRIVATE_IP / TOO_LARGE / TIMEOUT
   * @param {{ status?: number, cause?: unknown }} [extra]
   */
  constructor(message, code, extra = {}) {
    super(message, extra.cause !== undefined ? { cause: extra.cause } : undefined)
    this.name = 'NetguardError'
    this.code = code
    if (extra.status !== undefined) this.status = extra.status
  }
}

/** 是不是"被安全策略挡了"（相对于网络故障）。调用方拿它决定要不要重试。 */
export function isBlocked(error) {
  return error instanceof NetguardError && !['NETWORK', 'TIMEOUT', 'ABORTED', 'HTTP_ERROR'].includes(error.code)
}
