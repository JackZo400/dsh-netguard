# dsh-netguard

[English](README.en.md) | 简体中文

给 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（dsh）用的**出网护栏**：
让"拉一个外部 URL"这件事不再是一个 SSRF 入口。

一个服务（`netguard`）+ 一个工具（`fetch_url`，**默认关闭**）。
别的插件直接调服务，不用自己再写一遍地址判定 —— 判定写错一次，就是一次内网暴露。

---

## 为什么需要它

**不挡会怎样**

Agent 插件几乎都要出去拉东西：图片、语音、网页、回调。只要那个 URL 来自
**聊天消息或模型输出**（群里有人贴了张图、模型自己拼了个地址），它就是攻击者能控制的字符串。
而跑插件的机器通常站在一个比你有权的位置上：

| 模型/用户给出的 URL | 实际会发生什么 |
| --- | --- |
| `http://127.0.0.1:5099/api/…` | 本机上别的服务（管理台、内部 API、数据库 HTTP 口） |
| `http://192.168.1.1/` | 路由器 / 内网设备的管理页 |
| `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | **云厂商元数据 → 临时凭据**。拿到它，你的云账号就是他的 |
| `http://[::1]/` | IPv6 回环，只写 `127\.` 的实现完全看不见 |
| `http://2130706433/` | 还是 `127.0.0.1`（十进制变形）。`0177.0.0.1`、`0x7f.1`、`0x7f000001` 同理 |
| `http://demo.example.com/x` | 这个域名**解析到** `10.0.0.5` —— 域名看着人畜无害 |
| `http://demo.example.com/x` | 它回一个 `302 Location: http://169.254.169.254/…` |
| `file:///etc/passwd` | 有些 fetch 封装会把协议校验漏掉，直接读本地文件 |

最后两条最容易被漏掉，也最致命：

- **只检查入口 URL** 的实现，在"域名解析到内网"面前等于没装 —— 攻击者只需要一个自己的域名。
- 只检查入口 URL 的实现在 **302** 面前同样等于没装。攻击者甚至不需要控制 DNS，
  只要在自己那台公网服务器上写一行 `Location: http://169.254.169.254/…` 就够了。

这个插件把这两条都补上了：**解析出来的每一条地址都判，重定向的每一跳都重新判。**

## 安装

```bash
dsh plugin --profile web add github:JackZo400/dsh-netguard
```

没有依赖、没有子进程、没有要装的二进制。Node 18.17+（实测 22.x）。

## 配置

```yaml
- insert:
    - id: netguard
      name: dsh-netguard
      config:
        allowedProtocols: ['http:', 'https:']   # 只放这两种
        maxBytes: 8388608                       # 一次最多下多少字节（8 MiB）
        onOverflow: error                       # error = 报错；truncate = 截断到上限
        timeoutMs: 20000                        # 整条链共用的超时
        allowRedirects: true                    # 跟不跟重定向（每一跳都会重新体检）
        maxRedirects: 3
        blockedPorts: [22, 23, 25, 6379, 11211, 27017]   # 内网服务常客
        allowUrlCredentials: false              # 允不允许 URL 里带 user:pass@
        allowSingleLabel: false                 # 允不允许 http://intranet/ 这种
        userAgent: dsh-netguard/0.1.0
        enableTool: false                       # 要不要登记 fetch_url 工具
        toolMaxChars: 20000                     # 工具最多回多少字符正文
```

**大小上限与超时的取舍**（这几条是真会踩到的）：

- **超限默认报错，而不是静默截断。** 因为主要调用场景是"拉图/拉音频"，
  截断的字节是**坏数据**：半张 JPEG 解不出图，可流量已经花掉、附件也存下了，
  最后报的还是个更难查的错。要"只要前面一段"就显式写 `onOverflow: truncate`。
- **`Content-Length` 报得太大就直接不下载**，流量一点都不花。
- **读流是一边读一边数的**，超了立刻断（`reader.cancel()`），不是读完再判断 ——
  对面挂一个 50GB 的流，读完再判断等于自己把内存吃光。
- **超时是整条链共用一个预算**，不是每跳各给一份。否则"跳 10 次、每次卡 19 秒"
  能拖出 190 秒。跳转途中花掉的时间也会算进去。

## 用法

### 给别的插件用（推荐）

```js
const netguard = ctx.get('netguard')

// 只要字节（签名和老实现一致：(url, { timeoutMs, maxBytes }) → Buffer）
const bytes = await netguard.fetchPublicBytes(imageUrl, { maxBytes: 8 * 1024 * 1024, timeoutMs: 20_000 })

// 要更多信息：状态码、最终落到的地址、跳了几次、有没有被截断
const r = await netguard.fetchPublic(url, { maxBytes: 64 * 1024, onOverflow: 'truncate' })
// → { finalUrl, status, contentType, headers, bytes, truncated, redirects, hops }

// 只体检，不下载
const u = await netguard.assertPublicUrl(url)   // 不安全就抛（带 code）

// 主机名/地址判定（可以单独用，不用发请求）
netguard.isPublicHost('127.0.0.1')        // false（同步，不查 DNS，只挡明显的写法）
await netguard.checkHost('demo.example.com')  // { ok, addresses, offender? }（会查 DNS）
netguard.classifyIp('::ffff:10.0.0.1')    // { isIp:true, family:6, public:false, reason:'PRIVATE', mapped:'10.0.0.1' }
```

失败一律抛 `NetguardError`，`message` 是能直接上屏的人话，`code` 是机器可读的原因：

```
PRIVATE_ADDRESS  BAD_HOST  DNS_PRIVATE  DNS_FAILED  BAD_PROTOCOL  BAD_CREDENTIALS
BAD_PORT  BLOCKED_PORT  BAD_URL  TOO_LARGE  TIMEOUT  ABORTED  NETWORK
REDIRECT_DISABLED  BAD_REDIRECT  TOO_MANY_REDIRECTS  REDIRECT_LOOP  HTTP_ERROR
```

错误文案只带主机名，不带完整 URL（URL 里可能有 token），也不带响应体 —— 可以放心写日志。

### 给模型用（默认关闭）

打开之后多一个 `fetch_url` 工具：

```yaml
config:
  enableTool: true
```

```
抓一下 https://example.com/demo.html 里写了什么
```

它的返回值会进模型上下文，所以**默认是关的** —— 那等于开了一条"外部内容 → 模型"的管道。
工具描述里写明了：拉回来的东西是数据，不是指令。

### 只想用判定逻辑（不要 dsh）

```js
import { isPublicIp, classifyIp } from 'dsh-netguard/src/ip.js'
import { assertPublicUrl } from 'dsh-netguard/src/guard.js'

isPublicIp('169.254.169.254')   // false
```

`src/ip.js` 是纯函数，不碰网络、不读配置，可以单独拿去用。

## 它到底挡了什么

```
IPv4  0.0.0.0/8  10/8  100.64/10  127/8  169.254/16  172.16/12  192.0.0.0/24
      192.0.2.0/24  192.88.99.0/24  192.168/16  198.18/15  198.51.100/24
      203.0.113/24  224/4  240/4（含 255.255.255.255）
      以及 169.254.169.254 / 100.100.100.200 / 192.0.0.192 这几个元数据地址（单独报原因）
      变形写法：127.1 / 2130706433 / 0177.0.0.1 / 0x7f.1 / 0x7f000001 …

IPv6  ::1  ::  fc00::/7  fe80::/10  fec0::/10  ff00::/8  100::/64  2001:db8::/32
      ::ffff:a.b.c.d（IPv4-mapped）  ::a.b.c.d（IPv4-compatible）
      2002::/16（6to4，把 IPv4 塞在第 3~6 字节）  2001::/32（Teredo）
      64:ff9b::/96（NAT64，最后 4 字节就是 IPv4）
      最后只放行 2000::/3 —— 白名单式：漏掉一条规则只会更严，不会更松

名字  localhost / *.localhost / *.local / *.localdomain / *.internal / *.home.arpa
      *.lan / *.intranet / *.corp / *.private / *.home / *.onion
      单段主机名（http://intranet/）
      末段是纯数字/0x 的畸形写法（999.1.1.1 / 1.2.3.4.5 / 0178.0.0.1）—— 不猜，直接拒

协议  只放 http: / https:
端口  22 23 25 110 143 445 993 995 3306 5432 6379 11211 27017（可配）
DNS   解析出来的**每一条**都判；有一条内网就整体拒（不是取第一条、不是挑最像公网的那条）
      解析失败 / 解析出空 / 解析出不是 IP 的东西 → 一律拒（fail closed，绝不放行）
跳转  每一跳都重走一遍上面全部检查；成环、超跳数、跳转被关掉、没有 Location 都报错
```

## 和"只写几个正则"比，补了什么

如果你手上已经有一个 `isPrivateIp()` 之类的实现，可以对照一下这几处：

1. **变形写法**。老写法一般是 `/^127\./`、`/^10\./` 这种前缀正则，
   `127.1`、`2130706433`、`0177.0.0.1`、`0x7f.1` 全都过。这里按 inet_aton 的语义
   把 1~4 段的写法真解析成 32 位整数再判。
2. **黑名单换白名单**。老实现列了 7 个私网段，`192.0.0.0/24`、`198.18/15`、
   `240/4`、多播段都不在里面。这里按特殊用途地址表逐块判，IPv6 干脆只放 `2000::/3`。
3. **IPv4-mapped 的 IPv6**。`::ffff:127.0.0.1` 在内核看来就是 IPv4 连接，
   字符串前缀判定的实现完全看不见它（`::ffff:7f00:1` 这种纯十六进制写法更看不见）。
   这里解成 16 字节按位判，6to4 / NAT64 也一样拆出来。
4. **域名解析**。老实现只拿第一条记录判（`lookup` 不带 `all: true` 时甚至只看一个族）：
   攻击者给两条记录（一条公网、一条内网）就绕过去了。这里要**全部**记录，有一条内网就拒。
5. **重定向**。老实现用默认的 `redirect: 'follow'`，等于把"跳去哪"完全交给了对方。
   这里 `redirect: 'manual'` 自己接管，每一跳重新体检。
6. **大小上限**。老实现是 `arrayBuffer()` 读完再比 —— 内存已经吃进去了。
   这里流式读、边读边数，超了立刻断。另外 `Content-Length` 就能提前判掉。
7. **超时的层级**。老实现每跳各给一次 `AbortSignal.timeout()`（其实它根本没跟跳转，
   所以没暴露），这里整条链一个 deadline。
8. **失败的声音**。老实现把 DNS 失败 `.catch(() => [])` 之后报"解析失败"，
   意思对；但这里还把 `code` 分出来了（`DNS_FAILED` / `DNS_PRIVATE` / `PRIVATE_ADDRESS`…），
   调用方能分类处理，不用去正则匹配中文。顺手也顺手把 URL 里的账号密码这类
   "看着像别人"的伪装写法挡掉了。

## 测试

```bash
npm test          # 或者分别跑：
node test/selftest.mjs         # 判定逻辑 + 重定向 + 大小上限 + 超时（249 条断言）
node test/plugin-selftest.mjs  # 插件接线：服务/工具/配置覆盖（65 条断言）
```

**两个都是完全离线的**：DNS 解析器和 fetch 都是注入进去的假实现，
所以不需要网络、不会抖动，也不需要任何密钥 —— 更不会"顺手把内网探测一遍"。
断言是真断言：把 `src/` 里任何一条防护删掉，脚本都会红（比如把重定向的逐跳复查去掉，
会挂 4 条；把大小上限去掉，会挂 7 条）。

## 已知局限

**没防住的部分，写清楚比假装防住了强**

1. **DNS 解析与实际连接之间的时间差（TOCTOU）**。这里查一次 DNS、判定通过，
   然后交给 fetch 自己**再查一次**才连。攻击者如果用一个 TTL=0 的域名，
   可以让第一次查到公网、第二次查到内网 —— 这是 DNS rebinding 的第二种形态，
   **本插件挡不住**。真正的修法是把解析结果钉住（自己实现 dispatcher / connect 钩子，
   连那个 IP 而不是再查一次名字），或者连上之后核对对端地址。
   Node 的全局 fetch 不给这个钩子，所以这里留了 `fetchImpl` 注入点，宿主可以接自己的实现。
2. **代理**。如果宿主注入了一个走代理的 fetch，本插件的判定是在**代理之前**做的，
   它只描述"目标地址"，管不了代理那边怎么解析、怎么连。
   另外 Node 的 fetch 默认不读 `HTTP_PROXY` / `HTTPS_PROXY`，但这个行为取决于运行时版本 ——
   别指望这一层替你管代理。
3. **内容本身**。它只管"能不能去、拿多大"，不管"拿回来的东西写了什么"。
   拉回来的页面里完全可以写"忽略你之前的所有指令"。工具的描述和返回值末尾都提醒了这一点，
   但那是一句提醒，不是一道防护。
4. **不是浏览器**。`<meta http-equiv="refresh">`、JS 跳转、Service Worker 这些
   客户端侧的重定向不归它管（fetch 也看不到）。
5. **公网地址上的内网内容**。攻击者自己那台公网服务器完全可以反代到内网 ——
   从地址层面看不出任何问题。这一层挡不住，也不该指望它挡。
6. **端口黑名单是近似，不是完整**。`8081`、`9090`、`5000` 这些也可能挂着内网服务。
   想更严就自己往 `blockedPorts` 里加。
7. **IPv6 只放 `2000::/3`**，极少数合法的特殊写法会被误挡（被挡了会报 `RESERVED`，能改）。
8. **没有速率/并发限制**。它回答的是"能不能去这个地址"，不回答"去多少次"。
   真要做配额得在外面加。
9. **只做 GET**，不支持上传、POST、流式长连接。
10. **DNS 层不做 DNSSEC 验证**，系统解析器返回什么就判什么。
    （不过 CNAME 链不影响结论：判的是最终地址。）

## License

MIT © 2026 JackZo400

---

## English

→ Full English README: [README.en.md](README.en.md)
