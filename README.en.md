# dsh-netguard

[简体中文](README.md) | English

An **egress guard** for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh):
it stops "fetch an external URL" from being an SSRF entry point.

One service (`netguard`) + one tool (`fetch_url`, **off by default**).
Other plugins call the service instead of writing the address check again themselves -- get that
check wrong once and the internal network is exposed once.

---

## Why you need it

**What happens if nothing blocks it**

Almost every agent plugin fetches things from the outside: images, audio, web pages, callbacks.
Whenever that URL comes from **a chat message or model output** (someone drops an image in the
group, the model builds an address itself), it is a string an attacker can control. And the box
running the plugin usually sits somewhere more privileged than you do:

| URL from the model/user | What actually happens |
| --- | --- |
| `http://127.0.0.1:5099/api/…` | another service on the same box (admin UI, internal API, database HTTP port) |
| `http://192.168.1.1/` | the admin page of a router / LAN device |
| `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | **cloud metadata → temporary credentials**. Whoever gets this owns your cloud account |
| `http://[::1]/` | IPv6 loopback; an implementation that only matches `127\.` never sees it |
| `http://2130706433/` | still `127.0.0.1` (decimal spelling). Same for `0177.0.0.1`, `0x7f.1`, `0x7f000001` |
| `http://demo.example.com/x` | that hostname **resolves to** `10.0.0.5` -- the name looks harmless |
| `http://demo.example.com/x` | it answers `302 Location: http://169.254.169.254/…` |
| `file:///etc/passwd` | some fetch wrappers miss the protocol check and read local files directly |

The last two are the easiest to miss and the most fatal:

- An implementation that **checks the entry URL only** is as good as absent in front of
  "hostname resolves to the intranet" -- the attacker only needs a domain of their own.
- It is equally absent in front of a **302**. The attacker does not even need to control DNS:
  one line `Location: http://169.254.169.254/…` on their own public server is enough.

This plugin covers both: **every resolved address is classified, and every redirect hop is
re-validated.**

## Install

```bash
dsh plugin --profile web add github:JackZo400/dsh-netguard
```

No dependencies, no subprocesses, no binaries to install. Node 18.17+ (tested on 22.x).

## Configuration

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

**The size-cap / timeout trade-offs** (these are the ones you really hit):

- **Going over the cap fails by default instead of truncating silently.** The main callers fetch
  images/audio, and truncated bytes are **bad data**: half a JPEG decodes to nothing, yet the
  traffic is already paid for and the attachment is already stored -- and the error you finally
  see is harder to trace. If you want "just the first chunk", say `onOverflow: truncate`
  explicitly.
- **If `Content-Length` reports too much, nothing is downloaded at all** -- zero traffic spent.
- **The stream is counted while it is read**, and aborted the moment it goes over
  (`reader.cancel()`), instead of deciding after the fact -- point it at a 50GB stream and the
  "read it all, then check" version eats its own memory.
- **The timeout is one budget for the whole chain**, not one per hop. Otherwise "10 hops, each
  stuck for 19 seconds" drags out to 190 seconds. Time spent inside redirects counts too.

## Usage

### For other plugins (recommended)

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

Every failure throws a `NetguardError`: `message` is human-readable text you can show as-is, and
`code` is the machine-readable reason:

```
PRIVATE_ADDRESS  BAD_HOST  DNS_PRIVATE  DNS_FAILED  BAD_PROTOCOL  BAD_CREDENTIALS
BAD_PORT  BLOCKED_PORT  BAD_URL  TOO_LARGE  TIMEOUT  ABORTED  NETWORK
REDIRECT_DISABLED  BAD_REDIRECT  TOO_MANY_REDIRECTS  REDIRECT_LOOP  HTTP_ERROR
```

Error text carries the hostname only, never the full URL (a URL may hold a token) and never the
response body -- so it is safe to log.

### For the model (off by default)

Once enabled there is an extra `fetch_url` tool:

```yaml
config:
  enableTool: true
```

```
抓一下 https://example.com/demo.html 里写了什么
```

Its return value goes into the model context, which is why it is **off by default** -- enabling
it opens a pipe from "external content" to "the model". The tool description states it
explicitly: what comes back is data, not instructions.

### Just the classification logic (without dsh)

```js
import { isPublicIp, classifyIp } from 'dsh-netguard/src/ip.js'
import { assertPublicUrl } from 'dsh-netguard/src/guard.js'

isPublicIp('169.254.169.254')   // false
```

`src/ip.js` is pure functions: it touches no network and reads no config, so it can be used on
its own.

## What exactly it blocks

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

## What it adds over "just a few regexes"

If you already have an `isPrivateIp()`-style implementation lying around, compare it against
these points:

1. **Alternate spellings.** The old approach is usually prefix regexes like `/^127\./`,
   `/^10\./`, and `127.1`, `2130706433`, `0177.0.0.1`, `0x7f.1` all sail through. Here the 1-to-4
   part spellings are actually parsed into a 32-bit integer with inet_aton semantics before being
   classified.
2. **Blacklist to allowlist.** The old implementation lists 7 private ranges; `192.0.0.0/24`,
   `198.18/15`, `240/4` and the multicast blocks are not in it. Here each block is classified
   against the special-purpose address table, and IPv6 simply allows only `2000::/3`.
3. **IPv4-mapped IPv6.** `::ffff:127.0.0.1` is an IPv4 connection as far as the kernel is
   concerned, and a string-prefix implementation cannot see it at all (the pure hex spelling
   `::ffff:7f00:1` even less). Here it is decoded into 16 bytes and classified bit by bit, and
   6to4 / NAT64 are unpacked the same way.
4. **DNS resolution.** The old implementation classifies only the first record (with `lookup` and
   no `all: true` it may even look at a single family): an attacker who returns two records (one
   public, one private) walks right past it. Here **all** records are required, and one intranet
   record rejects the request.
5. **Redirects.** The old implementation uses the default `redirect: 'follow'`, which hands
   "where to jump" entirely to the other side. Here `redirect: 'manual'` takes over and every hop
   is re-checked.
6. **Size cap.** The old implementation does `arrayBuffer()` and compares afterwards -- the
   memory is already eaten. Here the stream is read and counted as it goes, and cut off the
   moment it goes over. On top of that, `Content-Length` rules it out up front.
7. **Timeout layering.** The old implementation gives each hop its own `AbortSignal.timeout()`
   (it never followed redirects anyway, so this never showed). Here the whole chain shares a
   single deadline.
8. **The sound of failure.** The old implementation does `.catch(() => [])` on a DNS failure and
   then reports "resolution failed", which means the right thing; but here the `code` is split
   out as well (`DNS_FAILED` / `DNS_PRIVATE` / `PRIVATE_ADDRESS`…), so callers can branch on it
   instead of regex-matching a message. It also rejects the credential-in-URL "looks like someone
   else" disguise along the way.

## Tests

```bash
npm test          # 或者分别跑：
node test/selftest.mjs         # 判定逻辑 + 重定向 + 大小上限 + 超时（249 条断言）
node test/plugin-selftest.mjs  # 插件接线：服务/工具/配置覆盖（65 条断言）
```

The two scripts run **314 assertions** in total. **Both are fully offline**: the DNS resolver and
fetch are injected fakes, so no network is
needed, nothing flaps, no keys are required -- and they will never "probe the intranet as a side
effect". The assertions are real: delete any single protection in `src/` and the script turns
red (drop the per-hop redirect re-check and 4 assertions fail; drop the size cap and 7 fail).

## Known limitations

**The parts it does not stop -- saying so beats pretending**

1. **The time-of-check/time-of-use gap between DNS resolution and the actual connection
   (TOCTOU).** We resolve DNS once and classify, then hand it to fetch, which resolves **again**
   before connecting. An attacker with a TTL=0 domain can make the first lookup return a public
   address and the second a private one -- the second form of DNS rebinding, and **this plugin
   does not stop it**. The real fix is to pin the resolution result (implement your own
   dispatcher / connect hook and connect to that IP instead of resolving the name again), or to
   verify the peer address after connecting. Node's global fetch does not expose that hook, so a
   `fetchImpl` injection point is left here for the host to plug in its own implementation.
2. **Proxies.** If the host injects a fetch that goes through a proxy, this plugin's checks run
   **before the proxy**; they only describe the "target address" and say nothing about how the
   proxy resolves and connects. Also, Node's fetch does not read `HTTP_PROXY` / `HTTPS_PROXY` by
   default, but that behaviour depends on the runtime version -- do not count on this layer to
   manage proxies for you.
3. **The content itself.** It only governs "may we go there, and how much may we take", not "what
   does what we brought back say". A fetched page can happily say "ignore all your previous
   instructions". The tool description and the end of the return value both remind you of this,
   but that is a reminder, not a protection.
4. **Not a browser.** `<meta http-equiv="refresh">`, JS redirects, Service Workers -- client-side
   redirects are out of scope (fetch cannot see them either).
5. **Intranet content on a public address.** The attacker's own public server can reverse-proxy
   straight into the intranet -- nothing looks wrong at the address level. This layer does not
   stop it, and it should not be expected to.
6. **The port blocklist is an approximation, not a complete list.** `8081`, `9090`, `5000` may
   well host internal services too. Want it stricter? Add them to `blockedPorts` yourself.
7. **IPv6 allows `2000::/3` only**, so a few legitimate special spellings get blocked by mistake
   (they report `RESERVED`, and that can be changed).
8. **No rate or concurrency limit.** It answers "may we go to this address", not "how many
   times". Real quotas have to be added outside.
9. **GET only**; no uploads, no POST, no long-lived streaming connections.
10. **No DNSSEC validation at the DNS layer** -- whatever the system resolver returns is what
    gets classified. (The CNAME chain does not change the conclusion: it is the final address
    that is classified.)

## License

MIT © 2026 JackZo400
