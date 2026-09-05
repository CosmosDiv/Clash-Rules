/**
 * Sub-Store IPQuality Quality + Network Identity v1.4.0 Stable
 * ------------------------------------------------------------
 * Upstream detection semantics baseline:
 *   xykt/IPQuality v2026-09-04
 *   commit 3c0eb8856c67ad351020d1edd1bfd4e2515d32fe
 *   License: AGPL-3.0
 *
 * Pipeline contract:
 *   Node Standardizer V2.1.5
 *     -> IPQuality V1.4.0
 *     -> Mihomo / OpenClash / Surfing V4.0.1 policy layer
 *
 * v1.4.0 Stable:
 *   - 新增高置信度“失效节点复检/过滤”：一次 Full/EIP 任务内先完成正常 EIP 探测，
 *     仅把“IPv4 当前 Live Probe 完整 Transport Failure 且无任何 EIP”的 route 视为 DeadCandidate；
 *   - DeadCandidate 不会直接删除。先用本轮其他 Live Route 评估环境，再启动独立 Fresh HTTP META Session，
 *     以最多 3 个已知 EIP 成功 route 作为 Control；至少 2 个 Control 现场复测成功后，才复检 Candidate；
 *   - Candidate 在 Fresh META 下再次完整 Transport Failure 才标记 DeadConfirmed；任一复检恢复则 DeadRecovered；
 *   - 过滤失效=1 时只过滤 DeadConfirmed；默认关闭。Chain 默认旁路，Unsupported/Provider/HTTP 状态响应均不会判 Dead；
 *   - Dead 健康门仅使用“本轮真实 Live Probe”，缓存命中不冒充实时健康证据；小样本时由 Fresh Control 兜底；
 *   - 保留 v1.3.2 的 upstream-style HTTP Recovery 与逐 Endpoint EIP DETAIL；不纳入 v1.3.3 实验 Rescue Endpoint。
 *   - RESULT 现在统计最终保留节点；诊断模式且启用过滤时额外输出 RESULT RAW，避免 Dead/Risk 已删除但 RESULT 仍计入的歧义。
 *
 * v1.3.2 RC:
 *   - EIP IPv4 Recovery 增加 upstream-style HTTP fallback：上游 get_ipv4() 使用无 scheme URL，
 *     与我们此前全部硬编码 HTTPS 并不等价；当前保留 HTTPS 快速探测，并在失败后尝试 HTTP Recovery；
 *   - 日志详情=1 时，EIP 失败新增逐 Endpoint 诊断，区分 Timeout/TLS/DNS/HTTP/WrongFamily；
 *   - Quality / Identity / Risk / Chain / Provider 逻辑均不变。
 *
 * v1.3.1 RC:
 *   - 修复 Provider Cache 日志统计：MaxMind Lite / 安全跳过不再误记为 MISS；
 *   - PROVIDER CACHE 日志新增 skip=；检测、缓存与 Policy 语义均不变。
 *
 * v1.3.0 Upstream Parity Refactor:
 *   - 正式输出契约保持不变：Trust/Normal/Risk/Unrated + ConsIP/BusiIP/HostIP/UnkIP；
 *   - Risk 过滤、Chain 默认旁路、Quality / Identity 裁决算法保持不变；
 *   - EIP 引擎升级为 IPv4 / IPv6 双栈模型；默认同时发现，策略判定仍默认 IPv4 优先；
 *   - 新增 IPv4/IPv6 专用 EIP Endpoint，弥补 Sub-Store HTTP Client 没有 curl -4/-6 的差异；
 *   - EIP Cache 升级到 v2，并自动迁移 v1 单 IP 缓存；
 *   - 同配置节点在同一冷启动批次只探测一次 EIP，再向同 fingerprint 节点传播；
 *   - Provider 对齐 xykt/IPQuality v2026-09-04，ipapi 改用 ipinfo.check.place ?db=ipapi；
 *   - 显式目标 IP 的 Provider 支持“代理优先 -> DIRECT 安全回退”，避免出口被 API/CDN 阻断后整项缺失；
 *   - DB-IP /self 严禁 DIRECT 回退；IPv6 继续安全跳过，避免把 Sub-Store 宿主出口误当目标节点；
 *   - Provider 成功缓存判定同时承认 Quality 与 Network Identity 有效字段；
 *   - 新增 Provider 强制刷新、阶段模式、EIP/Provider 覆盖率与失败类型日志；
 *   - v1.0.1 Provider Cache namespace 继续沿用，避免无必要的全量数据库冷启动。
 *
 * ------------------------------------------------------------
 * 正式名称协议（不可随意修改）：
 *   Region @Source IPQualityTag·IPQualityTag·StandardizerTag...｜Tail
 *
 * Quality:
 *   Risk    任意可靠来源出现明确高风险评分或明确恶意事实
 *   Trust   至少 3 个评分源有效；全部 Clean；无 Caution / Risk
 *   Normal  至少 1 个评分源有效且无 Risk，但未达到 Trust
 *   Unrated 无评分证据，或检测链路无法完成
 *
 * Network Identity:
 *   ConsIP / BusiIP / HostIP / UnkIP
 *
 * Standardizer Manual Source:
 *   ResIP / Mobile / SatNet -> C
 *   ISP                     -> I
 *   DediSrv                 -> H
 *   StaticIP / DynIP / DediIP / NativeIP / IPv6 不直接参与 Identity
 *
 * ------------------------------------------------------------
 * 参数：
 *   诊断 = 0
 *   过滤Risk =              // 未填写：正式模式默认1，诊断模式默认0
 *   检测Chain = 0
 *   过滤失效 = 0          // 仅过滤 Fresh META 二次确认的 DeadConfirmed；默认关闭
 *   失效复检 = 1          // DeadCandidate 使用 Fresh META + Control Node 二次确认
 *
 *   阶段 = Full             // Full / EIP / Provider
 *   地址族 = 双栈           // 双栈 / IPv4 / IPv6
 *   主地址族 = IPv4         // 双栈时 Quality/Identity 使用哪个 EIP；缺失时自动回退另一族
 *
 *   成功缓存小时 = 20
 *   失败缓存小时 = 2
 *   强制刷新 = 0            // EIP + Provider 全刷新
 *   Provider强制刷新 = 0   // 仅 Provider
 *
 *   出口缓存分钟 = 30
 *   出口失败缓存分钟 = 2
 *   出口强制刷新 = 0
 *   出口并发 = 4
 *   出口timeout = 2500
 *   出口恢复timeout = 4500
 *
 *   数据并发 = 2
 *   数据timeout = 10000
 *   Provider直连回退 = 1   // 仅显式指定目标 IP 的 API；DB-IP /self 永不回退
 *
 *   日志 = 1
 *   日志详情 = 0
 *
 *   proxycheck_key =
 *   http_meta_host = 127.0.0.1
 *   http_meta_port = 9876
 *   http_meta_protocol = http
 *   http_meta_authorization =
 *   http_meta_start_delay = 1800
 *   http_meta_proxy_timeout = 15000
 */

const IPQUALITY_VERSION = '1.4.0'
const UPSTREAM_VERSION = 'v2026-09-04'
const UPSTREAM_COMMIT = '3c0eb8856c67ad351020d1edd1bfd4e2515d32fe'

const EXIT_CACHE_KEY = 'ipqlite:eip:v2'
const LEGACY_EXIT_CACHE_KEY = 'ipqlite:eip:v1'
const PROVIDER_CACHE_PREFIX = 'ipqlite:v101:'
const RUN_MARKER_PREFIX = 'ipqlite:run:v1:'

// Dead filter safety gates are intentionally internal, not user-facing tuning knobs.
const DEAD_ENV_MIN_LIVE = 8
const DEAD_ENV_HEALTHY_RATE = 0.75
const DEAD_ENV_BAD_RATE = 0.50
const DEAD_CONTROL_COUNT = 3
const DEAD_CONTROL_MIN = 2
const DEAD_MIN_ENDPOINTS = 3
const DEAD_TRANSPORT_REASONS = new Set(['Timeout', 'TLS', 'Connect', 'DNS', 'RequestErr'])

const EIP_ENDPOINTS = Object.freeze({
  4: Object.freeze({
    // DNS/endpoint-level IPv4 constraints. These are our Sub-Store equivalent
    // to upstream curl -4 where the HTTP runtime itself exposes no family flag.
    fast: Object.freeze([
      ['ipify4', 'https://api.ipify.org'],
      ['ican4', 'https://ipv4.icanhazip.com'],
      ['ident4', 'https://4.ident.me'],
    ]),
    // Upstream v2026-09-04 get_ipv4() lists these hosts without an explicit
    // scheme. curl's handling is not equivalent to our former HTTPS-only list.
    // In Sub-Store we therefore keep HTTPS fast probes, then try an HTTP recovery
    // path matching the upstream host set. Bodies are still family-validated.
    recovery: Object.freeze([
      ['ipinfo-http', 'http://ipinfo.io/ip'],
      ['checkplace-http', 'http://myip.check.place'],
      ['ipsb-http', 'http://ip.sb'],
      ['ping0-http', 'http://ping0.cc'],
      ['ican-http', 'http://icanhazip.com'],
      ['ipify64-http', 'http://api64.ipify.org'],
      ['ifconfig-http', 'http://ifconfig.co'],
      ['ident-http', 'http://ident.me'],
    ]),
    // Secondary compatibility path: preserve the previous HTTPS recovery set
    // after the upstream-style HTTP path fails.
    recoveryHttps: Object.freeze([
      ['ipinfo-https', 'https://ipinfo.io/ip'],
      ['checkplace-https', 'https://myip.check.place'],
      ['ipsb-https', 'https://ip.sb'],
      ['ping0-https', 'https://ping0.cc'],
      ['ican-https', 'https://icanhazip.com'],
      ['ipify64-https', 'https://api64.ipify.org'],
      ['ifconfig-https', 'https://ifconfig.co'],
      ['ident-https', 'https://ident.me'],
    ]),
  }),
  6: Object.freeze({
    // Family-specific endpoints are required here because generic dual-stack
    // hosts cannot reproduce curl -6 reliably in Sub-Store.
    fast: Object.freeze([
      ['ipify6', 'https://api6.ipify.org'],
      ['ican6', 'https://ipv6.icanhazip.com'],
      ['ident6', 'https://6.ident.me'],
    ]),
    recovery: Object.freeze([]),
  }),
})

async function operator(proxies = [], targetPlatform, env = {}) {
  const $ = $substore
  const args = typeof $arguments === 'object' && $arguments ? $arguments : {}
  const startedAt = Date.now()
  const runId = createRunId()

  const stageMode = parseStageMode(args['阶段'])
  const familyMode = parseAddressFamilyMode(args['地址族'])
  const primaryPreference = parsePrimaryFamily(args['主地址族'])

  const exitConcurrency = clampInt(args['出口并发'], 4, 1, 12)
  const dataConcurrency = clampInt(args['数据并发'], 2, 1, 6)
  const exitTimeout = clampInt(args['出口timeout'], 2500, 1200, 15000)
  const exitRecoveryTimeout = clampInt(args['出口恢复timeout'], 4500, exitTimeout, 20000)
  const dataTimeout = clampInt(args['数据timeout'], 10000, 5000, 30000)
  const proxycheckKey = String(args.proxycheck_key || '').trim()

  const successCacheHours = Math.max(0, numberArg(args['成功缓存小时'], 20))
  const failCacheHours = Math.max(0, numberArg(args['失败缓存小时'], 2))
  const forceRefresh = isTruthy(args['强制刷新'])
  const providerForceRefresh = forceRefresh || isTruthy(args['Provider强制刷新'])
  const exitCacheMinutes = Math.max(0, numberArg(args['出口缓存分钟'], 30))
  const exitFailCacheMinutes = Math.max(0, numberArg(args['出口失败缓存分钟'], 2))
  const exitForceRefresh = forceRefresh || isTruthy(args['出口强制刷新'])

  const diagnostic = isTruthy(args['诊断'])
  const detectChain = isTruthy(args['检测Chain'])
  const filterDead = isTruthy(args['过滤失效'])
  const deadRecheck = Object.prototype.hasOwnProperty.call(args, '失效复检')
    ? isTruthy(args['失效复检'])
    : true
  const hasFilterRiskArg = Object.prototype.hasOwnProperty.call(args, '过滤Risk')
  const filterRisk = hasFilterRiskArg ? isTruthy(args['过滤Risk']) : !diagnostic
  const allowDirectFallback = Object.prototype.hasOwnProperty.call(args, 'Provider直连回退')
    ? isTruthy(args['Provider直连回退'])
    : true
  const logEnabled = Object.prototype.hasOwnProperty.call(args, '日志') ? isTruthy(args['日志']) : true
  const logDetails = isTruthy(args['日志详情'])

  const cache = typeof scriptResourceCache !== 'undefined' ? scriptResourceCache : null
  const cacheAvailable = !!(cache && typeof cache.get === 'function' && typeof cache.set === 'function')

  const host = String(args.http_meta_host || '127.0.0.1')
  const port = String(args.http_meta_port || '9876')
  const protocol = String(args.http_meta_protocol || 'http')
  const authorization = String(args.http_meta_authorization || '')
  const startDelay = Math.max(0, clampInt(args.http_meta_start_delay, 1800, 0, 30000))
  const perProxyTimeout = clampInt(args.http_meta_proxy_timeout, 15000, 6000, 60000)
  const api = `${protocol}://${host}:${port}`

  const log = createRunLogger($, runId, logEnabled)
  const output = proxies.map(p => ({ ...p }))
  const internal = []
  const riskIndices = new Set()
  const deadIndices = new Set()
  const sessions = []

  let chainBypass = 0
  let unsupported = 0
  let stage = 'prepare'
  let runMarker = null

  const eipStats = createEipStats()
  const providerStats = createProviderStats()

  for (let i = 0; i < proxies.length; i++) {
    const proxy = proxies[i]
    const isChain = isChainNodeName(proxy?.name)

    if (isChain && !detectChain) {
      chainBypass++
      continue
    }

    try {
      const node = ProxyUtils.produce([{ ...proxy }], 'ClashMeta', 'internal', {
        'include-unsupported-proxy': true,
      })?.[0]

      if (!node) {
        unsupported++
        if (stageMode !== 'EIP' || diagnostic) {
          output[i].name = addTempTags(
            proxy.name,
            diagnostic ? ['Unrated', 'UnkIP', 'IPProbeUnsup'] : ['Unrated', 'UnkIP']
          )
        }
        continue
      }

      for (const key in proxy) {
        if (/^_/i.test(key)) node[key] = proxy[key]
      }

      internal.push({
        index: i,
        node,
        originalName: String(proxy.name || ''),
        isChain,
        fingerprint: nodeFingerprint(node),
        localProxy: '',
        eip4: '',
        eip6: '',
        eip4Reason: '',
        eip6Reason: '',
        eip4Source: '',
        eip6Source: '',
        eip4Details: [],
        eip6Details: [],
        eip4Live: false,
        eip6Live: false,
        deadState: '',
        primaryIp: '',
        primaryFamily: 0,
      })
    } catch (_) {
      unsupported++
      if (stageMode !== 'EIP' || diagnostic) {
        output[i].name = addTempTags(
          proxy.name,
          diagnostic ? ['Unrated', 'UnkIP', 'IPProbeUnsup'] : ['Unrated', 'UnkIP']
        )
      }
    }
  }

  log.info(
    `START | version=${IPQUALITY_VERSION} upstream=${UPSTREAM_VERSION} ` +
    `stage=${stageMode} family=${familyMode.label} primary=${primaryPreference === 6 ? 'IPv6' : 'IPv4'} ` +
    `input=${proxies.length} detect=${internal.length} chain-bypass=${chainBypass} unsupported=${unsupported} ` +
    `dead-filter=${filterDead ? 'on' : 'off'} dead-recheck=${deadRecheck ? 'on' : 'off'} ` +
    `cache=${cacheAvailable ? 'available' : 'unavailable'}`
  )

  if (!internal.length) {
    log.info(`DONE | output=${output.length} duration=${formatDuration(Date.now() - startedAt)}`)
    return output
  }

  const runScope = hashString(internal.map(x => x.fingerprint).sort().join('|'))
  runMarker = markRunStarted(cache, runScope, runId, startedAt)
  if (runMarker?.previous?.active) {
    log.warn(
      `OVERLAP | previous=${runMarker.previous.id || 'unknown'} ` +
      `age=${formatDuration(Date.now() - Number(runMarker.previous.ts || Date.now()))}; current run continues`
    )
  }

  const exitCache = loadExitCache(cache, eipStats)
  // Persist a successful legacy v1 -> v2 migration even when no live probe is needed.
  let exitCacheDirty = eipStats.legacyMigrated > 0

  try {
    stage = 'eip-cache'

    for (const item of internal) {
      if (familyMode.want4) {
        applyExitCacheFamily(
          item, 4, exitCache, exitCacheMinutes, exitFailCacheMinutes,
          exitForceRefresh, eipStats
        )
      }
      if (familyMode.want6) {
        applyExitCacheFamily(
          item, 6, exitCache, exitCacheMinutes, exitFailCacheMinutes,
          exitForceRefresh, eipStats
        )
      }
    }

    log.info(
      `EIP CACHE | v4=${formatEipFamilyCacheStats(eipStats.v4)} ` +
      `v6=${formatEipFamilyCacheStats(eipStats.v6)} ` +
      `legacy-migrated=${eipStats.legacyMigrated} force=${exitForceRefresh ? 'on' : 'off'}`
    )

    if (stageMode !== 'Provider') {
      stage = 'eip-probe'
      const probeGroups = buildEipProbeGroups(internal, familyMode)

      if (probeGroups.length) {
        log.info(
          `HTTP META | start EIP probe routes=${probeGroups.length} ` +
          `nodes=${probeGroups.reduce((n, g) => n + g.members.length, 0)}`
        )

        const representatives = probeGroups.map(g => g.rep)
        const session = await startHttpMetaSession(
          $, api, authorization, representatives, startDelay, perProxyTimeout
        )
        sessions.push(session)

        for (let i = 0; i < probeGroups.length; i++) {
          probeGroups[i].rep.localProxy = `http://${host}:${session.ports[i]}`
        }

        let done = 0
        const reportProgress = createProgressReporter(probeGroups.length, n => {
          log.info(`EIP PROBE | ${n}/${probeGroups.length} routes`)
        })

        const tasks = probeGroups.map(group => async () => {
          const rep = group.rep
          const jobs = []

          if (group.need4) {
            jobs.push(
              probeExitFamily($, rep.localProxy, 4, exitTimeout, exitRecoveryTimeout)
                .then(result => ({ family: 4, result }))
            )
          }
          if (group.need6) {
            jobs.push(
              probeExitFamily($, rep.localProxy, 6, exitTimeout, exitRecoveryTimeout)
                .then(result => ({ family: 6, result }))
            )
          }

          const results = await Promise.all(jobs)
          for (const { family, result } of results) {
            applyProbeResultToGroup(group, family, result)
            const bucket = family === 6 ? eipStats.v6 : eipStats.v4
            bucket.probeRoutes++
            if (result.ok) bucket.probeSuccess++
            else bucket.probeFail++

            if (logDetails && !result.ok) {
              const detail = formatEipProbeDetails(result.details)
              log.info(
                `EIP DETAIL | node=${eipNodeLabel(rep.originalName)} ` +
                `family=IPv${family} final=${sanitizeReason(result.reason || 'ProbeFail')} ` +
                `endpoints=${detail || '-'}`
              )
            }

            const ttlEnabled = result.ok ? exitCacheMinutes > 0 : exitFailCacheMinutes > 0
            if (ttlEnabled) {
              setExitCacheFamilyEntry(
                exitCache,
                rep.fingerprint,
                family,
                result.ok,
                result.ip || '',
                result.reason || '',
                result.source || ''
              )
              exitCacheDirty = true
            }
          }

          done++
          reportProgress(done)
        })

        await runConcurrent(tasks, exitConcurrency)
      } else {
        log.info('HTTP META | skip EIP probe; all requested address families resolved from cache')
      }
    } else {
      // Provider-only mode deliberately never performs live EIP discovery.
      for (const item of internal) {
        if (familyMode.want4 && !item.eip4 && !item.eip4Reason) item.eip4Reason = 'CacheMiss'
        if (familyMode.want6 && !item.eip6 && !item.eip6Reason) item.eip6Reason = 'CacheMiss'
      }
      log.info('EIP PROBE | skipped by stage=Provider; cache-only EIP input')
    }

    for (const item of internal) {
      selectPrimaryEip(item, familyMode, primaryPreference)
    }

    // High-confidence dead-node verification. A first-pass EIP miss is never enough:
    // only current-run IPv4 transport-dead evidence can become a candidate, and a
    // separate Fresh META session with live controls must pass before confirmation.
    if (stageMode !== 'Provider' && familyMode.want4) {
      const deadResult = await verifyDeadCandidates({
        $, api, authorization, httpMetaHost: host, internal, familyMode, primaryPreference,
        exitTimeout, exitRecoveryTimeout, exitConcurrency, startDelay, perProxyTimeout,
        deadRecheck, filterDead, log, logDetails, exitCache, exitCacheMinutes,
        exitFailCacheMinutes,
      })
      for (const i of deadResult.confirmedIndices) deadIndices.add(i)
      if (deadResult.cacheDirty) exitCacheDirty = true
    } else if (filterDead && stageMode === 'Provider') {
      log.warn('DEAD CHECK | skipped stage=Provider; no live EIP evidence, safety=hold')
    }

    if (exitCacheDirty) {
      persistExitCache(
        cache,
        exitCache,
        Math.max(exitCacheMinutes, exitFailCacheMinutes),
        exitCacheMinutes,
        exitFailCacheMinutes,
        eipStats
      )
    }

    if (eipStats.cacheReadError || eipStats.cacheWriteError) {
      log.warn(
        `EIP CACHE ERROR | read=${eipStats.cacheReadError} write=${eipStats.cacheWriteError}`
      )
    }

    const coverage = summarizeEipCoverage(internal, familyMode)
    log.info(
      `EIP RESULT | ipv4=${coverage.ipv4} ipv6=${coverage.ipv6} dual=${coverage.dual} ` +
      `v4-only=${coverage.v4Only} v6-only=${coverage.v6Only} no-eip=${coverage.none} ` +
      `primary-known=${coverage.primaryKnown}`
    )

    const fail4 = formatFailureReasons(internal, 4, familyMode.want4)
    const fail6 = formatFailureReasons(internal, 6, familyMode.want6)
    if (fail4 || fail6) {
      log.info(`EIP FAIL | v4=${fail4 || '-'} | v6=${fail6 || '-'}`)
    }

    if (stageMode === 'EIP') {
      if (diagnostic) {
        for (const item of internal) {
          output[item.index].name = addTempTags(
            item.originalName,
            [...buildEipDiagnosticTags(item, familyMode), ...buildDeadDiagnosticTags(item)]
          )
        }
      }
      const eipOutput = filterDead ? output.filter((_, i) => !deadIndices.has(i)) : output
      log.info(
        `DEAD FILTER | enabled=${filterDead ? 'on' : 'off'} confirmed=${deadIndices.size} ` +
        `removed=${filterDead ? deadIndices.size : 0}`
      )
      log.info(
        `DONE | stage=EIP output=${eipOutput.length} dead-removed=${filterDead ? deadIndices.size : 0} ` +
        `duration=${formatDuration(Date.now() - startedAt)}`
      )
      return eipOutput
    }

    // Nodes with no primary EIP cannot enter Provider/Policy stages.
    for (const item of internal) {
      if (item.primaryIp) continue
      output[item.index].name = addTempTags(
        item.originalName,
        diagnostic
          ? ['Unrated', 'UnkIP', ...buildEipDiagnosticTags(item, familyMode), ...buildDeadDiagnosticTags(item)]
          : ['Unrated', 'UnkIP']
      )
    }

    // Deduplicate by the policy EIP. Prefer a representative that already owns
    // a live localProxy from the EIP stage.
    const representatives = new Map()
    for (const item of internal) {
      if (!item.primaryIp) continue
      const current = representatives.get(item.primaryIp)
      if (!current || (!current.localProxy && item.localProxy)) {
        representatives.set(item.primaryIp, item)
      }
    }

    stage = 'provider-preflight'
    const providerProxyItems = []
    for (const [ip, item] of representatives.entries()) {
      if (item.localProxy) continue
      if (
        providerNeedsLocalProxy(
          cache, ip, successCacheHours, failCacheHours, providerForceRefresh
        )
      ) {
        providerProxyItems.push(item)
      }
    }

    if (providerProxyItems.length) {
      log.info(
        `HTTP META | provider refresh needs representative nodes=${providerProxyItems.length}`
      )
      const session = await startHttpMetaSession(
        $, api, authorization, providerProxyItems, startDelay, perProxyTimeout
      )
      sessions.push(session)
      for (let i = 0; i < providerProxyItems.length; i++) {
        providerProxyItems[i].localProxy = `http://${host}:${session.ports[i]}`
      }
    } else {
      log.info('HTTP META | provider refresh needs no live representative')
    }

    stage = 'provider-check'
    const checkMap = new Map()
    const repEntries = [...representatives.entries()]
    let providerDone = 0
    const reportProviderProgress = createProgressReporter(repEntries.length, n => {
      log.info(`PROVIDER CHECK | ${n}/${repEntries.length} EIP`)
    })

    log.info(
      `PROVIDER CHECK | unique-eip=${repEntries.length} concurrency=${dataConcurrency} ` +
      `force=${providerForceRefresh ? 'on' : 'off'} direct-fallback=${allowDirectFallback ? 'on' : 'off'}`
    )

    const checkTasks = repEntries.map(([ip, item]) => async () => {
      const r = await queryProviderSet({
        $,
        cache,
        ip,
        localProxy: item.localProxy || '',
        dataTimeout,
        proxycheckKey,
        successCacheHours,
        failCacheHours,
        force: providerForceRefresh,
        allowDirectFallback,
      })

      recordProviderStats(r, providerStats)
      checkMap.set(ip, r)
      providerDone++
      reportProviderProgress(providerDone)
    })

    await runConcurrent(checkTasks, dataConcurrency)

    log.info(
      `PROVIDER CACHE | hit=${providerStats.hit} miss=${providerStats.miss} skip=${providerStats.skip} ` +
      `read-error=${providerStats.readError} write-error=${providerStats.writeError}`
    )
    log.info(
      `PROVIDER HEALTH | usable=${providerStats.usable} json=${providerStats.json} ` +
      `html=${providerStats.html} err=${providerStats.err} skip=${providerStats.skip}`
    )

    if (logDetails) {
      const detail = formatProviderStatsDetail(providerStats.byProvider)
      if (detail) log.info(`PROVIDER DETAIL | ${detail}`)
    }

    stage = 'verdict'
    for (const item of internal) {
      if (!item.primaryIp) continue
      const r = checkMap.get(item.primaryIp) || {}
      const c = buildSimpleVerdict(r)
      const n = buildNetworkIdentity(r, item.originalName)

      let tags
      if (diagnostic) {
        tags = [
          ...buildEipDiagnosticTags(item, familyMode),
          ...buildDeadDiagnosticTags(item),
          c.verdict,
          n.verdict,
          formatNetworkCounts(n.counts),
          formatNetworkSources(n.sources),
          `NetWhy-${n.reason}`,
          `Q${c.ratingValidCount}/7`,
          `Clean${c.cleanCount}/7`,
          `Caution${c.cautionCount}`,
          `RiskSrc${c.riskSourceCount}`,
          `Valid${c.validCount}/10`,
          r._fullMode ? 'Full' : 'Lite',
          c.riskReasons.length ? `RiskReason-${c.riskReasons.join('+')}` : 'RiskReason0',
          c.cautionReasons.length ? `CautionReason-${c.cautionReasons.join('+')}` : 'CautionReason0',
          `VPN${c.vpn.yes}/${c.vpn.valid}`,
          `Proxy${c.proxy.yes}/${c.proxy.valid}`,
          formatMaxmind(r.mm),
          formatFlagProvider('II', r.ii, parseIpinfoFlags),
          formatScoreProviderWithBand('SC', r.sc, d => d?.scamalytics?.scamalytics_score, scBand),
          formatFlagProvider('IR', r.ir, parseIpregistryFlags),
          formatIpapi(r.ia),
          formatScoreProviderWithBand('AB', r.ab, d => d?.data?.abuseConfidenceScore, abuseBand),
          formatScoreProviderWithBand('I2', r.i2, d => d?.fraud_score, i2Band),
          formatDbIp(r.db),
          formatFlagProvider('ID', r.id, parseIpdataFlags),
          formatScoreProviderWithBand('IQ', r.iq, d => d?.fraud_score, iqBand),
          formatProxycheck(r.pc),
        ]
      } else {
        tags = [c.verdict, n.verdict]
      }

      output[item.index].name = addTempTags(item.originalName, tags.filter(Boolean))
      if (c.verdict === 'Risk' && !item.isChain) riskIndices.add(item.index)
    }
  } catch (err) {
    riskIndices.clear()
    log.error(`FAIL | stage=${stage} reason=${errorMessage(err)}`)
    for (const item of internal) {
      output[item.index].name = addTempTags(
        item.originalName,
        diagnostic
          ? ['Unrated', 'UnkIP', 'IPQStageErr', ...buildEipDiagnosticTags(item, familyMode)]
          : ['Unrated', 'UnkIP']
      )
    }
  } finally {
    for (const session of sessions) {
      await stopHttpMetaSession($, api, authorization, session)
    }
    markRunFinished(cache, runMarker, runId)
  }

  const rawCounts = countFinalClassifications(output)
  const finalOutput = output.filter((_, i) => {
    if (filterRisk && riskIndices.has(i)) return false
    if (filterDead && deadIndices.has(i)) return false
    return true
  })
  const counts = countFinalClassifications(finalOutput)

  if (diagnostic && (filterRisk || filterDead)) {
    log.info(
      `RESULT RAW | Trust=${rawCounts.quality.Trust} Normal=${rawCounts.quality.Normal} ` +
      `Risk=${rawCounts.quality.Risk} Unrated=${rawCounts.quality.Unrated} ` +
      `ConsIP=${rawCounts.identity.ConsIP} BusiIP=${rawCounts.identity.BusiIP} ` +
      `HostIP=${rawCounts.identity.HostIP} UnkIP=${rawCounts.identity.UnkIP}`
    )
  }
  log.info(
    `RESULT | Trust=${counts.quality.Trust} Normal=${counts.quality.Normal} ` +
    `Risk=${counts.quality.Risk} Unrated=${counts.quality.Unrated} ` +
    `ConsIP=${counts.identity.ConsIP} BusiIP=${counts.identity.BusiIP} ` +
    `HostIP=${counts.identity.HostIP} UnkIP=${counts.identity.UnkIP}`
  )
  log.info(
    `DEAD FILTER | enabled=${filterDead ? 'on' : 'off'} confirmed=${deadIndices.size} ` +
    `removed=${filterDead ? deadIndices.size : 0}`
  )
  log.info(
    `DONE | output=${finalOutput.length} risk-removed=${filterRisk ? riskIndices.size : 0} ` +
    `dead-removed=${filterDead ? deadIndices.size : 0} ` +
    `duration=${formatDuration(Date.now() - startedAt)}`
  )
  return finalOutput
}

async function queryProviderSet(ctx) {
  const {
    $, cache, ip, localProxy, dataTimeout, proxycheckKey,
    successCacheHours, failCacheHours, force, allowDirectFallback,
  } = ctx

  const r = {}

  r.mm = await cachedProvider(
    cache, 'mm', ip, successCacheHours, failCacheHours, force,
    () => queryMaxmindBase($, ip, localProxy, dataTimeout, allowDirectFallback)
  )
  const fullMode = maxmindBaseUsable(r.mm)

  r.ii = await cachedProvider(
    cache, 'ii', ip, successCacheHours, failCacheHours, force,
    () => queryIpinfo($, ip, localProxy, dataTimeout, allowDirectFallback)
  )

  if (fullMode) {
    r.sc = await cachedProvider(
      cache, 'sc', ip, successCacheHours, failCacheHours, force,
      () => queryCheckPlaceDb($, ip, 'scamalytics', 'sc', localProxy, dataTimeout, allowDirectFallback)
    )
  } else r.sc = skippedByMaxmind()

  r.ir = await cachedProvider(
    cache, 'ir', ip, successCacheHours, failCacheHours, force,
    () => queryIpregistry($, ip, localProxy, dataTimeout, allowDirectFallback)
  )

  r.ia = await cachedProvider(
    cache, 'ia', ip, successCacheHours, failCacheHours, force,
    () => queryIpapi($, ip, localProxy, dataTimeout, allowDirectFallback)
  )

  if (fullMode) {
    r.ab = await cachedProvider(
      cache, 'ab', ip, successCacheHours, failCacheHours, force,
      () => queryCheckPlaceDb($, ip, 'abuseipdb', 'ab', localProxy, dataTimeout, allowDirectFallback)
    )
  } else r.ab = skippedByMaxmind()

  if (fullMode) {
    r.i2 = await cachedProvider(
      cache, 'i2', ip, successCacheHours, failCacheHours, force,
      () => queryCheckPlaceDb($, ip, 'ip2location', 'i2', localProxy, dataTimeout, allowDirectFallback)
    )
  } else r.i2 = skippedByMaxmind()

  r.db = await cachedProvider(
    cache, 'db', ip, successCacheHours, failCacheHours, force,
    () => queryDbIp($, ip, localProxy, dataTimeout)
  )

  if (fullMode) {
    r.id = await cachedProvider(
      cache, 'id', ip, successCacheHours, failCacheHours, force,
      () => queryCheckPlaceDb($, ip, 'ipdata', 'id', localProxy, dataTimeout, allowDirectFallback)
    )
  } else r.id = skippedByMaxmind()

  if (fullMode) {
    r.iq = await cachedProvider(
      cache, 'iq', ip, successCacheHours, failCacheHours, force,
      () => queryCheckPlaceDb($, ip, 'ipqualityscore', 'iq', localProxy, dataTimeout, allowDirectFallback)
    )
  } else r.iq = skippedByMaxmind()

  r.pc = await cachedProvider(
    cache, 'pc', ip, successCacheHours, failCacheHours, force,
    () => queryProxycheck($, ip, localProxy, proxycheckKey, dataTimeout, allowDirectFallback)
  )

  r._fullMode = fullMode
  return r
}

function parseStageMode(value) {
  const s = String(value ?? 'Full').trim().toLowerCase()
  if (['eip', '出口', '出口ip', 'ip'].includes(s)) return 'EIP'
  if (['provider', 'providers', '数据', '数据库'].includes(s)) return 'Provider'
  return 'Full'
}

function parseAddressFamilyMode(value) {
  const s = String(value ?? '双栈').trim().toLowerCase()
  if (['4', 'v4', 'ipv4', '仅ipv4', '只ipv4'].includes(s)) {
    return { want4: true, want6: false, label: 'IPv4' }
  }
  if (['6', 'v6', 'ipv6', '仅ipv6', '只ipv6'].includes(s)) {
    return { want4: false, want6: true, label: 'IPv6' }
  }
  return { want4: true, want6: true, label: 'Dual' }
}

function parsePrimaryFamily(value) {
  const s = String(value ?? 'IPv4').trim().toLowerCase()
  return ['6', 'v6', 'ipv6'].includes(s) ? 6 : 4
}

function clampInt(value, fallback, min, max) {
  const n = parseInt(value ?? fallback, 10)
  const safe = Number.isFinite(n) ? n : fallback
  return Math.max(min, Math.min(max, safe))
}

function numberArg(value, fallback) {
  const n = Number(value ?? fallback)
  return Number.isFinite(n) ? n : fallback
}

function createRunId() {
  return `${Date.now().toString(36).slice(-4)}${Math.random().toString(36).slice(2, 4)}`.toUpperCase()
}

function createRunLogger($, runId, enabled) {
  const emit = (level, message) => {
    if (!enabled) return
    const line = `[IPQuality#${runId}] ${message}`
    try {
      if ($ && typeof $[level] === 'function') {
        $[level](line)
        return
      }
      if ($ && typeof $.log === 'function') {
        $.log(line)
        return
      }
      if (typeof console !== 'undefined') {
        const fn = typeof console[level] === 'function' ? console[level] : console.log
        fn.call(console, line)
      }
    } catch (_) {}
  }
  return {
    info: message => emit('info', message),
    warn: message => emit('warn', message),
    error: message => emit('error', message),
  }
}

function createProgressReporter(total, callback) {
  if (!total || typeof callback !== 'function') return () => {}
  const marks = new Set([
    Math.max(1, Math.ceil(total * 0.25)),
    Math.max(1, Math.ceil(total * 0.50)),
    Math.max(1, Math.ceil(total * 0.75)),
    total,
  ])
  return done => {
    if (!marks.has(done)) return
    marks.delete(done)
    callback(done)
  }
}

async function startHttpMetaSession($, api, authorization, items, startDelay, perProxyTimeout) {
  if (!items.length) throw new Error('HTTP META start called with empty items')
  const totalTimeout = startDelay + items.length * perProxyTimeout
  const startRes = await request($, {
    method: 'post',
    url: `${api}/start`,
    headers: {
      'Content-Type': 'application/json',
      Authorization: authorization,
    },
    body: JSON.stringify({ proxies: items.map(x => x.node), timeout: totalTimeout }),
    timeout: 30000,
  })

  const startBody = json(startRes.body)
  if (
    !startBody?.pid ||
    !Array.isArray(startBody?.ports) ||
    startBody.ports.length !== items.length ||
    startBody.ports.some(p => !Number.isFinite(Number(p)) || Number(p) <= 0)
  ) {
    throw new Error('HTTP META start invalid')
  }

  if (startDelay) await $.wait(startDelay)
  return { pid: startBody.pid, ports: startBody.ports.map(Number) }
}

async function stopHttpMetaSession($, api, authorization, session) {
  if (!session?.pid) return
  try {
    await request($, {
      method: 'post',
      url: `${api}/stop`,
      headers: {
        'Content-Type': 'application/json',
        Authorization: authorization,
      },
      body: JSON.stringify({ pid: [session.pid] }),
      timeout: 5000,
    })
  } catch (_) {}
}

function createEipStats() {
  const family = () => ({
    hit: 0,
    failHit: 0,
    miss: 0,
    probeRoutes: 0,
    probeSuccess: 0,
    probeFail: 0,
  })
  return {
    v4: family(),
    v6: family(),
    cacheReadError: 0,
    cacheWriteError: 0,
    legacyMigrated: 0,
  }
}

function createProviderStats() {
  return {
    hit: 0,
    miss: 0,
    readError: 0,
    writeError: 0,
    usable: 0,
    json: 0,
    html: 0,
    err: 0,
    skip: 0,
    byProvider: {},
  }
}

function loadExitCache(cache, stats) {
  const empty = { version: 2, entries: {} }
  if (!cache || typeof cache.get !== 'function') return empty

  try {
    const raw = cache.get(EXIT_CACHE_KEY)
    if (raw && raw.version === 2 && raw.entries && typeof raw.entries === 'object') {
      return { version: 2, entries: cloneExitEntries(raw.entries) }
    }
  } catch (_) {
    if (stats) stats.cacheReadError++
  }

  // Best-effort migration from v1 single-IP cache. We never delete the old key.
  try {
    const legacy = cache.get(LEGACY_EXIT_CACHE_KEY)
    if (!legacy || !legacy.entries || typeof legacy.entries !== 'object') return empty

    const migrated = {}
    for (const [fingerprint, entry] of Object.entries(legacy.entries)) {
      if (!entry?.ts) continue
      if (entry.ok) {
        const ip = normalizeIp(entry.ip)
        if (!ip) continue
        const family = isIPv4(ip) ? 'ipv4' : isIPv6(ip) ? 'ipv6' : ''
        if (!family) continue
        migrated[fingerprint] = {
          [family]: {
            ts: Number(entry.ts),
            ok: true,
            ip,
            reason: '',
            source: 'legacy-v1',
          },
        }
      } else {
        // v1 failure did not identify a family, so it is unsafe to migrate it.
        continue
      }
    }

    if (stats) stats.legacyMigrated = Object.keys(migrated).length
    return { version: 2, entries: migrated }
  } catch (_) {
    if (stats) stats.cacheReadError++
    return empty
  }
}

function cloneExitEntries(entries) {
  const out = {}
  for (const [fingerprint, entry] of Object.entries(entries || {})) {
    out[fingerprint] = {}
    if (entry?.ipv4) out[fingerprint].ipv4 = { ...entry.ipv4 }
    if (entry?.ipv6) out[fingerprint].ipv6 = { ...entry.ipv6 }
  }
  return out
}

function getExitCacheFamilyEntry(store, fingerprint, family, successMinutes, failMinutes, force) {
  if (force || !store?.entries || !fingerprint) return { hit: false }

  const familyKey = family === 6 ? 'ipv6' : 'ipv4'
  const entry = store.entries[fingerprint]?.[familyKey]
  if (!entry?.ts) return { hit: false }

  const ttlMinutes = entry.ok ? successMinutes : failMinutes
  if (!(ttlMinutes > 0)) return { hit: false }

  const age = Date.now() - Number(entry.ts)
  if (age < 0 || age >= ttlMinutes * 60 * 1000) return { hit: false }

  if (entry.ok) {
    const ip = normalizeIp(entry.ip)
    const valid = family === 6 ? isIPv6(ip) : isIPv4(ip)
    if (!valid) return { hit: false }
    return {
      hit: true,
      ok: true,
      ip,
      source: String(entry.source || 'cache'),
      reason: '',
    }
  }

  return {
    hit: true,
    ok: false,
    ip: '',
    source: String(entry.source || 'cache'),
    reason: sanitizeReason(entry.reason || 'CachedFail'),
  }
}

function applyExitCacheFamily(item, family, store, successMinutes, failMinutes, force, stats) {
  const cached = getExitCacheFamilyEntry(
    store, item.fingerprint, family, successMinutes, failMinutes, force
  )
  const bucket = family === 6 ? stats.v6 : stats.v4

  if (cached.hit && cached.ok) {
    bucket.hit++
    if (family === 6) {
      item.eip6 = cached.ip
      item.eip6Source = cached.source
    } else {
      item.eip4 = cached.ip
      item.eip4Source = cached.source
    }
    return
  }

  if (cached.hit && !cached.ok) {
    bucket.failHit++
    if (family === 6) item.eip6Reason = cached.reason || 'CachedFail'
    else item.eip4Reason = cached.reason || 'CachedFail'
    return
  }

  bucket.miss++
}

function setExitCacheFamilyEntry(store, fingerprint, family, ok, ip, reason, source) {
  if (!store?.entries || !fingerprint) return
  const familyKey = family === 6 ? 'ipv6' : 'ipv4'
  const current = store.entries[fingerprint] || {}
  current[familyKey] = {
    ts: Date.now(),
    ok: !!ok,
    ip: ok ? normalizeIp(ip) : '',
    reason: ok ? '' : sanitizeReason(reason || 'ProbeFail'),
    source: String(source || ''),
  }
  store.entries[fingerprint] = current
}

function persistExitCache(cache, store, ttlMinutes, successMinutes, failMinutes, stats) {
  if (!cache || typeof cache.set !== 'function' || !(ttlMinutes > 0)) return

  try {
    const now = Date.now()
    let latest = {}
    try {
      const raw = cache.get(EXIT_CACHE_KEY)
      if (raw?.version === 2 && raw.entries && typeof raw.entries === 'object') {
        latest = cloneExitEntries(raw.entries)
      }
    } catch (_) {
      if (stats) stats.cacheReadError++
    }

    const merged = cloneExitEntries(latest)
    for (const [fingerprint, entry] of Object.entries(store.entries || {})) {
      const target = merged[fingerprint] || {}
      for (const familyKey of ['ipv4', 'ipv6']) {
        const incoming = entry?.[familyKey]
        if (!incoming) continue
        const current = target[familyKey]
        if (!current || Number(incoming.ts || 0) >= Number(current.ts || 0)) {
          target[familyKey] = { ...incoming }
        }
      }
      merged[fingerprint] = target
    }

    for (const [fingerprint, entry] of Object.entries(merged)) {
      for (const familyKey of ['ipv4', 'ipv6']) {
        const value = entry?.[familyKey]
        if (!value) continue
        const ttl = value.ok ? successMinutes : failMinutes
        const age = now - Number(value.ts || 0)
        if (!(ttl > 0) || !value.ts || age < 0 || age >= ttl * 60 * 1000) {
          delete entry[familyKey]
        }
      }
      if (!entry.ipv4 && !entry.ipv6) delete merged[fingerprint]
    }

    cache.set(
      EXIT_CACHE_KEY,
      { version: 2, entries: merged },
      Math.max(1000, ttlMinutes * 60 * 1000)
    )
  } catch (_) {
    if (stats) stats.cacheWriteError++
  }
}

function buildEipProbeGroups(items, familyMode) {
  const groups = new Map()

  for (const item of items) {
    const need4 = familyMode.want4 && !item.eip4 && !item.eip4Reason
    const need6 = familyMode.want6 && !item.eip6 && !item.eip6Reason
    if (!need4 && !need6) continue

    const current = groups.get(item.fingerprint)
    if (current) {
      current.members.push(item)
      current.need4 = current.need4 || need4
      current.need6 = current.need6 || need6
    } else {
      groups.set(item.fingerprint, {
        rep: item,
        members: [item],
        need4,
        need6,
      })
    }
  }

  return [...groups.values()]
}

function applyProbeResultToGroup(group, family, result) {
  for (const item of group.members) {
    if (family === 6) {
      item.eip6 = result.ok ? result.ip : ''
      item.eip6Reason = result.ok ? '' : sanitizeReason(result.reason || 'ProbeFail')
      item.eip6Source = result.source || ''
      item.eip6Details = Array.isArray(result.details) ? result.details.map(x => ({ ...x })) : []
      item.eip6Live = true
    } else {
      item.eip4 = result.ok ? result.ip : ''
      item.eip4Reason = result.ok ? '' : sanitizeReason(result.reason || 'ProbeFail')
      item.eip4Source = result.source || ''
      item.eip4Details = Array.isArray(result.details) ? result.details.map(x => ({ ...x })) : []
      item.eip4Live = true
    }
  }
}

function buildDeadCandidateGroups(items, familyMode) {
  if (!familyMode?.want4) return []
  const groups = new Map()

  for (const item of items || []) {
    if (!item?.eip4Live || item.eip4 || item.primaryIp) continue
    if (!isTransportDeadEvidence(item.eip4Details)) continue

    item.deadState = 'candidate'
    const current = groups.get(item.fingerprint)
    if (current) current.members.push(item)
    else groups.set(item.fingerprint, { rep: item, members: [item] })
  }

  return [...groups.values()]
}

function isTransportDeadEvidence(details) {
  const rows = (Array.isArray(details) ? details : []).filter(d => d?.source)
  const distinct = new Set(rows.map(d => String(d.source)))
  if (distinct.size < DEAD_MIN_ENDPOINTS) return false
  if (rows.some(d => d?.ok)) return false
  return rows.every(d => DEAD_TRANSPORT_REASONS.has(sanitizeReason(d?.reason || '')))
}

function assessDeadEnvironment(items, candidateFingerprints) {
  const seen = new Set()
  let live = 0
  let success = 0
  let fail = 0

  for (const item of items || []) {
    if (!item?.fingerprint || seen.has(item.fingerprint)) continue
    seen.add(item.fingerprint)
    if (candidateFingerprints?.has(item.fingerprint)) continue
    if (!item.eip4Live) continue
    live++
    if (item.eip4) success++
    else fail++
  }

  const rate = live > 0 ? success / live : 0
  let state
  if (live < DEAD_ENV_MIN_LIVE) state = 'unknown-small-sample'
  else if (rate >= DEAD_ENV_HEALTHY_RATE) state = 'healthy'
  else if (rate < DEAD_ENV_BAD_RATE) state = 'unhealthy'
  else state = 'uncertain'

  return { live, success, fail, rate, state }
}

function deadEnvironmentAllowsControl(state) {
  return state === 'healthy' || state === 'unknown-small-sample'
}

function selectDeadControlItems(items, candidateFingerprints, limit = DEAD_CONTROL_COUNT) {
  const unique = new Map()
  for (const item of items || []) {
    if (!item?.fingerprint || candidateFingerprints?.has(item.fingerprint) || !item.eip4) continue
    if (!unique.has(item.fingerprint)) unique.set(item.fingerprint, item)
  }

  const pool = [...unique.values()]
  const selected = []
  const usedSources = new Set()
  const usedRegions = new Set()
  const usedTypes = new Set()

  while (selected.length < limit && pool.length) {
    let bestIndex = 0
    let bestScore = -Infinity
    for (let i = 0; i < pool.length; i++) {
      const item = pool[i]
      const parsed = parseV21Name(item.originalName) || {}
      const source = String(parsed.source || '')
      const region = String(parsed.region || '')
      const type = String(item.node?.type || item.node?.protocol || '')
      let score = item.eip4Live ? 8 : 0
      if (source && !usedSources.has(source)) score += 4
      if (region && !usedRegions.has(region)) score += 2
      if (type && !usedTypes.has(type)) score += 1
      if (score > bestScore) {
        bestScore = score
        bestIndex = i
      }
    }

    const [chosen] = pool.splice(bestIndex, 1)
    selected.push(chosen)
    const parsed = parseV21Name(chosen.originalName) || {}
    if (parsed.source) usedSources.add(String(parsed.source))
    if (parsed.region) usedRegions.add(String(parsed.region))
    const type = String(chosen.node?.type || chosen.node?.protocol || '')
    if (type) usedTypes.add(type)
  }

  return selected
}

function formatPercent(value) {
  if (!Number.isFinite(value)) return '0.0%'
  return `${(value * 100).toFixed(1)}%`
}

function buildDeadDiagnosticTags(item) {
  if (!item?.deadState) return []
  if (item.deadState === 'candidate') return ['DeadCandidate']
  if (item.deadState === 'confirmed') return ['DeadConfirmed']
  if (item.deadState === 'recovered') return ['DeadRecovered']
  return []
}

async function verifyDeadCandidates(ctx) {
  const {
    $, api, authorization, httpMetaHost, internal, familyMode, primaryPreference,
    exitTimeout, exitRecoveryTimeout, exitConcurrency, startDelay, perProxyTimeout,
    deadRecheck, filterDead, log, logDetails, exitCache, exitCacheMinutes,
    exitFailCacheMinutes,
  } = ctx

  const confirmedIndices = new Set()
  const candidateGroups = buildDeadCandidateGroups(internal, familyMode)
  const candidateFingerprints = new Set(candidateGroups.map(g => g.rep.fingerprint))
  const candidateNodes = candidateGroups.reduce((n, g) => n + g.members.length, 0)
  const env = assessDeadEnvironment(internal, candidateFingerprints)

  log.info(
    `DEAD ENV | live-other-v4=${env.live} success=${env.success} fail=${env.fail} ` +
    `rate=${formatPercent(env.rate)} state=${env.state} ` +
    `candidates=${candidateGroups.length} routes/${candidateNodes} nodes`
  )

  if (!candidateGroups.length) {
    return { confirmedIndices, cacheDirty: false }
  }

  if (!deadRecheck) {
    log.info(
      `DEAD RECHECK | skipped recheck=off candidates=${candidateGroups.length} ` +
      `filter=${filterDead ? 'on' : 'off'} safety=hold`
    )
    return { confirmedIndices, cacheDirty: false }
  }

  if (!deadEnvironmentAllowsControl(env.state)) {
    log.warn(`DEAD RECHECK | skipped env=${env.state} safety=hold`)
    return { confirmedIndices, cacheDirty: false }
  }

  const controls = selectDeadControlItems(internal, candidateFingerprints, DEAD_CONTROL_COUNT)
  if (controls.length < DEAD_CONTROL_MIN) {
    log.warn(
      `DEAD CONTROL | selected=${controls.length} required-min=${DEAD_CONTROL_MIN} ` +
      `state=insufficient safety=hold`
    )
    return { confirmedIndices, cacheDirty: false }
  }

  const requiredPass = Math.min(DEAD_CONTROL_MIN, controls.length)
  const sessionItems = [
    ...controls.map(item => ({ kind: 'control', item, node: item.node })),
    ...candidateGroups.map(group => ({ kind: 'candidate', group, item: group.rep, node: group.rep.node })),
  ]

  let session = null
  let cacheDirty = false
  try {
    log.info(
      `DEAD META | start fresh session controls=${controls.length} candidates=${candidateGroups.length}`
    )
    session = await startHttpMetaSession(
      $, api, authorization, sessionItems, startDelay, perProxyTimeout
    )

    const proxyByFingerprint = new Map()
    const proxyHost = String(httpMetaHost || '127.0.0.1')
    for (let i = 0; i < sessionItems.length; i++) {
      proxyByFingerprint.set(
        sessionItems[i].item.fingerprint,
        `http://${proxyHost}:${session.ports[i]}`
      )
    }

    const controlResults = []
    const controlTasks = controls.map(item => async () => {
      const result = await probeExitFamily(
        $, proxyByFingerprint.get(item.fingerprint), 4, exitTimeout, exitRecoveryTimeout
      )
      controlResults.push({ item, result })
      if (logDetails && !result.ok) {
        log.info(
          `DEAD CONTROL DETAIL | node=${eipNodeLabel(item.originalName)} ` +
          `final=${sanitizeReason(result.reason || 'ProbeFail')} ` +
          `endpoints=${formatEipProbeDetails(result.details) || '-'}`
        )
      }
    })
    await runConcurrent(controlTasks, Math.min(exitConcurrency, controls.length))

    const controlPass = controlResults.filter(x => x.result.ok).length
    const controlFail = controlResults.length - controlPass
    const controlHealthy = controlPass >= requiredPass
    log.info(
      `DEAD CONTROL | selected=${controls.length} pass=${controlPass} fail=${controlFail} ` +
      `required=${requiredPass} state=${controlHealthy ? 'healthy' : 'failed'}`
    )

    if (!controlHealthy) {
      log.warn('DEAD RECHECK | aborted control-gate=failed safety=hold')
      return { confirmedIndices, cacheDirty }
    }

    let confirmedRoutes = 0
    let recoveredRoutes = 0
    let ambiguousRoutes = 0
    const candidateTasks = candidateGroups.map(group => async () => {
      const rep = group.rep
      const result = await probeExitFamily(
        $, proxyByFingerprint.get(rep.fingerprint), 4, exitTimeout, exitRecoveryTimeout
      )

      applyProbeResultToGroup(group, 4, result)
      for (const member of group.members) selectPrimaryEip(member, familyMode, primaryPreference)

      const ttlEnabled = result.ok ? exitCacheMinutes > 0 : exitFailCacheMinutes > 0
      if (ttlEnabled) {
        setExitCacheFamilyEntry(
          exitCache,
          rep.fingerprint,
          4,
          result.ok,
          result.ip || '',
          result.reason || '',
          result.source || ''
        )
        cacheDirty = true
      }

      if (result.ok) {
        recoveredRoutes++
        for (const member of group.members) member.deadState = 'recovered'
      } else if (isTransportDeadEvidence(result.details)) {
        confirmedRoutes++
        for (const member of group.members) {
          member.deadState = 'confirmed'
          confirmedIndices.add(member.index)
        }
      } else {
        ambiguousRoutes++
        for (const member of group.members) member.deadState = 'candidate'
      }

      if (logDetails && !result.ok) {
        log.info(
          `DEAD RECHECK DETAIL | node=${eipNodeLabel(rep.originalName)} ` +
          `final=${sanitizeReason(result.reason || 'ProbeFail')} ` +
          `transport-dead=${isTransportDeadEvidence(result.details) ? 'yes' : 'no'} ` +
          `endpoints=${formatEipProbeDetails(result.details) || '-'}`
        )
      }
    })

    await runConcurrent(candidateTasks, exitConcurrency)
    log.info(
      `DEAD RECHECK | candidates=${candidateGroups.length} confirmed=${confirmedRoutes} ` +
      `recovered=${recoveredRoutes} ambiguous=${ambiguousRoutes}`
    )
  } catch (err) {
    log.warn(`DEAD RECHECK | failed reason=${sanitizeReason(errorMessage(err))} safety=hold`)
    confirmedIndices.clear()
    for (const group of candidateGroups) {
      for (const member of group.members) {
        if (member.deadState === 'confirmed') member.deadState = 'candidate'
      }
    }
  } finally {
    if (session) await stopHttpMetaSession($, api, authorization, session)
  }

  return { confirmedIndices, cacheDirty }
}

async function probeExitFamily($, localProxy, family, fastTimeout, recoveryTimeout) {
  const set = EIP_ENDPOINTS[family]
  if (!set) return { ok: false, ip: '', reason: 'BadFamily', source: '', details: [] }

  const fast = await probeExitBatch($, localProxy, family, set.fast, fastTimeout)
  if (fast.ok) return fast

  let last = fast

  if (set.recovery?.length) {
    // Upstream-style recovery hosts are split into two bounded batches.
    const midpoint = Math.ceil(set.recovery.length / 2)
    const batches = [
      set.recovery.slice(0, midpoint),
      set.recovery.slice(midpoint),
    ]
    for (const batch of batches) {
      if (!batch.length) continue
      const r = await probeExitBatch($, localProxy, family, batch, recoveryTimeout)
      if (r.ok) return mergeProbeSuccess(last, r)
      last = mergeProbeFailures(last, r)
    }
  }

  if (set.recoveryHttps?.length) {
    // Secondary compatibility fallback. Run as one bounded batch so hard
    // failures do not multiply latency excessively.
    const r = await probeExitBatch($, localProxy, family, set.recoveryHttps, recoveryTimeout)
    if (r.ok) return mergeProbeSuccess(last, r)
    last = mergeProbeFailures(last, r)
  }

  return last
}

async function probeExitBatch($, localProxy, family, endpoints, timeout) {
  const results = await Promise.all(
    endpoints.map(async ([source, url]) => {
      try {
        const r = await request($, {
          method: 'get',
          url,
          proxy: localProxy,
          headers: {
            Accept: 'text/plain,application/json,*/*',
            'User-Agent': 'curl/8.5.0',
          },
          timeout,
        })

        const status = httpStatus(r)
        if (status >= 400) {
          return { ok: false, ip: '', reason: `HTTP${status}`, source }
        }

        const ip = extractPlainIp(r.body)
        const valid = family === 6 ? isIPv6(ip) : isIPv4(ip)
        if (valid) return { ok: true, ip, reason: '', source }

        if (ip) return { ok: false, ip: '', reason: 'WrongFamily', source }
        return { ok: false, ip: '', reason: 'InvalidBody', source }
      } catch (err) {
        return {
          ok: false,
          ip: '',
          reason: classifyRequestError(err),
          source,
        }
      }
    })
  )

  const success = results.find(r => r.ok)
  if (success) {
    return {
      ...success,
      details: results.map(compactProbeDetail),
    }
  }

  return {
    ok: false,
    ip: '',
    reason: chooseProbeFailureReason(results),
    source: results.map(r => r.source).filter(Boolean).join('+'),
    details: results.map(compactProbeDetail),
  }
}

function compactProbeDetail(r) {
  return {
    source: String(r?.source || ''),
    ok: Boolean(r?.ok),
    reason: String(r?.reason || ''),
  }
}

function mergeProbeSuccess(previous, success) {
  return {
    ...success,
    details: [
      ...(Array.isArray(previous?.details) ? previous.details : []),
      ...(Array.isArray(success?.details) ? success.details : []),
    ],
  }
}

function mergeProbeFailures(a, b) {
  return {
    ok: false,
    ip: '',
    reason: chooseProbeFailureReason([a, b]),
    source: [a?.source, b?.source].filter(Boolean).join('+'),
    details: [
      ...(Array.isArray(a?.details) ? a.details : []),
      ...(Array.isArray(b?.details) ? b.details : []),
    ],
  }
}

function formatEipProbeDetails(details) {
  return (Array.isArray(details) ? details : [])
    .map(d => `${sanitizeReason(d?.source || 'unknown')}:${d?.ok ? 'OK' : sanitizeReason(d?.reason || 'Fail')}`)
    .join(',')
}

function eipNodeLabel(name) {
  const parsed = parseV21Name(name)
  const tail = String(parsed?.tail || '').trim()
  if (tail) return tail.replace(/\s+/g, '_').slice(0, 48)
  return String(name || '').replace(/\s+/g, '_').slice(0, 48) || 'unknown'
}

function chooseProbeFailureReason(results) {
  const reasons = (results || []).map(r => sanitizeReason(r?.reason || '')).filter(Boolean)
  if (!reasons.length) return 'ProbeFail'
  const priority = [
    'Timeout',
    'TLS',
    'Connect',
    'DNS',
    'HTTP429',
    'HTTP403',
    'HTTP5xx',
    'WrongFamily',
    'InvalidBody',
  ]
  for (const p of priority) {
    const found = reasons.find(x => x === p || (p === 'HTTP5xx' && /^HTTP5\d\d$/.test(x)))
    if (found) return found
  }
  return reasons[0]
}

function classifyRequestError(err) {
  const s = String(err?.message || err || '').toLowerCase()
  if (/timeout|timed out|etimedout/.test(s)) return 'Timeout'
  if (/tls|ssl|certificate|handshake/.test(s)) return 'TLS'
  if (/dns|resolve|enotfound|eai_again/.test(s)) return 'DNS'
  if (/connect|econnrefused|econnreset|socket|network/.test(s)) return 'Connect'
  return 'RequestErr'
}

function extractPlainIp(body) {
  const raw = String(body ?? '').trim()
  if (!raw) return null
  const d = json(raw)
  if (d && typeof d === 'object') {
    const v = normalizeIp(d.ip || d.query || d.address)
    if (v) return v
  }

  // Do not search the whole body for an arbitrary IP: some services/CDNs place
  // unrelated IP-looking values in HTML or headers. Only accept the first token.
  return normalizeIp(raw.split(/\s+/)[0])
}

function isIPv4(ip) {
  const m = String(ip || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  return !!m && m.slice(1).every(x => Number(x) >= 0 && Number(x) <= 255)
}

function isIPv6(ip) {
  const s = normalizeIp(ip)
  return !!s && s.includes(':') && !s.includes('.')
}

function selectPrimaryEip(item, familyMode, preference) {
  let family = 0
  let ip = ''

  if (familyMode.want4 && familyMode.want6) {
    if (preference === 6) {
      if (item.eip6) {
        family = 6
        ip = item.eip6
      } else if (item.eip4) {
        family = 4
        ip = item.eip4
      }
    } else {
      if (item.eip4) {
        family = 4
        ip = item.eip4
      } else if (item.eip6) {
        family = 6
        ip = item.eip6
      }
    }
  } else if (familyMode.want4 && item.eip4) {
    family = 4
    ip = item.eip4
  } else if (familyMode.want6 && item.eip6) {
    family = 6
    ip = item.eip6
  }

  item.primaryFamily = family
  item.primaryIp = ip
}

function summarizeEipCoverage(items, familyMode) {
  const out = {
    ipv4: 0,
    ipv6: 0,
    dual: 0,
    v4Only: 0,
    v6Only: 0,
    none: 0,
    primaryKnown: 0,
  }

  for (const item of items) {
    const has4 = !!item.eip4
    const has6 = !!item.eip6
    if (has4) out.ipv4++
    if (has6) out.ipv6++
    if (has4 && has6) out.dual++
    else if (has4) out.v4Only++
    else if (has6) out.v6Only++
    else out.none++
    if (item.primaryIp) out.primaryKnown++
  }
  return out
}

function buildEipDiagnosticTags(item, familyMode) {
  const tags = []

  if (familyMode.want4) {
    if (item.eip4) tags.push(`EIP4-${item.eip4}`)
    else tags.push(`EIP4Fail-${sanitizeReason(item.eip4Reason || 'Unknown')}`)
  }

  if (familyMode.want6) {
    if (item.eip6) tags.push(`EIP6-${item.eip6}`)
    else tags.push(`EIP6Fail-${sanitizeReason(item.eip6Reason || 'Unknown')}`)
  }

  if (item.eip4 && item.eip6) tags.push('EIPDual')
  else if (item.eip4) tags.push('EIP4Only')
  else if (item.eip6) tags.push('EIP6Only')
  else tags.push('EIPMissing')

  if (item.primaryFamily === 4) tags.push('Primary4')
  if (item.primaryFamily === 6) tags.push('Primary6')

  return tags
}

function sanitizeReason(value) {
  return String(value || 'Unknown')
    .replace(/[^0-9A-Za-z_-]+/g, '')
    .slice(0, 48) || 'Unknown'
}

function formatEipFamilyCacheStats(s) {
  if (!s) return '-'
  return `H${s.hit}/FH${s.failHit}/M${s.miss}/P${s.probeSuccess}/${s.probeRoutes}`
}

function formatFailureReasons(items, family, enabled) {
  if (!enabled) return 'disabled'
  const counts = {}
  for (const item of items) {
    const ip = family === 6 ? item.eip6 : item.eip4
    if (ip) continue
    const reason = sanitizeReason(
      family === 6 ? item.eip6Reason || 'Unknown' : item.eip4Reason || 'Unknown'
    )
    counts[reason] = (counts[reason] || 0) + 1
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([k, v]) => `${k}:${v}`)
    .join(',')
}

function nodeFingerprint(node) {
  const clean = {}
  for (const key of Object.keys(node || {}).sort()) {
    if (key === 'name' || /^_/i.test(key)) continue
    clean[key] = node[key]
  }
  return hashString(stableSerialize(clean))
}

function stableSerialize(value) {
  if (value === null || value === undefined) return String(value)
  if (typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(',')}]`
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableSerialize(value[key])}`).join(',')}}`
}

function hashString(value) {
  const s = String(value || '')
  let h1 = 0x811c9dc5
  let h2 = 0x9e3779b9
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    h1 = Math.imul(h1 ^ c, 0x01000193)
    h2 = Math.imul(h2 ^ c, 0x85ebca6b)
    h2 ^= h2 >>> 13
  }
  return `${(h1 >>> 0).toString(16).padStart(8, '0')}${(h2 >>> 0).toString(16).padStart(8, '0')}`
}

function providerCacheKey(provider, ip) {
  return `${PROVIDER_CACHE_PREFIX}${provider}:${ip}`
}

function readProviderCacheSnapshot(cache, provider, ip, okHours, failHours, force) {
  if (force || !cache || typeof cache.get !== 'function') return { hit: false }
  try {
    const hit = cache.get(providerCacheKey(provider, ip))
    if (!hit || !hit.ts || !hit.result) return { hit: false }
    const ttl = hit.ok ? okHours : failHours
    if (!(ttl > 0) || Date.now() - Number(hit.ts) >= ttl * 3600 * 1000) {
      return { hit: false }
    }
    return { hit: true, result: hit.result }
  } catch (_) {
    return { hit: false }
  }
}

function providerNeedsLocalProxy(cache, ip, okHours, failHours, force) {
  const mm = readProviderCacheSnapshot(cache, 'mm', ip, okHours, failHours, force)
  if (!mm.hit) return true

  const fullMode = maxmindBaseUsable(mm.result)
  const keys = fullMode
    ? ['ii', 'sc', 'ir', 'ia', 'ab', 'i2', 'db', 'id', 'iq', 'pc']
    : ['ii', 'ir', 'ia', 'db', 'pc']

  for (const key of keys) {
    if (key === 'db' && isIPv6(ip)) continue
    if (!readProviderCacheSnapshot(cache, key, ip, okHours, failHours, force).hit) {
      return true
    }
  }
  return false
}

function skippedByMaxmind() {
  return {
    state: 'skip',
    status: 0,
    data: null,
    _route: 'MM',
    _reason: 'MaxMindLite',
    // Synthetic policy skip: no provider request occurred, so it is neither cache HIT nor MISS.
    _cached: null,
  }
}

function maxmindBaseUsable(r) {
  return !!(
    r &&
    r.state === 'json' &&
    r.data &&
    typeof r.data === 'object' &&
    Object.keys(r.data).length
  )
}

async function cachedProvider(cache, provider, ip, okHours, failHours, force, fetcher) {
  const key = providerCacheKey(provider, ip)
  const now = Date.now()
  let cacheReadError = false
  let cacheWriteError = false

  if (!force && cache && typeof cache.get === 'function') {
    try {
      const hit = cache.get(key)
      if (hit && hit.ts && hit.result) {
        const ttl = hit.ok ? okHours : failHours
        if (ttl > 0 && now - Number(hit.ts) < ttl * 3600 * 1000) {
          return {
            ...hit.result,
            _cached: true,
            _cacheReadError: false,
            _cacheWriteError: false,
          }
        }
      }
    } catch (_) {
      cacheReadError = true
    }
  }

  let result
  try {
    result = await fetcher()
  } catch (err) {
    result = {
      state: 'err',
      status: 0,
      data: null,
      _reason: classifyRequestError(err),
    }
  }

  const ok = provider === 'mm'
    ? maxmindBaseUsable(result)
    : providerHasUsableEvidence(provider, result)

  if (cache && typeof cache.set === 'function') {
    try {
      const payload = { ts: now, ok, result }
      const maxHours = Math.max(okHours, failHours)
      if (maxHours > 0) cache.set(key, payload, Math.max(1000, maxHours * 3600 * 1000))
      else cache.set(key, payload)
    } catch (_) {
      cacheWriteError = true
    }
  }

  return {
    ...result,
    _cached: false,
    _cacheReadError: cacheReadError,
    _cacheWriteError: cacheWriteError,
  }
}

function providerHasUsableEvidence(key, r) {
  if (!r || r.state !== 'json' || (!r.data && key !== 'pc')) return false

  if (key === 'pc') {
    return normalizeScore(r?.risk) !== null ||
      ['yes', 'no', 'true', 'false'].includes(String(r?.data?.proxy ?? '').toLowerCase())
  }

  if (key === 'sc') {
    const d = r?.data || {}
    if (normalizeScore(d?.scamalytics?.scamalytics_score) !== null) return true
    const p = d?.scamalytics?.scamalytics_proxy || {}
    const x4 = d?.external_datasources?.x4bnet || {}
    return [
      d?.external_datasources?.firehol?.is_proxy,
      p?.is_vpn, p?.is_datacenter, p?.is_server,
      d?.scamalytics?.is_blacklisted_external,
      x4?.is_tor, x4?.is_blacklisted_spambot,
      x4?.is_bot_operamini, x4?.is_bot_semrush,
    ].some(v => toBool(v) !== null)
  }

  if (key === 'ab') {
    return normalizeScore(r?.data?.data?.abuseConfidenceScore) !== null ||
      Boolean(cleanNetText(r?.data?.data?.usageType))
  }

  if (key === 'i2') {
    const d = r?.data || {}
    if (normalizeScore(d?.fraud_score) !== null) return true
    if (mapIp2Usage(d?.usage_type) || mapIp2Usage(d?.as_info?.as_usage_type)) return true
    const p = d?.proxy || {}
    return [
      d?.is_proxy, p?.is_public_proxy, p?.is_web_proxy,
      p?.is_vpn, p?.is_tor, p?.is_spammer,
      p?.is_web_crawler, p?.is_scanner, p?.is_botnet,
      p?.is_data_center, p?.is_datacenter,
    ].some(v => toBool(v) !== null)
  }

  if (key === 'iq') {
    const d = r?.data || {}
    if (normalizeScore(d?.fraud_score) !== null) return true
    return [
      d?.proxy, d?.vpn, d?.tor, d?.recent_abuse, d?.bot_status, d?.hosting,
    ].some(v => toBool(v) !== null)
  }

  if (key === 'ii') {
    const d = r?.data || {}
    const p = d?.data?.privacy || {}
    if ([p?.proxy, p?.vpn, p?.tor, p?.hosting].some(v => toBool(v) !== null)) return true
    return [d?.data?.asn?.type, d?.data?.company?.type]
      .map(netType)
      .some(t => ['hosting', 'business', 'isp'].includes(t))
  }

  if (key === 'ir') {
    const d = r?.data || {}
    const s = d?.security || {}
    if ([
      s?.is_proxy, s?.is_vpn, s?.is_tor, s?.is_tor_exit,
      s?.is_abuser, s?.is_cloud_provider,
    ].some(v => toBool(v) !== null)) return true

    if (cleanNetText(d?.carrier?.name)) return true
    return [d?.connection?.type, d?.company?.type]
      .map(netType)
      .some(t => ['hosting', 'cdn', 'business', 'isp'].includes(t))
  }

  if (key === 'ia') {
    const d = r?.data || {}
    const risk = parseIpapiRisk(d)
    if (risk.score !== null || risk.label) return true
    if ([
      d?.is_proxy, d?.is_vpn, d?.is_tor, d?.is_abuser,
      d?.is_datacenter, d?.is_crawler, d?.is_mobile, d?.is_satellite,
    ].some(v => toBool(v) !== null)) return true

    return [d?.asn?.type, d?.company?.type]
      .map(netType)
      .some(t => ['hosting', 'business', 'isp'].includes(t))
  }

  if (key === 'db') {
    return Boolean(String(r?.data?.threatLevel || '').trim()) ||
      toBool(r?.data?.isProxy) !== null ||
      toBool(r?.data?.isCrawler) !== null
  }

  if (key === 'id') {
    const t = r?.data?.threat || {}
    return [
      t?.is_proxy, t?.is_tor, t?.is_datacenter, t?.is_threat,
      t?.is_known_abuser, t?.is_known_attacker,
    ].some(v => toBool(v) !== null)
  }

  return false
}

function recordProviderStats(r, stats) {
  if (!stats || !r) return

  for (const [provider, result] of Object.entries(r)) {
    if (provider.startsWith('_') || !result) continue

    const bucket = stats.byProvider[provider] || {
      hit: 0,
      miss: 0,
      usable: 0,
      json: 0,
      html: 0,
      err: 0,
      skip: 0,
    }

    if (result.state !== 'skip' && typeof result._cached === 'boolean') {
      if (result._cached) {
        stats.hit++
        bucket.hit++
      } else {
        stats.miss++
        bucket.miss++
      }
    }

    if (result._cacheReadError) stats.readError++
    if (result._cacheWriteError) stats.writeError++

    if (result.state === 'json') {
      stats.json++
      bucket.json++
    } else if (result.state === 'html') {
      stats.html++
      bucket.html++
    } else if (result.state === 'skip') {
      stats.skip++
      bucket.skip++
    } else {
      stats.err++
      bucket.err++
    }

    const usable = provider === 'mm'
      ? maxmindBaseUsable(result)
      : providerHasUsableEvidence(provider, result)
    if (usable) {
      stats.usable++
      bucket.usable++
    }

    stats.byProvider[provider] = bucket
  }
}

function formatProviderStatsDetail(byProvider) {
  const order = ['mm', 'ii', 'sc', 'ir', 'ia', 'ab', 'i2', 'db', 'id', 'iq', 'pc']
  return order
    .filter(key => byProvider?.[key])
    .map(key => {
      const b = byProvider[key]
      return `${key.toUpperCase()} H${b.hit}/M${b.miss}/U${b.usable}/E${b.html + b.err}`
    })
    .join(' | ')
}

function markRunStarted(cache, scope, runId, ts) {
  if (!cache || typeof cache.get !== 'function' || typeof cache.set !== 'function') return null
  const key = `${RUN_MARKER_PREFIX}${scope}`
  let previous = null
  try {
    previous = cache.get(key)
  } catch (_) {}
  try {
    cache.set(key, { active: true, id: runId, ts }, 30 * 60 * 1000)
  } catch (_) {}
  return { key, previous }
}

function markRunFinished(cache, marker, runId) {
  if (!marker?.key || !cache || typeof cache.get !== 'function' || typeof cache.set !== 'function') return
  try {
    const current = cache.get(marker.key)
    if (current?.active && current.id === runId) {
      cache.set(marker.key, { active: false, id: runId, ts: Date.now() }, 1000)
    }
  } catch (_) {}
}

function countFinalClassifications(output) {
  const quality = { Trust: 0, Normal: 0, Risk: 0, Unrated: 0 }
  const identity = { ConsIP: 0, BusiIP: 0, HostIP: 0, UnkIP: 0 }
  for (const proxy of output || []) {
    const parsed = parseV21Name(proxy?.name)
    if (!parsed) continue
    for (const tag of parsed.tags) {
      if (Object.prototype.hasOwnProperty.call(quality, tag)) quality[tag]++
      if (Object.prototype.hasOwnProperty.call(identity, tag)) identity[tag]++
    }
  }
  return { quality, identity }
}

function formatDuration(ms) {
  const n = Math.max(0, Number(ms) || 0)
  if (n < 1000) return `${Math.round(n)}ms`
  return `${(n / 1000).toFixed(n < 10000 ? 2 : 1)}s`
}

function errorMessage(err) {
  return String(err?.message || err || 'unknown error').replace(/\s+/g, ' ').slice(0, 240)
}

function providerHasRatingEvidence(key, r) {
  if (!r || r.state !== 'json') return false

  if (key === 'pc') {
    return normalizeScore(r?.risk) !== null
  }

  if (key === 'sc') {
    return normalizeScore(r?.data?.scamalytics?.scamalytics_score) !== null
  }

  if (key === 'ia') {
    const risk = parseIpapiRisk(r?.data)
    return risk.score !== null || Boolean(risk.label)
  }

  if (key === 'ab') {
    return normalizeScore(r?.data?.data?.abuseConfidenceScore) !== null
  }

  if (key === 'i2') {
    return normalizeScore(r?.data?.fraud_score) !== null
  }

  if (key === 'db') {
    const level = String(r?.data?.threatLevel || '').trim().toLowerCase()
    return ['low', 'medium', 'high'].includes(level)
  }

  if (key === 'iq') {
    return normalizeScore(r?.data?.fraud_score) !== null
  }

  return false
}

function classifyRatingSource(key, r) {
  if (!providerHasRatingEvidence(key, r)) {
    return { level: 'None', reason: '' }
  }

  if (key === 'pc') {
    const score = normalizeScore(r?.risk)
    if (score === null) return { level: 'None', reason: '' }

    if (score <= 33) {
      return { level: 'Clean', reason: `PC:${score}` }
    }

    if (score <= 66) {
      return { level: 'Caution', reason: `PC:${score}` }
    }

    return { level: 'Risk', reason: `PC:${score}` }
  }

  if (key === 'sc') {
    const score = normalizeScore(r?.data?.scamalytics?.scamalytics_score)
    if (score === null) return { level: 'None', reason: '' }
    const band = scBand(score)
    if (band === 'Low') return { level: 'Clean', reason: `SC:${band}` }
    if (band === 'Medium') return { level: 'Caution', reason: `SC:${band}` }
    return { level: 'Risk', reason: `SC:${band}` }
  }

  if (key === 'ia') {
    const risk = parseIpapiRisk(r?.data)
    const label = String(risk.label || '').trim()
    if (!label && risk.score === null) return { level: 'None', reason: '' }

    if (label === 'Very Low' || label === 'Low') {
      return { level: 'Clean', reason: `IA:${label.replace(/\s+/g, '')}` }
    }
    if (label === 'Elevated') {
      return { level: 'Caution', reason: 'IA:Elevated' }
    }
    if (label === 'High' || label === 'Very High') {
      return { level: 'Risk', reason: `IA:${label.replace(/\s+/g, '')}` }
    }

    // upstream 的核心语义来自文字等级；如果只有数值但没有等级，
    // 只承认“有结果”，不擅自发明新的区间。
    return { level: 'None', reason: '' }
  }

  if (key === 'ab') {
    const score = normalizeScore(r?.data?.data?.abuseConfidenceScore)
    if (score === null) return { level: 'None', reason: '' }
    const band = abuseBand(score)
    if (band === 'Low') return { level: 'Clean', reason: 'AB:Low' }
    return { level: 'Risk', reason: `AB:${band}` }
  }

  if (key === 'i2') {
    const score = normalizeScore(r?.data?.fraud_score)
    if (score === null) return { level: 'None', reason: '' }
    const band = i2Band(score)
    if (band === 'Low') return { level: 'Clean', reason: 'I2:Low' }
    if (band === 'Medium') return { level: 'Caution', reason: 'I2:Medium' }
    return { level: 'Risk', reason: 'I2:High' }
  }

  if (key === 'db') {
    const level = String(r?.data?.threatLevel || '').trim().toLowerCase()
    if (level === 'low') return { level: 'Clean', reason: 'DB:Low' }
    if (level === 'medium') return { level: 'Caution', reason: 'DB:Medium' }
    if (level === 'high') return { level: 'Risk', reason: 'DB:High' }
    return { level: 'None', reason: '' }
  }

  if (key === 'iq') {
    const score = normalizeScore(r?.data?.fraud_score)
    if (score === null) return { level: 'None', reason: '' }
    const band = iqBand(score)
    if (band === 'Low') return { level: 'Clean', reason: 'IQ:Low' }
    return { level: 'Risk', reason: `IQ:${band}` }
  }

  return { level: 'None', reason: '' }
}

function collectHardRiskReasons(r) {
  const risk = []

  const pcType = String(r?.pc?.data?.type || '').toLowerCase()
  if (r?.pc?.state === 'json' && pcType.includes('tor')) risk.push('PC:Tor')

  if (r?.ii?.state === 'json') {
    const p = r?.ii?.data?.data?.privacy || {}
    if (toBool(p?.tor) === true) risk.push('II:Tor')
  }

  if (r?.sc?.state === 'json') {
    const d = r?.sc?.data || {}
    const x4 = d?.external_datasources?.x4bnet || {}
    if (toBool(x4?.is_tor) === true) risk.push('SC:Tor')
    if (toBool(d?.scamalytics?.is_blacklisted_external) === true) risk.push('SC:Abuse')
    if (
      anyTrue(
        x4?.is_blacklisted_spambot,
        x4?.is_bot_operamini,
        x4?.is_bot_semrush
      ) === true
    ) {
      risk.push('SC:Bot')
    }
  }

  if (r?.ir?.state === 'json') {
    const s = r?.ir?.data?.security || {}
    if (anyTrue(s?.is_tor, s?.is_tor_exit) === true) risk.push('IR:Tor')
    if (toBool(s?.is_abuser) === true) risk.push('IR:Abuse')
  }

  if (r?.ia?.state === 'json') {
    const d = r?.ia?.data || {}
    if (toBool(d?.is_tor) === true) risk.push('IA:Tor')
    if (toBool(d?.is_abuser) === true) risk.push('IA:Abuse')
  }

  if (r?.i2?.state === 'json') {
    const p = r?.i2?.data?.proxy || {}
    if (toBool(p?.is_tor) === true) risk.push('I2:Tor')
    if (toBool(p?.is_botnet) === true) risk.push('I2:Bot')
    if (toBool(p?.is_spammer) === true) risk.push('I2:Abuse')
  }

  if (r?.id?.state === 'json') {
    const t = r?.id?.data?.threat || {}
    if (toBool(t?.is_tor) === true) risk.push('ID:Tor')
    if (toBool(t?.is_known_abuser) === true) risk.push('ID:Abuse')
    if (toBool(t?.is_known_attacker) === true) risk.push('ID:Attacker')
    if (
      toBool(t?.is_threat) === true &&
      toBool(t?.is_known_abuser) !== true &&
      toBool(t?.is_known_attacker) !== true
    ) {
      risk.push('ID:Threat')
    }
  }

  if (r?.iq?.state === 'json') {
    const d = r?.iq?.data || {}
    if (toBool(d?.tor) === true) risk.push('IQ:Tor')
    if (toBool(d?.bot_status) === true) risk.push('IQ:Bot')
    if (toBool(d?.recent_abuse) === true) risk.push('IQ:Abuse')
  }

  return [...new Set(risk)]
}

function buildSimpleVerdict(r) {
  const providerKeys = ['pc', 'ii', 'sc', 'ir', 'ia', 'ab', 'i2', 'db', 'id', 'iq']
  const ratingKeys = ['pc', 'sc', 'ia', 'ab', 'i2', 'db', 'iq']

  const validCount = providerKeys.filter(k => providerHasUsableEvidence(k, r?.[k])).length

  const ratingResults = ratingKeys.map(key => ({
    key,
    ...classifyRatingSource(key, r?.[key]),
  }))

  const rated = ratingResults.filter(x => x.level !== 'None')
  const clean = rated.filter(x => x.level === 'Clean')
  const caution = rated.filter(x => x.level === 'Caution')
  const ratingRisk = rated.filter(x => x.level === 'Risk')
  const hardRisk = collectHardRiskReasons(r)

  const riskReasons = [
    ...ratingRisk.map(x => x.reason),
    ...hardRisk,
  ].filter(Boolean)

  // RiskSrc 统计的是“所有触发 Risk 的独立 Provider”。
  // 一个 Provider 同时命中评分风险和事实风险时只算 1 个。
  const riskProviders = [...new Set(
    riskReasons
      .map(reason => String(reason || '').split(':')[0].trim())
      .filter(Boolean)
  )]

  const cautionReasons = caution.map(x => x.reason).filter(Boolean)

  // VPN / Proxy 仍保留为诊断信息，但不参与 v1.1.1 Quality 最终评级。
  const weakProviders = [
    weakFromProxycheck(r?.pc),
    weakFromIpinfo(r?.ii),
    weakFromScamalytics(r?.sc),
    weakFromIpregistry(r?.ir),
    weakFromIpapi(r?.ia),
    weakFromIp2Location(r?.i2),
    weakFromDbIp(r?.db),
    weakFromIpdata(r?.id),
    weakFromIpqs(r?.iq),
  ]
  const vpn = countWeak(weakProviders, 'vpn')
  const proxy = countWeak(weakProviders, 'proxy')

  let verdict = 'Unrated'

  if (riskReasons.length >= 1) {
    verdict = 'Risk'
  } else if (rated.length === 0) {
    verdict = 'Unrated'
  } else if (caution.length >= 1) {
    verdict = 'Normal'
  } else if (clean.length >= 3) {
    verdict = 'Trust'
  } else {
    verdict = 'Normal'
  }

  return {
    verdict,
    validCount,
    ratingValidCount: rated.length,
    cleanCount: clean.length,
    cautionCount: caution.length,
    riskSourceCount: riskProviders.length,
    riskReasons: [...new Set(riskReasons)],
    cautionReasons: [...new Set(cautionReasons)],
    vpn,
    proxy,
  }
}


// ---------------------------------------------------------------------------
// Network Identity v1.1.1
// ---------------------------------------------------------------------------
// Provider verdicts are normalized to one direction per independent source:
// C Consumer, L last-mile/fixed ISP, I generic ISP, B business, H hosting, X conflict.
// A Provider can never contribute more than one vote, even when several fields match.

function buildNetworkIdentity(r, originalStandardizedName) {
  const sources = []

  pushNetEvidence(sources, manualNetworkEvidence(originalStandardizedName))
  pushNetEvidence(sources, netFromIpinfo(r?.ii))
  pushNetEvidence(sources, netFromIpregistry(r?.ir))
  pushNetEvidence(sources, netFromIpapi(r?.ia))
  pushNetEvidence(sources, netFromAbuseIpdb(r?.ab))
  pushNetEvidence(sources, netFromIp2Location(r?.i2))
  pushNetEvidence(sources, netFromScamalytics(r?.sc))
  pushNetEvidence(sources, netFromIpdata(r?.id))
  pushNetEvidence(sources, netFromIpqs(r?.iq))

  const counts = { C: 0, L: 0, I: 0, B: 0, H: 0, X: 0 }
  for (const e of sources) {
    if (Object.prototype.hasOwnProperty.call(counts, e.kind)) counts[e.kind] += 1
  }

  const consumerCandidate =
    counts.C >= 2 ||
    (counts.C >= 1 && counts.L >= 1) ||
    counts.L >= 2

  let verdict = 'UnkIP'
  let reason = 'LowEvidence'

  // Strong Consumer consensus plus any Hosting evidence is treated as a conflict,
  // not as a reason for one dimension to override the other.
  if (consumerCandidate) {
    if (counts.H >= 1) {
      verdict = 'UnkIP'
      reason = 'ConflictCH'
    } else {
      verdict = 'ConsIP'
      if (counts.C >= 2) reason = 'C2'
      else if (counts.C >= 1 && counts.L >= 1) reason = 'C1L1'
      else reason = 'L2'
    }
  } else if (counts.H >= 2) {
    // Two or more independent Hosting sources outweigh a lone, insufficient
    // Consumer/last-mile hint. If Consumer itself reached threshold, the branch above wins.
    verdict = 'HostIP'
    reason = 'H2'
  } else if (counts.H === 1) {
    // A single explicit Hosting source is enough only when there is no strong
    // Consumer-side evidence at all. Otherwise preserve uncertainty.
    if (counts.C + counts.L >= 1) {
      verdict = 'UnkIP'
      reason = 'ConflictCH'
    } else {
      verdict = 'HostIP'
      reason = 'H1'
    }
  } else if (counts.I + counts.B >= 2) {
    verdict = 'BusiIP'
    reason = 'Biz2'
  }

  return { verdict, reason, counts, sources }
}

function pushNetEvidence(out, evidence) {
  if (!evidence || !evidence.source || !evidence.kind) return
  out.push(evidence)
}

function netEvidence(source, kind, detail = '') {
  return { source, kind, detail: String(detail || '') }
}

function manualNetworkEvidence(name) {
  const parsed = parseV21Name(name)
  if (!parsed) return null
  const tags = new Set(parsed.tags || [])

  const consumerTags = ['ResIP', 'Mobile', 'SatNet'].filter(t => tags.has(t))
  const hasConsumer = consumerTags.length > 0
  const hasIsp = tags.has('ISP')
  const hasHosting = tags.has('DediSrv')

  // Manual Source is one source. Strong C + H is self-contradictory, so abstain as X.
  if (hasConsumer && hasHosting) return netEvidence('M', 'X', 'C-H')
  if (hasHosting) return netEvidence('M', 'H', 'DediSrv')
  if (hasConsumer) return netEvidence('M', 'C', consumerTags.join('+'))
  if (hasIsp) return netEvidence('M', 'I', 'ISP')
  return null
}

function netFromIpinfo(r) {
  if (!r || r.state !== 'json' || !r.data) return null
  const d = r.data || {}
  const p = d?.data?.privacy || {}
  const types = [d?.data?.asn?.type, d?.data?.company?.type].map(netType)
  if (toBool(p?.hosting) === true || types.includes('hosting')) return netEvidence('II', 'H', 'Hosting')
  if (types.includes('business')) return netEvidence('II', 'B', 'Business')
  if (types.includes('isp')) return netEvidence('II', 'I', 'ISP')
  return null
}

function netFromIpregistry(r) {
  if (!r || r.state !== 'json' || !r.data) return null
  const d = r.data || {}
  const types = [d?.connection?.type, d?.company?.type].map(netType)
  const carrierName = cleanNetText(d?.carrier?.name)
  const mobile = Boolean(carrierName)
  const hosting =
    toBool(d?.security?.is_cloud_provider) === true ||
    types.includes('hosting') ||
    types.includes('cdn')

  if (mobile && hosting) return netEvidence('IR', 'X', 'Mobile-H')
  if (mobile) return netEvidence('IR', 'C', 'Carrier')
  if (hosting) return netEvidence('IR', 'H', 'Hosting')
  if (types.includes('business')) return netEvidence('IR', 'B', 'Business')
  if (types.includes('isp')) return netEvidence('IR', 'I', 'ISP')
  return null
}

function netFromIpapi(r) {
  if (!r || r.state !== 'json' || !r.data) return null
  const d = r.data || {}
  const types = [d?.asn?.type, d?.company?.type].map(netType)
  const consumer = toBool(d?.is_mobile) === true || toBool(d?.is_satellite) === true
  const hosting = toBool(d?.is_datacenter) === true || types.includes('hosting')

  if (consumer && hosting) return netEvidence('IA', 'X', 'Consumer-H')
  if (consumer) {
    if (toBool(d?.is_mobile) === true && toBool(d?.is_satellite) === true) return netEvidence('IA', 'C', 'Mobile+Satellite')
    if (toBool(d?.is_mobile) === true) return netEvidence('IA', 'C', 'Mobile')
    return netEvidence('IA', 'C', 'Satellite')
  }
  if (hosting) return netEvidence('IA', 'H', 'Hosting')
  if (types.includes('business')) return netEvidence('IA', 'B', 'Business')
  if (types.includes('isp')) return netEvidence('IA', 'I', 'ISP')
  return null
}

function netFromAbuseIpdb(r) {
  if (!r || r.state !== 'json' || !r.data) return null
  const usage = cleanNetText(r?.data?.data?.usageType).toLowerCase()
  if (!usage) return null
  if (usage.includes('mobile isp')) return netEvidence('AB', 'C', 'MobileISP')
  if (usage.includes('fixed line isp')) return netEvidence('AB', 'L', 'FixedISP')
  if (
    usage.includes('data center') ||
    usage.includes('web hosting') ||
    usage.includes('transit') ||
    usage.includes('content delivery network') ||
    usage === 'cdn'
  ) return netEvidence('AB', 'H', 'Hosting')
  if (usage.includes('commercial')) return netEvidence('AB', 'B', 'Commercial')
  return null
}

function netFromIp2Location(r) {
  if (!r || r.state !== 'json' || !r.data) return null
  const d = r.data || {}
  // IP-specific usage_type is more specific than ASN-level as_usage_type.
  const primary = mapIp2Usage(d?.usage_type)
  if (primary) return netEvidence('I2', primary.kind, `IP-${primary.detail}`)
  const asUsage = mapIp2Usage(d?.as_info?.as_usage_type)
  if (asUsage) return netEvidence('I2', asUsage.kind, `AS-${asUsage.detail}`)
  // Explicit datacenter flag is still useful when usage type is missing.
  if (firstKnownBool(d?.proxy?.is_data_center, d?.proxy?.is_datacenter) === true) {
    return netEvidence('I2', 'H', 'DCFlag')
  }
  return null
}

function mapIp2Usage(value) {
  const raw = cleanNetText(value)
  if (!raw) return null
  const upper = raw.toUpperCase()
  const code = upper.split('/')[0].trim()

  if (code === 'MOB' || upper.includes('MOBILE')) return { kind: 'C', detail: 'MOB' }
  if (code === 'ISP' || upper.includes('FIXED LINE ISP')) return { kind: 'L', detail: 'ISP' }
  if (
    code === 'DCH' || code === 'CDN' ||
    upper.includes('DATA CENTER') || upper.includes('DATACENTER') ||
    upper.includes('HOSTING') || upper.includes('TRANSIT') || upper.includes('CONTENT DELIVERY')
  ) return { kind: 'H', detail: code || 'Hosting' }
  if (code === 'COM' || upper.includes('COMMERCIAL')) return { kind: 'B', detail: 'COM' }
  return null
}

function netFromScamalytics(r) {
  if (!r || r.state !== 'json' || !r.data) return null
  const s = r?.data?.scamalytics?.scamalytics_proxy || {}
  if (firstKnownBool(s?.is_server, s?.is_datacenter) === true) return netEvidence('SC', 'H', 'DC')
  return null
}

function netFromIpdata(r) {
  if (!r || r.state !== 'json' || !r.data) return null
  if (toBool(r?.data?.threat?.is_datacenter) === true) return netEvidence('ID', 'H', 'DC')
  return null
}

function netFromIpqs(r) {
  if (!r || r.state !== 'json' || !r.data) return null
  if (toBool(r?.data?.hosting) === true) return netEvidence('IQ', 'H', 'Hosting')
  return null
}

function netType(value) {
  return String(value ?? '').trim().toLowerCase()
}

function cleanNetText(value) {
  const s = String(value ?? '').trim()
  if (!s || s.toLowerCase() === 'null' || s.toLowerCase() === 'undefined') return ''
  return s
}

function formatNetworkCounts(c) {
  const x = c || {}
  return `Net-C${x.C || 0}-L${x.L || 0}-I${x.I || 0}-B${x.B || 0}-H${x.H || 0}-X${x.X || 0}`
}

function formatNetworkSources(sources) {
  const items = (sources || []).map(e => `${e.source}:${e.kind}`)
  return items.length ? `NetSrc-${items.join('+')}` : 'NetSrc0'
}

function countWeak(providers, field) {
  let yes = 0
  let valid = 0
  for (const p of providers) {
    const v = p?.[field]
    if (v === true || v === false) {
      valid += 1
      if (v === true) yes += 1
    }
  }
  return { yes, valid }
}

function weakFromProxycheck(r) {
  if (!r || r.state !== 'json') return {}
  const type = String(r?.data?.type || '').toLowerCase()
  const prox = String(r?.data?.proxy || '').toLowerCase()
  const isProxy = prox === 'yes' || prox === 'true' || r?.data?.proxy === true
  return {
    vpn: isProxy ? type.includes('vpn') : false,
    proxy: isProxy ? !type.includes('vpn') && !type.includes('tor') : false,
  }
}

function weakFromIpinfo(r) {
  if (!r || r.state !== 'json') return {}
  const p = r?.data?.data?.privacy || {}
  return { vpn: toBool(p?.vpn), proxy: toBool(p?.proxy) }
}

function weakFromScamalytics(r) {
  if (!r || r.state !== 'json') return {}
  const p = r?.data?.scamalytics?.scamalytics_proxy || {}
  return {
    vpn: toBool(p?.is_vpn),
    proxy: toBool(r?.data?.external_datasources?.firehol?.is_proxy),
  }
}

function weakFromIpregistry(r) {
  if (!r || r.state !== 'json') return {}
  const s = r?.data?.security || {}
  return { vpn: toBool(s?.is_vpn), proxy: toBool(s?.is_proxy) }
}

function weakFromIpapi(r) {
  if (!r || r.state !== 'json') return {}
  const d = r?.data || {}
  return { vpn: toBool(d?.is_vpn), proxy: toBool(d?.is_proxy) }
}

function weakFromIp2Location(r) {
  if (!r || r.state !== 'json') return {}
  const d = r?.data || {}
  const p = d?.proxy || {}
  return {
    vpn: toBool(p?.is_vpn),
    proxy: anyTrue(d?.is_proxy, p?.is_public_proxy, p?.is_web_proxy),
  }
}

function weakFromDbIp(r) {
  if (!r || r.state !== 'json') return {}
  return { vpn: null, proxy: toBool(r?.data?.isProxy) }
}

function weakFromIpdata(r) {
  if (!r || r.state !== 'json') return {}
  const t = r?.data?.threat || {}
  return { vpn: null, proxy: toBool(t?.is_proxy) }
}

function weakFromIpqs(r) {
  if (!r || r.state !== 'json') return {}
  const d = r?.data || {}
  return { vpn: toBool(d?.vpn), proxy: toBool(d?.proxy) }
}

function flagsFromProxycheck(pc) {
  if (!pc || pc.state !== 'json') return {}
  const type = String(pc?.data?.type || '').toLowerCase()
  const prox = String(pc?.data?.proxy || '').toLowerCase()
  const isProxy = prox === 'yes' || prox === 'true' || pc?.data?.proxy === true
  return {
    proxy: isProxy ? !type.includes('vpn') && !type.includes('tor') : false,
    vpn: isProxy ? type.includes('vpn') : false,
    tor: isProxy ? type.includes('tor') : false,
    abuse: null,
    dc: null,
    isp: null,
  }
}

function parseScamalyticsFlags(d) {
  if (!d) return {}
  const s = d?.scamalytics?.scamalytics_proxy || {}
  return {
    proxy: firstKnownBool(
      d?.external_datasources?.firehol?.is_proxy,
      s?.is_proxy,
      s?.is_public_proxy,
      s?.is_web_proxy
    ),
    vpn: firstKnownBool(s?.is_vpn),
    tor: firstKnownBool(
      d?.external_datasources?.x4bnet?.is_tor,
      s?.is_tor
    ),
    abuse: firstKnownBool(
      d?.external_datasources?.x4bnet?.is_blacklisted_spambot,
      d?.external_datasources?.x4bnet?.is_blacklisted
    ),
    dc: firstKnownBool(s?.is_server, s?.is_datacenter),
    isp: null,
  }
}

function parseIp2LocationFlags(d) {
  if (!d) return {}
  const p = d?.proxy || {}
  const usage = String(d?.usage_type || '').toLowerCase()
  return {
    proxy: firstKnownBool(p?.is_proxy),
    vpn: firstKnownBool(p?.is_vpn),
    tor: firstKnownBool(p?.is_tor),
    abuse: firstKnownBool(p?.is_spammer, p?.is_scanner, p?.is_botnet),
    dc: firstKnownBool(p?.is_data_center, p?.is_datacenter),
    isp: usage.includes('isp') ? true : usage ? false : null,
  }
}

function parseDbIpFlags(d) {
  if (!d) return {}
  return {
    proxy: toBool(d?.isProxy),
    vpn: null,
    tor: null,
    abuse: null,
    dc: null,
    isp: null,
  }
}

function parseIpqsFlags(d) {
  if (!d) return {}
  return {
    proxy: toBool(d?.proxy),
    vpn: toBool(d?.vpn),
    tor: toBool(d?.tor),
    abuse: firstKnownBool(d?.recent_abuse, d?.bot_status),
    dc: firstKnownBool(d?.is_crawler === false ? null : d?.hosting, d?.hosting),
    isp: null,
  }
}

function firstKnownBool(...values) {
  for (const v of values) {
    const b = toBool(v)
    if (b === true || b === false) return b
  }
  return null
}

function median(values) {
  const a = [...values].sort((x, y) => x - y)
  const m = Math.floor(a.length / 2)
  if (a.length % 2) return a[m]
  return Math.round((a[m - 1] + a[m]) / 2)
}



async function queryMaxmindBase($, ip, localProxy, timeout, allowDirectFallback) {
  return await queryExplicitProviderJson(
    $, 'mm', {
      method: 'get',
      url: `https://ipinfo.check.place/${encodeURIComponent(ip)}?lang=en`,
      proxy: localProxy,
      headers: { 'User-Agent': 'curl/8.5.0' },
      timeout,
    },
    allowDirectFallback
  )
}

async function queryProxycheck($, ip, localProxy, key, timeout, allowDirectFallback) {
  const keyPart = key ? `&key=${encodeURIComponent(key)}` : ''
  const pathIp = encodeURIComponent(ip)
  const urls = [
    `https://proxycheck.io/v2/${pathIp}?vpn=1&risk=1${keyPart}`,
    `http://proxycheck.io/v2/${pathIp}?vpn=1&risk=1${keyPart}`,
  ]

  let last = { state: 'err', status: 0, data: null, _reason: 'NoResult', _route: 'P' }

  for (const url of urls) {
    const r = await queryExplicitProviderJson(
      $, 'pc', {
        method: 'get',
        url,
        proxy: localProxy,
        headers: { Accept: 'application/json', 'User-Agent': 'curl/8.5.0' },
        timeout,
      },
      allowDirectFallback
    )
    last = r

    if (r.state !== 'json' || !r.data) continue
    const d = r.data
    if (d.status === 'denied' || d.status === 'error') continue

    let info = d[ip]
    if (!info || typeof info !== 'object') {
      const candidate = Object.keys(d).find(
        k => k !== 'status' && k !== 'message' && d[k] && typeof d[k] === 'object'
      )
      if (candidate) info = d[candidate]
    }
    if (!info || typeof info !== 'object') continue

    const risk = normalizeScore(info.risk)
    const proxyKnown = ['yes', 'no', 'true', 'false'].includes(
      String(info.proxy ?? '').toLowerCase()
    )
    if (risk === null && !proxyKnown) continue

    const flags = []
    const isProxy =
      String(info.proxy || '').toLowerCase() === 'yes' || info.proxy === true
    const type = String(info.type || '').trim().toLowerCase()
    if (isProxy) {
      if (type.includes('vpn')) flags.push('V')
      else if (type.includes('tor')) flags.push('T')
      else flags.push('P')
    }

    return {
      ...r,
      risk,
      flags,
      data: info,
    }
  }

  return last
}

async function queryIpinfo($, ip, localProxy, timeout, allowDirectFallback) {
  // Upstream v2026-09-04 uses a direct request for IPv6 and CurlARG for IPv4.
  // In Sub-Store, an explicit target IP is semantically safe to retry DIRECT:
  // proxy route remains first when available, then DIRECT only on unusable response.
  return await queryExplicitProviderJson(
    $, 'ii', {
      method: 'get',
      url: `https://ipinfo.io/widget/demo/${encodeURIComponent(ip)}`,
      proxy: localProxy,
      headers: { 'User-Agent': 'curl/8.5.0' },
      timeout,
    },
    allowDirectFallback
  )
}

async function queryCheckPlaceDb($, ip, db, providerKey, localProxy, timeout, allowDirectFallback) {
  return await queryExplicitProviderJson(
    $, providerKey, {
      method: 'get',
      url: `https://ipinfo.check.place/${encodeURIComponent(ip)}?db=${encodeURIComponent(db)}`,
      proxy: localProxy,
      headers: { 'User-Agent': 'curl/8.5.0' },
      timeout,
    },
    allowDirectFallback
  )
}

async function queryIpregistry($, ip, localProxy, timeout, allowDirectFallback) {
  const browserUa = randomBrowserUa()
  let key = 'sb69ksjcajfs4c'

  const page = await attemptTextWithDirectFallback($, {
    method: 'get',
    url: 'https://ipregistry.co',
    proxy: localProxy,
    headers: { 'User-Agent': browserUa },
    timeout,
  }, allowDirectFallback)

  const html = String(page.body || '')
  const m = html.match(/apiKey=["']([a-zA-Z0-9]+)["']/i)
  if (m?.[1]) key = m[1]

  return await queryExplicitProviderJson(
    $, 'ir', {
      method: 'get',
      url: `https://api.ipregistry.co/${encodeURIComponent(ip)}?hostname=true&key=${encodeURIComponent(key)}`,
      proxy: localProxy,
      headers: {
        Accept: 'application/json,text/plain,*/*',
        Origin: 'https://ipregistry.co',
        Referer: 'https://ipregistry.co/',
        'User-Agent': browserUa,
      },
      timeout,
    },
    allowDirectFallback
  )
}

async function queryIpapi($, ip, localProxy, timeout, allowDirectFallback) {
  // xykt/IPQuality v2026-09-04 changed from api.ipapi.is to the check.place relay.
  return await queryExplicitProviderJson(
    $, 'ia', {
      method: 'get',
      url: `https://ipinfo.check.place/${encodeURIComponent(ip)}?db=ipapi`,
      proxy: localProxy,
      headers: { 'User-Agent': 'curl/8.5.0' },
      timeout,
    },
    allowDirectFallback
  )
}

async function queryDbIp($, ip, localProxy, timeout) {
  // DB-IP uses /self. DIRECT fallback would query the Sub-Store host instead of
  // the target node. Upstream also has special IPv6 routing behavior that is not
  // semantically safe in our proxy-per-node architecture, so IPv6 stays skipped.
  if (isIPv6(ip)) {
    return {
      state: 'skip',
      status: 0,
      data: null,
      _route: 'IPv6',
      _reason: 'SelfApiUnsafe',
    }
  }
  if (!localProxy) {
    return {
      state: 'skip',
      status: 0,
      data: null,
      _route: 'NeedProxy',
      _reason: 'SelfApiNeedProxy',
    }
  }

  const browserUa =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36'

  const first = await attemptText($, {
    method: 'get',
    url: 'https://db-ip.com/api/core/',
    proxy: localProxy,
    headers: {
      Accept: '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      'Content-Type': 'text/html;charset=UTF-8',
      DNT: '1',
      'User-Agent': browserUa,
    },
    timeout,
  })

  const html = String(first.body || '')
  const keyMatch = html.match(/data-api-key=["']([^"']+)["']/i)
  const apiKey = keyMatch?.[1]
  if (!apiKey) {
    return withRoute({
      state: html.trim() ? 'html' : 'err',
      status: first.status || 0,
      data: null,
      _reason: html.trim() ? 'ApiKeyMissing' : first._reason || 'Empty',
    }, 'P')
  }

  const r = await attemptJsonish($, {
    method: 'post',
    url: `https://api.db-ip.com/v2/${encodeURIComponent(apiKey)}/self?convertCurrencies`,
    proxy: localProxy,
    headers: {
      Accept: '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      'Content-Type': 'text/plain;charset=UTF-8',
      DNT: '1',
      Origin: 'https://db-ip.com',
      Referer: 'https://db-ip.com/',
      'sec-ch-ua': '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-site',
      'User-Agent': browserUa,
    },
    body: '[["11.49","EUR"],["139.90","EUR"],["699.90","EUR"]]',
    timeout,
  })

  return withRoute(r, 'P')
}

async function queryExplicitProviderJson($, provider, opt, allowDirectFallback) {
  const hasProxy = Boolean(opt?.proxy)
  const first = await attemptJsonish($, opt)
  const firstRoute = hasProxy ? 'P' : 'D'
  const firstWithRoute = withRoute(first, firstRoute)

  if (
    !hasProxy ||
    !allowDirectFallback ||
    providerResponseUsable(provider, firstWithRoute)
  ) {
    return firstWithRoute
  }

  const directOpt = { ...opt }
  delete directOpt.proxy
  const direct = withRoute(await attemptJsonish($, directOpt), 'D')

  if (providerResponseUsable(provider, direct)) return direct
  return chooseBetterProviderResult(provider, firstWithRoute, direct)
}

async function attemptTextWithDirectFallback($, opt, allowDirectFallback) {
  const hasProxy = Boolean(opt?.proxy)
  const first = withRoute(await attemptText($, opt), hasProxy ? 'P' : 'D')
  if (!hasProxy || !allowDirectFallback || (first.state === 'text' && String(first.body || '').trim())) {
    return first
  }

  const directOpt = { ...opt }
  delete directOpt.proxy
  const direct = withRoute(await attemptText($, directOpt), 'D')
  if (direct.state === 'text' && String(direct.body || '').trim()) return direct
  return first
}

function providerResponseUsable(provider, r) {
  if (provider === 'mm') return maxmindBaseUsable(r)
  return providerHasUsableEvidence(provider, r)
}

function chooseBetterProviderResult(provider, a, b) {
  const rank = r => {
    if (providerResponseUsable(provider, r)) return 100
    if (r?.state === 'json') return 70
    if (r?.state === 'html') return 40
    if (r?.state === 'text') return 30
    if (r?.state === 'skip') return 20
    return 10
  }
  return rank(b) > rank(a) ? b : a
}

async function attemptJsonish($, opt) {
  try {
    const r = await request($, opt)
    const status = httpStatus(r)
    const d = json(r.body)

    if (d && typeof d === 'object') {
      return {
        state: 'json',
        status,
        data: d,
        _reason: status >= 400 ? `HTTP${status}` : '',
      }
    }

    const body = String(r.body || '').trim()
    if (body) {
      return {
        state: 'html',
        status,
        data: null,
        _reason: status >= 400 ? `HTTP${status}` : 'NonJson',
      }
    }

    return {
      state: 'err',
      status,
      data: null,
      _reason: status >= 400 ? `HTTP${status}` : 'Empty',
    }
  } catch (err) {
    return {
      state: 'err',
      status: 0,
      data: null,
      _reason: classifyRequestError(err),
    }
  }
}

async function attemptText($, opt) {
  try {
    const r = await request($, opt)
    return {
      state: 'text',
      status: httpStatus(r),
      body: String(r.body || ''),
      _reason: '',
    }
  } catch (err) {
    return {
      state: 'err',
      status: 0,
      body: '',
      _reason: classifyRequestError(err),
    }
  }
}

function withRoute(result, route) {
  return {
    ...(result || { state: 'err', status: 0, data: null }),
    _route: route,
  }
}


function randomBrowserUa() {
  const chrome = ['145.0.0.0', '144.0.0.0', '143.0.0.0', '142.0.0.0', '141.0.0.0', '140.0.0.0']
  const firefox = ['147.0', '146.0', '145.0', '144.0', '143.0', '142.0', '141.0', '140.0']
  if (Math.random() < 0.5) {
    const v = chrome[Math.floor(Math.random() * chrome.length)]
    return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v} Safari/537.36`
  }
  const v = firefox[Math.floor(Math.random() * firefox.length)]
  return `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${v}) Gecko/20100101 Firefox/${v}`
}

function formatMaxmind(r) {
  if (!r) return 'MM-E@P'
  if (maxmindBaseUsable(r)) return `MM-OK${routeSuffix(r)}`
  return formatState('MM', r)
}

function scBand(score) {
  if (score < 20) return 'Low'
  if (score < 60) return 'Medium'
  if (score < 90) return 'High'
  return 'VeryHigh'
}
function abuseBand(score) {
  if (score < 25) return 'Low'
  if (score < 75) return 'High'
  return 'DoS'
}
function i2Band(score) {
  if (score < 33) return 'Low'
  if (score < 66) return 'Medium'
  return 'High'
}
function iqBand(score) {
  if (score < 75) return 'Low'
  if (score < 85) return 'Suspicious'
  if (score < 90) return 'Risky'
  return 'HighRisk'
}

function formatScoreProviderWithBand(prefix, result, reader, bandFn) {
  const r = result || { state: 'err', status: 0, data: null }
  if (r.state === 'skip') return `${prefix}-Skip${r._route === 'MM' ? 'MM' : ''}`
  if (r.state !== 'json' || !r.data) return formatState(prefix, r)
  const score = normalizeScore(reader(r.data))
  if (score === null) return `${prefix}-JNoScore${routeSuffix(r)}`
  return `${prefix}-R${score}-${bandFn(score)}${routeSuffix(r)}`
}

function parseIpapiRisk(data) {
  const raw = String(data?.company?.abuser_score ?? '').trim()
  if (!raw) return { score: null, label: '' }

  const numMatch = raw.match(/([0-9]*\.?[0-9]+)/)
  let score = null
  if (numMatch) {
    const n = Number(numMatch[1])
    if (Number.isFinite(n)) score = n <= 1 ? Math.round(n * 100) : Math.round(n)
  }

  const labelMatch = raw.match(/\(([^)]+)\)/)
  const label = String(labelMatch?.[1] || '').trim()
  return { score: score === null ? null : Math.max(0, Math.min(100, score)), label }
}

function formatIpapi(result) {
  const r = result || { state: 'err', status: 0, data: null }
  if (r.state !== 'json' || !r.data) return formatState('IA', r)

  const risk = parseIpapiRisk(r.data)
  const flags = parseIpapiFlags(r.data)
  const label = risk.label
    ? risk.label.replace(/\s+/g, '').replace('VeryLow', 'VLow').replace('VeryHigh', 'VHigh')
    : ''
  const score = risk.score === null ? 'NA' : String(risk.score)
  return `IA-R${score}${label ? `-${label}` : ''}-F${flags.length ? flags.join('') : '0'}${routeSuffix(r)}`
}

function routeSuffix(r) {
  return r?._route ? `@${r._route}` : ''
}

function formatProxycheck(result) {
  const r = result || { state: 'err', status: 0, risk: null, flags: [] }
  if (r.state === 'json' && r.risk !== null && r.risk !== undefined) {
    return `PC-R${r.risk}${r.flags?.length ? `F${r.flags.join('')}` : ''}${routeSuffix(r)}`
  }
  return formatState('PC', r)
}

function formatGenericJson(prefix, result) {
  const r = result || { state: 'err', status: 0 }
  if (r.state === 'json') return `${prefix}-J${r.status || ''}`
  return formatState(prefix, r)
}

function formatScoreProvider(prefix, result, reader) {
  const r = result || { state: 'err', status: 0, data: null }
  if (r.state !== 'json' || !r.data) return formatState(prefix, r)

  const score = normalizeScore(reader(r.data))
  if (score === null) return `${prefix}-JNoScore${routeSuffix(r)}`
  return `${prefix}-R${score}${routeSuffix(r)}`
}

function formatFlagProvider(prefix, result, parser) {
  const r = result || { state: 'err', status: 0, data: null }
  if (r.state === 'skip') return `${prefix}-Skip${r._route === 'MM' ? 'MM' : ''}`
  if (r.state !== 'json' || !r.data) return formatState(prefix, r)

  const keyMap = { II: 'ii', IR: 'ir', ID: 'id' }
  const key = keyMap[prefix]
  if (key && !providerHasUsableEvidence(key, r)) {
    return `${prefix}-JNoData${routeSuffix(r)}`
  }

  const flags = parser(r.data)
  return `${prefix}-F${flags.length ? flags.join('') : '0'}${routeSuffix(r)}`
}

function formatDbIp(result) {
  const r = result || { state: 'err', status: 0, data: null }
  if (r.state === 'skip') return `DB-Skip${r._route ? `@${r._route}` : ''}`
  if (r.state !== 'json' || !r.data) return formatState('DB', r)

  const threat = String(r.data?.threatLevel || '').trim().toLowerCase()
  const flags = []
  if (toBool(r.data?.isProxy) === true) flags.push('P')
  if (toBool(r.data?.isCrawler) === true) flags.push('B')

  let level = ''
  if (threat === 'low') level = 'Low'
  else if (threat === 'medium') level = 'Med'
  else if (threat === 'high') level = 'High'
  else if (threat) level = threat.replace(/\s+/g, '')

  if (!level && flags.length === 0) return `DB-JNoRisk${routeSuffix(r)}`
  return `DB-${level || 'Risk'}${flags.length ? `F${flags.join('')}` : ''}${routeSuffix(r)}`
}

function formatState(prefix, r) {
  const status = r?.status ? String(r.status) : ''
  if (r?.state === 'skip') return `${prefix}-Skip${r?._route === 'MM' ? 'MM' : ''}`
  const route = routeSuffix(r)
  if (r?.state === 'html') return `${prefix}-H${status}${route}`
  if (r?.state === 'json') return `${prefix}-J${status}${route}`
  return `${prefix}-E${status}${route}`
}

function parseIpinfoFlags(d) {
  const p = d?.data?.privacy || {}
  return collectFlags({
    P: p.proxy,
    V: p.vpn,
    T: p.tor,
    D: p.hosting,
  })
}

function parseIpregistryFlags(d) {
  const s = d?.security || {}
  return collectFlags({
    P: s.is_proxy,
    V: s.is_vpn,
    T: anyTrue(s.is_tor, s.is_tor_exit),
    D: s.is_cloud_provider,
    A: s.is_abuser,
    M: Boolean(cleanNetText(d?.carrier?.name)),
  })
}

function parseIpapiFlags(d) {
  return collectFlags({
    P: d?.is_proxy,
    V: d?.is_vpn,
    T: d?.is_tor,
    D: d?.is_datacenter,
    A: d?.is_abuser,
    B: d?.is_crawler,
    M: d?.is_mobile,
    S: d?.is_satellite,
  })
}

function parseIpdataFlags(d) {
  const t = d?.threat || {}
  return collectFlags({
    P: t.is_proxy,
    T: t.is_tor,
    D: t.is_datacenter,
    A: anyTrue(t.is_threat, t.is_known_abuser, t.is_known_attacker),
  })
}

function ipinfoDims(d) {
  const p = d?.data?.privacy || {}
  const asnType = String(d?.data?.asn?.type || '').toLowerCase()
  const companyType = String(d?.data?.company?.type || '').toLowerCase()
  return {
    proxy: toBool(p?.proxy),
    vpn: toBool(p?.vpn),
    tor: toBool(p?.tor),
    abuse: null,
    dc: toBool(p?.hosting),
    isp: asnType === 'isp' || companyType === 'isp'
      ? true
      : (asnType || companyType ? false : null),
  }
}

function ipregistryDims(d) {
  const s = d?.security || {}
  const connectionType = String(d?.connection?.type || '').toLowerCase()
  const companyType = String(d?.company?.type || '').toLowerCase()
  return {
    proxy: toBool(s?.is_proxy),
    vpn: toBool(s?.is_vpn),
    tor: firstKnownBool(s?.is_tor, s?.is_tor_exit),
    abuse: toBool(s?.is_abuser),
    dc: toBool(s?.is_cloud_provider),
    isp: connectionType === 'isp' || companyType === 'isp'
      ? true
      : (connectionType || companyType ? false : null),
  }
}

function ipapiDims(d) {
  const asnType = String(d?.asn?.type || '').toLowerCase()
  const companyType = String(d?.company?.type || '').toLowerCase()
  return {
    proxy: toBool(d?.is_proxy),
    vpn: toBool(d?.is_vpn),
    tor: toBool(d?.is_tor),
    abuse: toBool(d?.is_abuser),
    dc: toBool(d?.is_datacenter),
    isp: asnType === 'isp' || companyType === 'isp'
      ? true
      : (asnType || companyType ? false : null),
  }
}

function ipdataDims(d) {
  const t = d?.threat || {}
  return {
    proxy: toBool(t?.is_proxy),
    vpn: null,
    tor: toBool(t?.is_tor),
    abuse: firstKnownBool(t?.is_threat, t?.is_known_abuser, t?.is_known_attacker),
    dc: toBool(t?.is_datacenter),
    isp: null,
  }
}

function collectFlags(values) {
  const out = []
  for (const [k, v] of Object.entries(values || {})) {
    if (toBool(v) === true) out.push(k)
  }
  return out
}

function anyTrue(...values) {
  for (const v of values) {
    if (toBool(v) === true) return true
  }
  let sawFalse = false
  for (const v of values) {
    if (toBool(v) === false) sawFalse = true
  }
  return sawFalse ? false : null
}

function toBool(v) {
  if (v === true || v === false) return v
  const s = String(v ?? '').trim().toLowerCase()
  if (['true', 'yes', '1', 'y'].includes(s)) return true
  if (['false', 'no', '0', 'n'].includes(s)) return false
  return null
}

function isTruthy(value) {
  if (value === true || value === 1) return true
  return ['1', 'true', 'yes', 'on', '是'].includes(
    String(value ?? '').trim().toLowerCase()
  )
}

function normalizeScore(value) {
  if (value === null || value === undefined || value === '') return null
  const n = Number(value)
  if (!Number.isFinite(n)) return null
  return Math.max(0, Math.min(100, Math.round(n)))
}

function httpStatus(r) {
  const n = Number(r?.statusCode ?? r?.status ?? r?.response?.statusCode ?? 0)
  return Number.isFinite(n) && n > 0 ? Math.round(n) : 0
}
function normalizeIp(value) {
  const s = String(value || '').trim()
  if (!s) return ''
  if (!/^[0-9A-Fa-f:.]+$/.test(s)) return ''
  if (!s.includes('.') && !s.includes(':')) return ''
  return s
}

function addTempTags(name, newTags) {
  const parsed = parseV21Name(name)
  if (!parsed) return `[${newTags.join(',')}:Fmt] ${String(name || '')}`

  // Remove only tags owned by IPQuality. Standardizer evidence such as ResIP / ISP /
  // Mobile / SatNet / DediSrv must survive, otherwise a second run would lose Manual Source.
  const kept = parsed.tags.filter(t => !isIpQualityManagedTag(t))
  const tags = [...newTags, ...kept]
  return `${parsed.region} ${parsed.source}${tags.length ? ` ${tags.join('·')}` : ''}｜${parsed.tail}`
}

function isIpQualityManagedTag(t) {
  return /^(?:EIP-|EIP4-|EIP6-|EIP4Fail-|EIP6Fail-|EIPDual$|EIP4Only$|EIP6Only$|EIPMissing$|Primary4$|Primary6$|DeadCandidate$|DeadConfirmed$|DeadRecovered$|IPQStageErr$|Trust$|Normal$|Risk$|Unrated$|ConsumerIP$|BusinessIP$|HostingIP$|NetUnrated$|ConsIP$|BusiIP$|HostIP$|UnkIP$|Net-C\d+-L\d+-I\d+-B\d+-H\d+-X\d+$|NetSrc(?:0|-.*)$|NetWhy(?:0|-.*)$|Q\d+\/7$|Clean\d+\/7$|Caution\d+$|RiskSrc\d+$|Score\d+\/7$|Core\d+\/(?:4|5)$|Valid\d+(?:\/10)?$|Full$|Lite$|MM-(?:Full|Lite|OK.*|H\d+.*|E.*|Skip.*)$|Hard(?:0|-.+)$|Strong(?:0|-.+)$|RiskReason(?:0|-.+)$|CautionReason(?:0|-.+)$|VPN\d+\/\d+$|Proxy\d+\/\d+$|PC-|II-|SC-|IR-|IA-|AB-|I2-|DB-|ID-|IQ-|TrustedIP$|RiskIP$|AbuseIP$|VPNIP$|ProxyIP$|TorIP$|DCIP$|ISPNet$|IPQS-R\d+$|VPN$|Proxy$|Tor$|Abuse$|CPBase|CPCurl|PCScoreErr$|IPProbe(?:MetaErr|ExitErr|Unsup)$|IPScoreErr$|IPQ(?:MetaErr|ApiErr|Unsup)$)/.test(String(t || ''))
}

function isChainNodeName(name) {
  const parsed = parseV21Name(name)
  return !!(parsed && /^@Chain-/i.test(parsed.source))
}

function parseV21Name(name) {
  const s = String(name || '')
  const bar = s.indexOf('｜')
  if (bar < 0) return null
  const left = s.slice(0, bar).trim()
  const tail = s.slice(bar + 1)
  const m = left.match(/^(\S+)\s+(@\S+)(?:\s+(.+))?$/)
  if (!m) return null
  return {
    region: m[1],
    source: m[2],
    tags: m[3] ? m[3].split('·').filter(Boolean) : [],
    tail,
  }
}

async function request($, opt) {
  const method = String(opt.method || 'get').toLowerCase()
  return await $.http[method]({ ...opt, timeout: Number(opt.timeout || 8000) })
}

async function runConcurrent(tasks, concurrency) {
  let cursor = 0
  const workers = Array.from({ length: Math.min(concurrency, tasks.length || 1) }, async () => {
    while (true) {
      const i = cursor++
      if (i >= tasks.length) return
      await tasks[i]()
    }
  })
  await Promise.all(workers)
}

function json(v) {
  try {
    if (typeof v === 'string') return JSON.parse(v)
    if (v && typeof v === 'object') return v
    return null
  } catch (_) {
    return null
  }
}
