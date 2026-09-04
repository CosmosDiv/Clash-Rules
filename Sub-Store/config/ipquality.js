/**
 * Sub-Store IPQuality Quality + Network Identity v1.2.0
 * ------------------------------------------------------------
 * Adapted from xykt/IPQuality v2026-08-09 (AGPL-3.0)
 *
 * v1.2.0 性能与可观测性版：
 *   - Quality / Network Identity / Risk 过滤算法保持 v1.1.1 完全不变；
 *   - 新增节点配置指纹 -> EIP 短缓存：默认成功 30 分钟、失败 2 分钟；
 *   - EIP 缓存命中时不再为该节点启动 HTTP META；仅对缓存 MISS 节点实时探测；
 *   - Provider 缓存缺失而 EIP 已缓存时，仅补启动每个相关 EIP 的一个代表节点；
 *   - 新增 Run ID、阶段进度、EIP/Provider 缓存命中率、结果统计与总耗时日志；
 *   - 新增同批次运行重叠提醒，只告警、不阻断；
 *   - EIP 缓存采用独立 namespace，不影响 v1.0.1 Provider 缓存 namespace。
 *
 * v1.1.1 正式版：
 *   - 仅优化 Network Identity 最终显示标签：ConsIP / BusiIP / HostIP / UnkIP；
 *   - 兼容清理 v1.1.0 旧标签 ConsumerIP / BusinessIP / HostingIP / NetUnrated；
 *   - 生产默认成功缓存由 24h 调整为 20h；Quality / Identity 裁决算法保持不变。
 *   - 在 v1.0.3 的 Quality 四级（Trust / Normal / Risk / Unrated）之外，
 *     新增独立的 Network Identity 四类（ConsIP / BusiIP / HostIP / UnkIP）。
 *   - Quality 与 Network Identity 完全独立：互不修改、互不补偿。
 *   - AI 策略不在本脚本内决定；Mihomo/YAML 后续按组合标签消费：
 *       Trust + ConsIP -> AI Preferred
 *       Trust + BusiIP -> AI Good
 *       Trust + HostIP  -> AI Fallback
 *     Normal / Unrated / UnkIP 不为 AI Auto 自动放宽；不设置 AI Emergency。
 *   - Network Identity 复用既有数据库响应，不新增外部 API 请求。
 *   - Standardizer 的 ResIP / Mobile / SatNet / ISP / DediSrv 仅作为一个 Manual Source；
 *     它是 Bonus Evidence，不是 Required Evidence，也不是 Override。
 *   - 同一个 Provider 无论命中多少字段，最多贡献一份网络身份方向，避免重复计票。
 *   - 相同 EIP 共享自动数据库结果，但每个节点仍结合自己的 Standardizer 标签独立裁决 Identity。
 *   - 增强幂等：重复运行时清除上次 Quality / Identity / 诊断标签，但保留 Standardizer 原始证据。
 *   - Chain 行为沿用 v1.0.3：@Chain-* 默认旁路；检测Chain=1 时可检测，但永不因 Risk 被删除。
 *   - 为避免升级后重新请求，继续沿用 v1.0.1 缓存 namespace。
 *
 * ------------------------------------------------------------
 * A. Quality / 信誉质量（算法保持 v1.0.3）
 *
 * Risk:
 *   任意可靠来源出现明确高风险评分或明确恶意事实 -> Risk。
 *
 * Trust:
 *   至少 3 个评分源有效；全部 Clean；没有 Caution；没有 Risk。
 *
 * Normal:
 *   至少 1 个评分源有效且没有 Risk，但不满足 Trust。
 *
 * Unrated:
 *   没有评分源，或检测链路无法完成。
 *
 * 注意：VPN / Proxy / Hosting / Datacenter 本身不改变 Quality。
 *
 * ------------------------------------------------------------
 * B. Network Identity / 网络身份
 *
 * 内部证据维度：
 *   C = Consumer 强证据（Residential / Mobile / Satellite）
 *   L = Last-mile / Fixed-line ISP 中强证据
 *   I = Generic ISP 弱证据
 *   B = Business / Commercial 证据
 *   H = Hosting / Datacenter / Cloud / Transit 强证据
 *   X = 单一来源内部出现强冲突，该来源本轮 abstain
 *
 * Manual Source（Standardizer）只算 1 个来源：
 *   ResIP / Mobile / SatNet -> C
 *   ISP                     -> I
 *   DediSrv                 -> H
 *   StaticIP / DynIP / DediIP / NativeIP / IPv6 不参与网络身份。
 *   C 与 H 同时出现时 Manual -> X，不制造“两票”。
 *
 * 自动来源（只复用已有响应）：
 *   IPinfo      hosting/type=hosting -> H；type=business -> B；type=isp -> I
 *   ipregistry  carrier.name -> C；cloud/hosting/cdn -> H；business -> B；isp -> I
 *   ipapi.is    is_mobile/is_satellite -> C；is_datacenter/hosting -> H；business -> B；isp -> I
 *   AbuseIPDB   Mobile ISP -> C；Fixed Line ISP -> L；Hosting/Transit/CDN -> H；Commercial -> B
 *   IP2Location MOB -> C；ISP -> L；DCH/CDN -> H；COM -> B（优先 IP usage_type，再看 ASN usage）
 *   Scamalytics server/datacenter -> H
 *   ipdata       is_datacenter -> H
 *   IPQS         hosting -> H
 *
 * ConsIP：
 *   H=0 且满足 C>=2，或 C>=1+L>=1，或 L>=2。
 *
 * BusiIP：
 *   未达到 Consumer，H=0，且 I+B >= 2 个独立来源。
 *
 * HostIP：
 *   - H>=2，且没有已经达到 Consumer 阈值的强冲突；或
 *   - H=1 且 C=L=0。
 *
 * UnkIP：
 *   证据不足，或 Consumer/Hosting 强证据冲突无法可靠消解。
 *
 * 核心原则：
 *   Quality 是 AI 的资格门槛；Network Identity 是通过资格门槛后的优先级。
 *   两者互不替代、互不补偿。
 *
 * ------------------------------------------------------------
 * 正式输出（诊断=0）：
 *   US @Airport Trust·ConsIP·ResIP·StaticIP·Bulk·1x｜...
 *   US @Airport Trust·BusiIP·ISP·Bulk·1x｜...
 *   US @Airport Trust·HostIP·DediSrv·1x｜...
 *   US @Airport Trust·UnkIP·Bulk·1x｜...
 *   US @Chain-US ResIP·1x｜...  // 默认原样旁路
 *
 * 诊断输出（诊断=1）额外包含：
 *   EIP-x.x.x.x
 *   Trust / Normal / Risk / Unrated
 *   ConsIP / BusiIP / HostIP / UnkIP
 *   Net-Cx-Lx-Ix-Bx-Hx-Xx
 *   NetSrc-M:C+II:I+IA:H+...
 *   NetWhy-...
 *   以及 v1.0.3 原有评分、风险与 Provider 状态标签。
 *
 * ------------------------------------------------------------
 * 参数：
 *   诊断 = 0            // 0=正式短标签；1=完整诊断标签
 *   过滤Risk =           // 未填写：正式模式默认1，诊断模式默认0
 *   检测Chain = 0       // 0=默认跳过 @Chain-*；1=检测但 Chain 永不因 Risk 删除
 *   成功缓存小时 = 20
 *   失败缓存小时 = 2
 *   强制刷新 = 0       // 1=Provider + EIP 全部强制刷新
 *
 *   出口缓存分钟 = 30  // 节点配置未变时复用 EIP；0=关闭
 *   出口失败缓存分钟 = 2
 *   出口强制刷新 = 0   // 只强制刷新 EIP，不影响 Provider 数据缓存
 *
 *   日志 = 1          // 1=输出阶段日志；需 Sub-Store 开启日志保存后在 /logs 查看
 *   日志详情 = 0      // 1=额外输出各 Provider HIT/MISS
 *
 *   出口并发 = 4
 *   数据并发 = 2
 *   出口timeout = 2500
 *   数据timeout = 10000
 *
 *   proxycheck_key =
 *   http_meta_host = 127.0.0.1
 *   http_meta_port = 9876
 *   http_meta_protocol = http
 *   http_meta_authorization =
 *   http_meta_start_delay = 1800
 *   http_meta_proxy_timeout = 15000
 */

async function operator(proxies = [], targetPlatform, env = {}) {
  const $ = $substore
  const args = typeof $arguments === 'object' && $arguments ? $arguments : {}
  const startedAt = Date.now()
  const runId = createRunId()

  const exitConcurrency = Math.max(1, Math.min(12, parseInt(args['出口并发'] || 4)))
  const dataConcurrency = Math.max(1, Math.min(6, parseInt(args['数据并发'] || 2)))
  const exitTimeout = Math.max(1500, parseInt(args['出口timeout'] || 2500))
  const dataTimeout = Math.max(5000, parseInt(args['数据timeout'] || 10000))
  const proxycheckKey = String(args.proxycheck_key || '').trim()
  const successCacheHours = Math.max(0, Number(args['成功缓存小时'] || 20))
  const failCacheHours = Math.max(0, Number(args['失败缓存小时'] || 2))
  const forceRefresh = isTruthy(args['强制刷新'])
  const exitCacheMinutes = Math.max(0, Number(args['出口缓存分钟'] ?? 30))
  const exitFailCacheMinutes = Math.max(0, Number(args['出口失败缓存分钟'] ?? 2))
  const exitForceRefresh = forceRefresh || isTruthy(args['出口强制刷新'])
  const diagnostic = isTruthy(args['诊断'])
  const detectChain = isTruthy(args['检测Chain'])
  const hasFilterRiskArg = Object.prototype.hasOwnProperty.call(args, '过滤Risk')
  const filterRisk = hasFilterRiskArg ? isTruthy(args['过滤Risk']) : !diagnostic
  const logEnabled = Object.prototype.hasOwnProperty.call(args, '日志') ? isTruthy(args['日志']) : true
  const logDetails = isTruthy(args['日志详情'])
  const cache = typeof scriptResourceCache !== 'undefined' ? scriptResourceCache : null
  const cacheAvailable = !!(cache && typeof cache.get === 'function' && typeof cache.set === 'function')
  const host = String(args.http_meta_host || '127.0.0.1')
  const port = String(args.http_meta_port || '9876')
  const protocol = String(args.http_meta_protocol || 'http')
  const authorization = String(args.http_meta_authorization || '')
  const startDelay = Math.max(0, parseInt(args.http_meta_start_delay || 1800))
  const perProxyTimeout = Math.max(6000, parseInt(args.http_meta_proxy_timeout || 15000))
  const api = `${protocol}://${host}:${port}`
  const log = createRunLogger($, runId, logEnabled)

  const output = proxies.map(p => ({ ...p }))
  const internal = []
  const riskIndices = new Set()
  let chainBypass = 0
  let unsupported = 0
  let stage = 'prepare'
  let runMarker = null
  const sessions = []
  const eipStats = {
    cacheSuccessHit: 0,
    cacheFailHit: 0,
    cacheMiss: 0,
    cacheReadError: 0,
    cacheWriteError: 0,
    probeSuccess: 0,
    probeFail: 0,
  }
  const providerStats = {
    hit: 0,
    miss: 0,
    readError: 0,
    writeError: 0,
    byProvider: {},
  }

  for (let i = 0; i < proxies.length; i++) {
    const proxy = proxies[i]
    const isChain = isChainNodeName(proxy?.name)

    // Production default: Chain landing nodes are manually authorized policy assets.
    // They share the same merged subscription, but bypass IPQuality unless explicitly requested.
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
        output[i].name = addTempTags(proxy.name, diagnostic ? ['Unrated', 'UnkIP', 'IPProbeUnsup'] : ['Unrated', 'UnkIP'])
        continue
      }
      for (const key in proxy) {
        if (/^_/i.test(key)) node[key] = proxy[key]
      }
      internal.push({
        index: i,
        node,
        originalName: String(proxy.name || ''),
        ip: '',
        isChain,
        fingerprint: nodeFingerprint(node),
        localProxy: '',
      })
    } catch (_) {
      unsupported++
      output[i].name = addTempTags(proxy.name, diagnostic ? ['Unrated', 'UnkIP', 'IPProbeUnsup'] : ['Unrated', 'UnkIP'])
    }
  }

  log.info(
    `START | input=${proxies.length} detect=${internal.length} chain-bypass=${chainBypass} unsupported=${unsupported} ` +
    `cache=${cacheAvailable ? 'available' : 'unavailable'} eip-ttl=${exitCacheMinutes}m provider-ttl=${successCacheHours}h`
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
  let exitCacheDirty = false

  try {
    stage = 'eip-cache'
    const probeItems = []

    for (const item of internal) {
      const cached = getExitCacheEntry(
        exitCache,
        item.fingerprint,
        exitCacheMinutes,
        exitFailCacheMinutes,
        exitForceRefresh
      )

      if (cached.hit && cached.ok && cached.ip) {
        item.ip = cached.ip
        eipStats.cacheSuccessHit++
        continue
      }

      if (cached.hit && !cached.ok) {
        eipStats.cacheFailHit++
        output[item.index].name = addTempTags(
          item.originalName,
          diagnostic ? ['Unrated', 'UnkIP', 'IPProbeExitErr'] : ['Unrated', 'UnkIP']
        )
        continue
      }

      eipStats.cacheMiss++
      probeItems.push(item)
    }

    log.info(
      `EIP CACHE | hit=${eipStats.cacheSuccessHit} fail-hit=${eipStats.cacheFailHit} ` +
      `miss=${eipStats.cacheMiss} force=${exitForceRefresh ? 'on' : 'off'}`
    )

    stage = 'eip-probe'
    if (probeItems.length) {
      log.info(`HTTP META | start EIP probe nodes=${probeItems.length}`)
      const session = await startHttpMetaSession(
        $, api, authorization, probeItems, startDelay, perProxyTimeout
      )
      sessions.push(session)
      for (let i = 0; i < probeItems.length; i++) {
        probeItems[i].localProxy = `http://${host}:${session.ports[i]}`
      }

      let done = 0
      const reportProgress = createProgressReporter(probeItems.length, n => {
        log.info(`EIP PROBE | ${n}/${probeItems.length}`)
      })

      const probeTasks = probeItems.map(item => async () => {
        try {
          item.ip = await detectExitIp($, item.localProxy, exitTimeout)
          eipStats.probeSuccess++
          if (exitCacheMinutes > 0) {
            setExitCacheEntry(exitCache, item.fingerprint, true, item.ip)
            exitCacheDirty = true
          }
        } catch (_) {
          eipStats.probeFail++
          output[item.index].name = addTempTags(
            item.originalName,
            diagnostic ? ['Unrated', 'UnkIP', 'IPProbeExitErr'] : ['Unrated', 'UnkIP']
          )
          if (exitFailCacheMinutes > 0) {
            setExitCacheEntry(exitCache, item.fingerprint, false, '')
            exitCacheDirty = true
          }
        } finally {
          done++
          reportProgress(done)
        }
      })
      await runConcurrent(probeTasks, exitConcurrency)
      log.info(
        `EIP PROBE DONE | success=${eipStats.probeSuccess} fail=${eipStats.probeFail}`
      )
    } else {
      log.info('HTTP META | skip EIP probe; all eligible nodes resolved from cache')
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

    // 按真实出口 IP 去重；优先保留已有 localProxy 的代表节点。
    const representatives = new Map()
    for (const item of internal) {
      if (!item.ip) continue
      const current = representatives.get(item.ip)
      if (!current || (!current.localProxy && item.localProxy)) {
        representatives.set(item.ip, item)
      }
    }

    // 若 EIP 来自短缓存，但 Provider 数据已经过期/缺失，则只补启动每个 EIP 的一个代表节点。
    stage = 'provider-preflight'
    const providerProxyItems = []
    for (const [ip, item] of representatives.entries()) {
      if (item.localProxy) continue
      if (providerNeedsLocalProxy(cache, ip, successCacheHours, failCacheHours, forceRefresh)) {
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
    }

    // 单 EIP 严格串行；不同 EIP 之间按数据并发执行。
    // 先完整保持 upstream 的数据库顺序；最后再追加我们自己的 ProxyCheck 冗余。
    stage = 'provider-check'
    const checkMap = new Map()
    const repEntries = [...representatives.entries()]
    let providerDone = 0
    const reportProviderProgress = createProgressReporter(repEntries.length, n => {
      log.info(`PROVIDER CHECK | ${n}/${repEntries.length} EIP`)
    })

    log.info(`PROVIDER CHECK | unique-eip=${repEntries.length} concurrency=${dataConcurrency}`)

    const checkTasks = repEntries.map(([ip, item]) => async () => {
      const localProxy = item.localProxy || ''
      const r = {}

      // upstream 1: db_maxmind()
      r.mm = await cachedProvider(
        cache, 'mm', ip, successCacheHours, failCacheHours, forceRefresh,
        () => queryMaxmindBase($, ip, localProxy, dataTimeout)
      )
      const fullMode = maxmindBaseUsable(r.mm)

      // upstream 2: db_ipinfo()
      r.ii = await cachedProvider(
        cache, 'ii', ip, successCacheHours, failCacheHours, forceRefresh,
        () => queryIpinfo($, ip, localProxy, dataTimeout)
      )

      // upstream 3: db_scamalytics()
      if (fullMode) {
        r.sc = await cachedProvider(
          cache, 'sc', ip, successCacheHours, failCacheHours, forceRefresh,
          () => queryCheckPlaceDb($, ip, 'scamalytics', localProxy, dataTimeout)
        )
      } else r.sc = skippedByMaxmind()

      // upstream 4: db_ipregistry()
      r.ir = await cachedProvider(
        cache, 'ir', ip, successCacheHours, failCacheHours, forceRefresh,
        () => queryIpregistry($, ip, localProxy, dataTimeout)
      )

      // upstream 5: db_ipapi()
      r.ia = await cachedProvider(
        cache, 'ia', ip, successCacheHours, failCacheHours, forceRefresh,
        () => queryIpapiIs($, ip, localProxy, dataTimeout)
      )

      // upstream 6: db_abuseipdb()
      if (fullMode) {
        r.ab = await cachedProvider(
          cache, 'ab', ip, successCacheHours, failCacheHours, forceRefresh,
          () => queryCheckPlaceDb($, ip, 'abuseipdb', localProxy, dataTimeout)
        )
      } else r.ab = skippedByMaxmind()

      // upstream 7: db_ip2location()
      if (fullMode) {
        r.i2 = await cachedProvider(
          cache, 'i2', ip, successCacheHours, failCacheHours, forceRefresh,
          () => queryCheckPlaceDb($, ip, 'ip2location', localProxy, dataTimeout)
        )
      } else r.i2 = skippedByMaxmind()

      // upstream 8: db_dbip()
      r.db = await cachedProvider(
        cache, 'db', ip, successCacheHours, failCacheHours, forceRefresh,
        () => queryDbIp($, ip, localProxy, dataTimeout)
      )

      // upstream 9: db_ipdata()
      if (fullMode) {
        r.id = await cachedProvider(
          cache, 'id', ip, successCacheHours, failCacheHours, forceRefresh,
          () => queryCheckPlaceDb($, ip, 'ipdata', localProxy, dataTimeout)
        )
      } else r.id = skippedByMaxmind()

      // upstream 10: db_ipqs()
      if (fullMode) {
        r.iq = await cachedProvider(
          cache, 'iq', ip, successCacheHours, failCacheHours, forceRefresh,
          () => queryCheckPlaceDb($, ip, 'ipqualityscore', localProxy, dataTimeout)
        )
      } else r.iq = skippedByMaxmind()

      // Extra: ProxyCheck。仅作为额外冗余，不改变 upstream 执行顺序。
      r.pc = await cachedProvider(
        cache, 'pc', ip, successCacheHours, failCacheHours, forceRefresh,
        () => queryProxycheck($, ip, localProxy, proxycheckKey, dataTimeout)
      )

      r._fullMode = fullMode
      recordProviderCacheStats(r, providerStats)
      checkMap.set(ip, r)
      providerDone++
      reportProviderProgress(providerDone)
    })

    await runConcurrent(checkTasks, dataConcurrency)

    log.info(
      `PROVIDER CACHE | hit=${providerStats.hit} miss=${providerStats.miss} ` +
      `read-error=${providerStats.readError} write-error=${providerStats.writeError}`
    )
    if (logDetails) {
      const detail = formatProviderCacheDetail(providerStats.byProvider)
      if (detail) log.info(`PROVIDER CACHE DETAIL | ${detail}`)
    }

    // 分别计算两张独立成绩单，再组合输出。
    // Quality 只回答信誉/风险；Network Identity 只回答网络身份。
    // 相同 EIP 可以共享 r（自动数据库结果），但 Identity 必须逐节点叠加各自 Manual Source。
    stage = 'verdict'
    for (const item of internal) {
      if (!item.ip) continue
      const r = checkMap.get(item.ip) || {}
      const c = buildSimpleVerdict(r)
      const n = buildNetworkIdentity(r, item.originalName)

      let tags

      if (diagnostic) {
        tags = [
          `EIP-${item.ip}`,
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
    log.error(`FAIL | stage=${stage} reason=${errorMessage(err)}`)
    for (const item of internal) {
      output[item.index].name = addTempTags(
        item.originalName,
        diagnostic ? ['Unrated', 'UnkIP', 'IPProbeMetaErr'] : ['Unrated', 'UnkIP']
      )
    }
  } finally {
    for (const session of sessions) {
      await stopHttpMetaSession($, api, authorization, session)
    }
    markRunFinished(cache, runMarker, runId)
  }

  const counts = countFinalClassifications(output)
  const finalOutput = filterRisk ? output.filter((_, i) => !riskIndices.has(i)) : output
  log.info(
    `RESULT | Trust=${counts.quality.Trust} Normal=${counts.quality.Normal} ` +
    `Risk=${counts.quality.Risk} Unrated=${counts.quality.Unrated} ` +
    `ConsIP=${counts.identity.ConsIP} BusiIP=${counts.identity.BusiIP} ` +
    `HostIP=${counts.identity.HostIP} UnkIP=${counts.identity.UnkIP}`
  )
  log.info(
    `DONE | output=${finalOutput.length} risk-removed=${filterRisk ? riskIndices.size : 0} ` +
    `duration=${formatDuration(Date.now() - startedAt)}`
  )
  return finalOutput
}

const EXIT_CACHE_KEY = 'ipqlite:eip:v1'
const RUN_MARKER_PREFIX = 'ipqlite:run:v1:'

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
  if (!startBody?.pid || !Array.isArray(startBody?.ports) || startBody.ports.length !== items.length) {
    throw new Error('HTTP META start invalid')
  }
  if (startDelay) await $.wait(startDelay)
  return { pid: startBody.pid, ports: startBody.ports }
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

function loadExitCache(cache, stats) {
  const empty = { version: 1, entries: {} }
  if (!cache || typeof cache.get !== 'function') return empty
  try {
    const raw = cache.get(EXIT_CACHE_KEY)
    if (!raw || typeof raw !== 'object' || !raw.entries || typeof raw.entries !== 'object') {
      return empty
    }
    return { version: 1, entries: { ...raw.entries } }
  } catch (_) {
    if (stats) stats.cacheReadError++
    return empty
  }
}

function getExitCacheEntry(store, fingerprint, successMinutes, failMinutes, force) {
  if (force || !store?.entries || !fingerprint) return { hit: false }
  const entry = store.entries[fingerprint]
  if (!entry || !entry.ts) return { hit: false }
  const ttlMinutes = entry.ok ? successMinutes : failMinutes
  if (!(ttlMinutes > 0)) return { hit: false }
  const age = Date.now() - Number(entry.ts)
  if (age < 0 || age >= ttlMinutes * 60 * 1000) return { hit: false }
  if (entry.ok) {
    const ip = normalizeIp(entry.ip)
    if (!ip) return { hit: false }
    return { hit: true, ok: true, ip }
  }
  return { hit: true, ok: false, ip: '' }
}

function setExitCacheEntry(store, fingerprint, ok, ip) {
  if (!store?.entries || !fingerprint) return
  store.entries[fingerprint] = {
    ts: Date.now(),
    ok: !!ok,
    ip: ok ? normalizeIp(ip) : '',
  }
}

function persistExitCache(cache, store, ttlMinutes, successMinutes, failMinutes, stats) {
  if (!cache || typeof cache.set !== 'function' || !(ttlMinutes > 0)) return
  try {
    const now = Date.now()
    const latest = (() => {
      try {
        const raw = cache.get(EXIT_CACHE_KEY)
        return raw && typeof raw === 'object' && raw.entries && typeof raw.entries === 'object'
          ? raw.entries
          : {}
      } catch (_) {
        if (stats) stats.cacheReadError++
        return {}
      }
    })()

    const merged = { ...latest }
    for (const [key, value] of Object.entries(store.entries || {})) {
      if (!merged[key] || Number(value?.ts || 0) >= Number(merged[key]?.ts || 0)) {
        merged[key] = value
      }
    }

    for (const [key, value] of Object.entries(merged)) {
      const ttl = value?.ok ? successMinutes : failMinutes
      const age = now - Number(value?.ts || 0)
      if (!(ttl > 0) || !value?.ts || age < 0 || age >= ttl * 60 * 1000) {
        delete merged[key]
      }
    }

    cache.set(
      EXIT_CACHE_KEY,
      { version: 1, entries: merged },
      Math.max(1000, ttlMinutes * 60 * 1000)
    )
  } catch (_) {
    if (stats) stats.cacheWriteError++
  }
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

function readProviderCacheSnapshot(cache, provider, ip, okHours, failHours, force) {
  if (force || !cache || typeof cache.get !== 'function') return { hit: false }
  try {
    const hit = cache.get(`ipqlite:v101:${provider}:${ip}`)
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
    if (key === 'db' && String(ip).includes(':')) continue
    if (!readProviderCacheSnapshot(cache, key, ip, okHours, failHours, force).hit) {
      return true
    }
  }
  return false
}

function recordProviderCacheStats(r, stats) {
  if (!stats || !r) return
  for (const [provider, result] of Object.entries(r)) {
    if (provider.startsWith('_') || !result || typeof result._cached !== 'boolean') continue
    const bucket = stats.byProvider[provider] || { hit: 0, miss: 0 }
    if (result._cached) {
      stats.hit++
      bucket.hit++
    } else {
      stats.miss++
      bucket.miss++
    }
    if (result._cacheReadError) stats.readError++
    if (result._cacheWriteError) stats.writeError++
    stats.byProvider[provider] = bucket
  }
}

function formatProviderCacheDetail(byProvider) {
  const order = ['mm', 'ii', 'sc', 'ir', 'ia', 'ab', 'i2', 'db', 'id', 'iq', 'pc']
  return order
    .filter(key => byProvider?.[key])
    .map(key => `${key.toUpperCase()} H${byProvider[key].hit}/M${byProvider[key].miss}`)
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

async function detectExitIp($, localProxy, timeout) {
  const ipv4Hosts = [
    'ipinfo.io/ip',
    'myip.check.place',
    'ip.sb',
    'ping0.cc',
    'icanhazip.com',
    'api64.ipify.org',
    'ifconfig.co',
    'ident.me',
  ]

  for (const host of ipv4Hosts) {
    try {
      const r = await request($, {
        method: 'get',
        url: `https://${host}`,
        proxy: localProxy,
        headers: { Accept: 'text/plain,*/*', 'User-Agent': 'curl/8.5.0' },
        timeout,
      })
      const ip = extractPlainIp(r.body)
      if (isIPv4(ip)) return ip
    } catch (_) {}
  }

  const ipv6Hosts = [
    'myip.check.place',
    'ip.sb',
    'ping0.cc',
    'icanhazip.com',
    'api64.ipify.org',
    'ifconfig.co',
    'ident.me',
  ]

  for (const host of ipv6Hosts) {
    try {
      const r = await request($, {
        method: 'get',
        url: `https://${host}`,
        proxy: localProxy,
        headers: { Accept: 'text/plain,*/*', 'User-Agent': 'curl/8.5.0' },
        timeout,
      })
      const ip = extractPlainIp(r.body)
      if (ip && ip.includes(':')) return ip
    } catch (_) {}
  }

  throw new Error('no public exit ip')
}

function extractPlainIp(body) {
  const raw = String(body ?? '').trim()
  if (!raw) return null
  const d = json(raw)
  if (d && typeof d === 'object') {
    const v = normalizeIp(d.ip || d.query || d.address)
    if (v) return v
  }
  return normalizeIp(raw.split(/\s+/)[0])
}

function isIPv4(ip) {
  const m = String(ip || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  return !!m && m.slice(1).every(x => Number(x) >= 0 && Number(x) <= 255)
}

function skippedByMaxmind() {
  return { state: 'skip', status: 0, data: null, _route: 'MM' }
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

async function safeProvider(fn) {
  try {
    return await fn()
  } catch (_) {
    return { state: 'err', status: 0, data: null }
  }
}

async function cachedProvider(cache, provider, ip, okHours, failHours, force, fetcher) {
  const key = `ipqlite:v101:${provider}:${ip}`
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
  } catch (_) {
    result = { state: 'err', status: 0, data: null }
  }

  const ok =
    provider === 'mm'
      ? maxmindBaseUsable(result)
      : providerHasUsableEvidence(provider, result)
  if (cache && typeof cache.set === 'function') {
    try {
      cache.set(key, { ts: now, ok, result })
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
  if (!r || r.state !== 'json' || !r.data && key !== 'pc') return false

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
      p?.is_vpn, p?.is_datacenter,
      d?.scamalytics?.is_blacklisted_external,
      x4?.is_tor, x4?.is_blacklisted_spambot,
      x4?.is_bot_operamini, x4?.is_bot_semrush,
    ].some(v => toBool(v) !== null)
  }

  if (key === 'ab') {
    return normalizeScore(r?.data?.data?.abuseConfidenceScore) !== null
  }

  if (key === 'i2') {
    const d = r?.data || {}
    if (normalizeScore(d?.fraud_score) !== null) return true
    const p = d?.proxy || {}
    return [
      d?.is_proxy, p?.is_public_proxy, p?.is_web_proxy,
      p?.is_vpn, p?.is_tor, p?.is_spammer,
      p?.is_web_crawler, p?.is_scanner, p?.is_botnet, p?.is_data_center,
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
    const p = r?.data?.data?.privacy || {}
    return [p?.proxy, p?.vpn, p?.tor, p?.hosting].some(v => toBool(v) !== null)
  }

  if (key === 'ir') {
    const s = r?.data?.security || {}
    return [
      s?.is_proxy, s?.is_vpn, s?.is_tor, s?.is_tor_exit,
      s?.is_abuser, s?.is_cloud_provider,
    ].some(v => toBool(v) !== null)
  }

  if (key === 'ia') {
    const d = r?.data || {}
    const risk = parseIpapiRisk(d)
    if (risk.score !== null || risk.label) return true
    return [
      d?.is_proxy, d?.is_vpn, d?.is_tor, d?.is_abuser,
      d?.is_datacenter, d?.is_crawler,
    ].some(v => toBool(v) !== null)
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

async function queryMaxmindBase($, ip, localProxy, timeout) {
  const r = await attemptJsonish($, {
    method: 'get',
    url: `https://ipinfo.check.place/${encodeURIComponent(ip)}?lang=en`,
    proxy: localProxy,
    headers: { 'User-Agent': 'curl/8.5.0' },
    timeout,
  })
  return withRoute(r, 'P')
}

async function queryProxycheck($, ip, localProxy, key, timeout) {
  const keyPart = key ? `&key=${encodeURIComponent(key)}` : ''
  const pathIp = encodeURIComponent(ip)
  const urls = [
    `https://proxycheck.io/v2/${pathIp}?vpn=1&risk=1${keyPart}`,
    `http://proxycheck.io/v2/${pathIp}?vpn=1&risk=1${keyPart}`,
  ]
  let last = { state: 'err', status: 0, data: null }

  for (const url of urls) {
    const r = await attemptJsonish($, {
      method: 'get',
      url,
      proxy: localProxy,
      headers: { Accept: 'application/json', 'User-Agent': 'curl/8.5.0' },
      timeout,
    })
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
    if (risk === null) continue

    const flags = []
    const isProxy =
      String(info.proxy || '').toLowerCase() === 'yes' || info.proxy === true
    const type = String(info.type || '').trim().toLowerCase()
    if (isProxy) {
      if (type.includes('vpn')) flags.push('V')
      else if (type.includes('tor')) flags.push('T')
      else flags.push('P')
    }

    return withRoute({ ...r, risk, flags, data: info }, 'P')
  }

  return withRoute(last, 'P')
}

async function queryIpinfo($, ip, localProxy, timeout) {
  const r = await attemptJsonish($, {
    method: 'get',
    url: `https://ipinfo.io/widget/demo/${encodeURIComponent(ip)}`,
    proxy: localProxy,
    headers: { 'User-Agent': 'curl/8.5.0' },
    timeout,
  })
  return withRoute(r, 'P')
}

async function queryCheckPlaceDb($, ip, db, localProxy, timeout) {
  const r = await attemptJsonish($, {
    method: 'get',
    url: `https://ipinfo.check.place/${encodeURIComponent(ip)}?db=${encodeURIComponent(db)}`,
    proxy: localProxy,
    headers: { 'User-Agent': 'curl/8.5.0' },
    timeout,
  })
  return withRoute(r, 'P')
}

async function queryIpregistry($, ip, localProxy, timeout) {
  const browserUa = randomBrowserUa()
  let key = 'sb69ksjcajfs4c'

  const page = await attemptText($, {
    method: 'get',
    url: 'https://ipregistry.co',
    proxy: localProxy,
    headers: { 'User-Agent': browserUa },
    timeout,
  })
  const html = String(page.body || '')
  const m = html.match(/apiKey=["']([a-zA-Z0-9]+)["']/i)
  if (m?.[1]) key = m[1]

  const r = await attemptJsonish($, {
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
  })
  return withRoute(r, 'P')
}

async function queryIpapiIs($, ip, localProxy, timeout) {
  const r = await attemptJsonish($, {
    method: 'get',
    url: `https://api.ipapi.is/?q=${encodeURIComponent(ip)}`,
    proxy: localProxy,
    headers: {
      Origin: 'https://ipapi.is',
      'User-Agent': 'curl/8.5.0',
    },
    timeout,
  })
  return withRoute(r, 'P')
}

async function queryDbIp($, ip, localProxy, timeout) {
  if (String(ip).includes(':')) {
    return { state: 'skip', status: 0, data: null, _route: 'IPv6' }
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
  const key = keyMatch?.[1]
  if (!key) {
    return withRoute({
      state: html.trim() ? 'html' : 'err',
      status: first.status || 0,
      data: null,
    }, 'P')
  }

  const r = await attemptJsonish($, {
    method: 'post',
    url: `https://api.db-ip.com/v2/${encodeURIComponent(key)}/self?convertCurrencies`,
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

async function attemptJsonish($, opt) {
  try {
    const r = await request($, opt)
    const status = httpStatus(r)
    const d = json(r.body)
    if (d && typeof d === 'object') return { state: 'json', status, data: d }
    const body = String(r.body || '').trim()
    if (body) return { state: 'html', status, data: null }
    return { state: 'err', status, data: null }
  } catch (_) {
    return { state: 'err', status: 0, data: null }
  }
}

async function attemptText($, opt) {
  try {
    const r = await request($, opt)
    return { state: 'text', status: httpStatus(r), body: String(r.body || '') }
  } catch (_) {
    return { state: 'err', status: 0, body: '' }
  }
}

function withRoute(result, route) {
  return { ...(result || { state: 'err', status: 0, data: null }), _route: route }
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
  return /^(?:EIP-|Trust$|Normal$|Risk$|Unrated$|ConsumerIP$|BusinessIP$|HostingIP$|NetUnrated$|ConsIP$|BusiIP$|HostIP$|UnkIP$|Net-C\d+-L\d+-I\d+-B\d+-H\d+-X\d+$|NetSrc(?:0|-.*)$|NetWhy(?:0|-.*)$|Q\d+\/7$|Clean\d+\/7$|Caution\d+$|RiskSrc\d+$|Score\d+\/7$|Core\d+\/(?:4|5)$|Valid\d+(?:\/10)?$|Full$|Lite$|MM-(?:Full|Lite|OK.*|H\d+.*|E.*|Skip.*)$|Hard(?:0|-.+)$|Strong(?:0|-.+)$|RiskReason(?:0|-.+)$|CautionReason(?:0|-.+)$|VPN\d+\/\d+$|Proxy\d+\/\d+$|PC-|II-|SC-|IR-|IA-|AB-|I2-|DB-|ID-|IQ-|TrustedIP$|RiskIP$|AbuseIP$|VPNIP$|ProxyIP$|TorIP$|DCIP$|ISPNet$|IPQS-R\d+$|VPN$|Proxy$|Tor$|Abuse$|CPBase|CPCurl|PCScoreErr$|IPProbe(?:MetaErr|ExitErr|Unsup)$|IPScoreErr$|IPQ(?:MetaErr|ApiErr|Unsup)$)/.test(String(t || ''))
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
