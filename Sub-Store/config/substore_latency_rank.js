/**
 * Sub-Store Latency Rank v2.0.0-rc1
 * HTTP META 稳健延迟排序 + 节点级增量缓存
 *
 * 设计目标：
 * 1. 请求真实经过每个代理节点进行 HTTP 延迟测试。
 * 2. 不删除节点、不修改节点名称、不新增/删除/修改任何节点字段，只改变返回顺序。
 * 3. 缓存“原始测速证据（samples）”而不是最终排序结果：排序/可靠性逻辑变化可立即重算。
 * 4. 节点配置、测速协议参数变化自动 Cache MISS；节点仅改名不触发无意义重测。
 * 5. 只把 Cache MISS 的唯一节点配置交给 HTTP META，适合大订阅和 Git 上传失败后的快速重试。
 * 6. 完整成功（例如 3/3）使用较长缓存；有任意正式采样失败则只使用短缓存，尽快复测。
 * 7. HTTP META 全局启动/运行失败时，保持原数组、原顺序返回，避免“半套排序”。
 *
 * 推荐默认参数（约 200 节点）：
 *   samples=3
 *   warmup=1
 *   min_success=2
 *   timeout=5000
 *   sample_delay=150
 *   concurrency=6
 *   retries=0
 *   cache=1
 *   cache_success_minutes=15
 *   cache_partial_minutes=2
 *   reliability_first=1
 *
 * 参数：
 *   url                        测试地址，默认 http://connectivitycheck.platform.hicloud.com/generate_204
 *   status                     合法 HTTP 状态码正则，默认 ^204$
 *   method                     head / get，默认 head
 *   ua                         User-Agent
 *   timeout                    单次请求超时（毫秒），默认 5000
 *   samples                    正式采样次数，默认 3
 *   warmup                     预热次数，默认 1
 *   min_success                至少成功几次才进入正常排序，默认 2
 *   sample_delay               同一节点相邻请求间隔（毫秒），默认 150
 *   concurrency                同时测试的唯一节点配置数，默认 6
 *   retries                    每次请求失败后的额外重试次数，默认 0
 *   retry_delay                重试间隔（毫秒），默认 250
 *   reliability_first          1=优先成功样本更多的节点；0=所有可靠节点只按延迟，默认 1
 *   cache                      是否启用节点级缓存，默认 1
 *   cache_success_minutes      所有正式采样均成功时缓存多久，默认 15
 *   cache_partial_minutes      正式采样存在失败时缓存多久，默认 2
 *   force_refresh              1=本轮忽略缓存并重测，默认 0
 *   cache_tag                  手工缓存代号；修改后可立即切换到新缓存空间，默认空
 *   log_details                1=输出逐节点/逐唯一配置详情，默认 0
 *   include_unsupported_proxy  是否让 ClashMeta 转换包含额外协议，默认 false
 *   http_meta_protocol         默认 http
 *   http_meta_host             默认 127.0.0.1
 *   http_meta_port             默认 9876
 *   http_meta_authorization    HTTP META Authorization，默认空
 *   http_meta_start_delay      HTTP META 启动后等待时间（毫秒），默认 3000
 *   http_meta_lifetime         HTTP META 最长存活时间（毫秒）；默认自动估算
 *
 * 缓存失效规则：
 * - 节点真实配置变化 -> fingerprint 变化 -> 自动 MISS
 * - 仅节点名称/IPQuality 标签变化 -> fingerprint 不变 -> 可继续 HIT
 * - url/method/status/ua/timeout/samples/warmup/sample_delay/retries/retry_delay 改变 -> 自动 MISS
 * - 修改 reliability_first/min_success 只改变“如何解释证据”，无需重测
 * - 若未来修改了“采样过程本身”的代码，请提升 MEASURE_PROTOCOL_VERSION
 */

const LATENCY_RANK_VERSION = '2.0.0-rc1'
const MEASURE_PROTOCOL_VERSION = '1'
const CACHE_NAMESPACE = 'latrank'

async function operator(proxies = [], targetPlatform, env = {}) {
  const $ = $substore
  const args = typeof $arguments === 'object' && $arguments ? $arguments : {}
  const startedAt = Date.now()

  if (!Array.isArray(proxies) || proxies.length === 0) return proxies

  const arg = (name, fallback) =>
    args[name] !== undefined && args[name] !== '' ? args[name] : fallback

  const toInt = (value, fallback, min = 0, max = Number.MAX_SAFE_INTEGER) => {
    const n = Number.parseInt(value, 10)
    const safe = Number.isFinite(n) ? n : fallback
    return Math.max(min, Math.min(max, safe))
  }

  const toNumber = (value, fallback, min = 0, max = Number.MAX_SAFE_INTEGER) => {
    const n = Number(value)
    const safe = Number.isFinite(n) ? n : fallback
    return Math.max(min, Math.min(max, safe))
  }

  const toBool = (value, fallback = false) => {
    if (value === undefined || value === null || value === '') return fallback
    if (typeof value === 'boolean') return value
    return /^(1|true|yes|on)$/i.test(String(value).trim())
  }

  const safeDecode = value => {
    try {
      return decodeURIComponent(String(value))
    } catch (_) {
      return String(value)
    }
  }

  const url = safeDecode(
    arg('url', 'http://connectivitycheck.platform.hicloud.com/generate_204')
  )
  const method = String(arg('method', 'head')).trim().toLowerCase()
  if (!['head', 'get'].includes(method)) {
    throw new Error(`[LatencyRank] method 仅支持 head/get，当前=${method}`)
  }

  const statusPattern = String(arg('status', '^204$'))
  let validStatus
  try {
    validStatus = new RegExp(statusPattern)
  } catch (error) {
    throw new Error(`[LatencyRank] status 正则无效: ${error?.message || error}`)
  }

  const ua = safeDecode(
    arg(
      'ua',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1'
    )
  )

  const timeout = toInt(arg('timeout', 5000), 5000, 100, 60000)
  const samples = toInt(arg('samples', 3), 3, 1, 20)
  const warmup = toInt(arg('warmup', 1), 1, 0, 10)
  const minSuccess = Math.min(
    samples,
    toInt(arg('min_success', Math.min(2, samples)), Math.min(2, samples), 1, samples)
  )
  const sampleDelay = toInt(arg('sample_delay', 150), 150, 0, 10000)
  const concurrency = toInt(arg('concurrency', 6), 6, 1, 32)
  const retries = toInt(arg('retries', 0), 0, 0, 5)
  const retryDelay = toInt(arg('retry_delay', 250), 250, 0, 10000)
  const reliabilityFirst = toBool(arg('reliability_first', true), true)

  const cacheEnabledArg = toBool(arg('cache', true), true)
  const forceRefresh = toBool(arg('force_refresh', false), false)
  const cacheSuccessMinutes = toNumber(arg('cache_success_minutes', 15), 15, 0, 1440)
  const cachePartialMinutes = toNumber(arg('cache_partial_minutes', 2), 2, 0, 1440)
  const cacheTag = String(arg('cache_tag', '')).trim()
  const logDetails = toBool(arg('log_details', false), false)

  const includeUnsupportedProxy = toBool(arg('include_unsupported_proxy', false), false)

  const httpMetaProtocol = String(arg('http_meta_protocol', 'http')).trim()
  const httpMetaHost = String(arg('http_meta_host', '127.0.0.1')).trim()
  const httpMetaPort = toInt(arg('http_meta_port', 9876), 9876, 1, 65535)
  const httpMetaAuthorization = String(arg('http_meta_authorization', ''))
  const httpMetaStartDelay = toInt(arg('http_meta_start_delay', 3000), 3000, 0, 30000)
  const httpMetaApi = `${httpMetaProtocol}://${httpMetaHost}:${httpMetaPort}`

  const cache =
    typeof scriptResourceCache !== 'undefined' && scriptResourceCache
      ? scriptResourceCache
      : null
  const cacheAvailable = !!(
    cache &&
    typeof cache.get === 'function' &&
    typeof cache.set === 'function'
  )
  const cacheEnabled = cacheEnabledArg && cacheAvailable

  // 只包含“会改变采样证据”的参数。
  // min_success / reliability_first 只是解释证据，不应导致重测。
  const measureSignature = hashString(
    stableSerialize({
      protocol: MEASURE_PROTOCOL_VERSION,
      cacheTag,
      url,
      method,
      statusPattern,
      ua,
      timeout,
      samples,
      warmup,
      sampleDelay,
      retries,
      retryDelay,
    })
  )

  const stats = {
    total: proxies.length,
    testable: 0,
    unsupported: 0,
    unique: 0,
    duplicateNodes: 0,
    cacheHitGroups: 0,
    cacheMissGroups: 0,
    cacheReadErrors: 0,
    cacheWriteErrors: 0,
    freshGroups: 0,
    freshCompleteGroups: 0,
    freshPartialGroups: 0,
    dependencyBlockedGroups: 0,
    dependencyPayloadGroups: 0,
  }

  const records = proxies.map((proxy, index) => ({
    proxy,
    index,
    testable: false,
    fingerprint: '',
    reliable: false,
    complete: false,
    latency: Infinity,
    samples: [],
    successCount: 0,
    mad: Infinity,
    spread: Infinity,
    reason: '',
    source: 'none',
    measuredAt: 0,
  }))

  const groups = new Map()

  // 转换测试副本 + 生成不受名称影响的节点指纹。
  for (const record of records) {
    try {
      const testCopy = deepClone(record.proxy)
      const produced = ProxyUtils.produce([testCopy], 'ClashMeta', 'internal', {
        'include-unsupported-proxy': includeUnsupportedProxy,
      })?.[0]

      if (!produced) {
        record.reason = 'HTTP META / ClashMeta 不兼容'
        stats.unsupported++
        continue
      }

      const fingerprint = nodeFingerprint(produced)
      if (!fingerprint) {
        record.reason = '无法生成节点指纹'
        stats.unsupported++
        continue
      }

      record.testable = true
      record.fingerprint = fingerprint
      stats.testable++

      let group = groups.get(fingerprint)
      if (!group) {
        group = {
          fingerprint,
          internalProxy: produced,
          records: [],
          evidence: null,
          cacheHit: false,
          order: groups.size,
        }
        groups.set(fingerprint, group)
      }
      group.records.push(record)
    } catch (error) {
      record.reason = `转换失败: ${error?.message || error}`
      stats.unsupported++
    }
  }

  stats.unique = groups.size
  stats.duplicateNodes = Math.max(0, stats.testable - stats.unique)

  // 当前名称 -> 唯一节点配置。若同名但配置不同，则引用关系本身具有歧义。
  const nameIndex = buildNameIndex(groups)

  $.info(
    `[LatencyRank] START version=${LATENCY_RANK_VERSION} protocol=${MEASURE_PROTOCOL_VERSION} ` +
      `nodes=${stats.total} testable=${stats.testable} unique=${stats.unique} ` +
      `duplicate-saved=${stats.duplicateNodes} samples=${samples} warmup=${warmup} ` +
      `min-success=${minSuccess} concurrency=${concurrency} ` +
      `cache=${cacheEnabled ? 'on' : cacheEnabledArg ? 'unavailable' : 'off'} ` +
      `force=${forceRefresh ? 'on' : 'off'} signature=${measureSignature}`
  )

  if (!stats.testable) {
    $.info('[LatencyRank] 没有可测速节点，保持原顺序返回')
    return proxies
  }

  // 先读取每个唯一节点配置的证据缓存。
  const misses = []
  for (const group of groups.values()) {
    let evidence = null
    if (cacheEnabled && !forceRefresh) {
      const result = readEvidenceCache(cache, cacheKey(group.fingerprint), {
        samples,
        stats,
      })
      if (result.hit) {
        evidence = result.evidence
        group.cacheHit = true
        stats.cacheHitGroups++
      }
    }

    if (evidence) {
      group.evidence = evidence
      applyEvidenceToGroup(group, evidence, 'cache')
    } else {
      stats.cacheMissGroups++
      misses.push(group)
    }
  }

  $.info(
    `[LatencyRank] CACHE groups hit=${stats.cacheHitGroups} miss=${stats.cacheMissGroups} ` +
      `read-error=${stats.cacheReadErrors}`
  )

  let fatalError = null

  // HTTP META 会把传入节点统一重命名为 proxy-0 / proxy-1 / ...。
  // 对 dialer-proxy / underlying-proxy 等引用节点，必须把依赖一并加入 payload，
  // 并在送入 HTTP META 前把引用改写成对应的 proxy-N，否则链式节点会产生假失败。
  const dependencyPlan = buildDependencyPlan(misses, groups, nameIndex)
  stats.dependencyBlockedGroups = dependencyPlan.blocked.length
  stats.dependencyPayloadGroups = dependencyPlan.payloadGroups.length

  for (const blocked of dependencyPlan.blocked) {
    const evidence = {
      version: 1,
      measuredAt: Date.now(),
      expectedSamples: samples,
      samples: [],
      reason: blocked.reason,
    }
    blocked.group.evidence = evidence
    applyEvidenceToGroup(blocked.group, evidence, 'dependency-blocked')
    if (logDetails) {
      $.info(
        `[LatencyRank] dependency blocked node=${blocked.group.records[0]?.proxy?.name || blocked.group.fingerprint} ` +
          `reason=${blocked.reason}`
      )
    }
  }

  if (dependencyPlan.blocked.length) {
    $.info(
      `[LatencyRank] DEPENDENCY blocked=${dependencyPlan.blocked.length} ` +
        `targets=${dependencyPlan.targets.length} payload=${dependencyPlan.payloadGroups.length}`
    )
  } else if (dependencyPlan.targets.length) {
    $.info(
      `[LatencyRank] DEPENDENCY targets=${dependencyPlan.targets.length} ` +
        `payload=${dependencyPlan.payloadGroups.length}`
    )
  }

  if (dependencyPlan.targets.length) {
    const oneProbeWorst = (retries + 1) * timeout + retries * retryDelay
    const oneNodeWorst =
      (warmup + samples) * oneProbeWorst +
      Math.max(0, warmup + samples - 1) * sampleDelay
    const batches = Math.ceil(dependencyPlan.targets.length / concurrency)
    const autoLifetime = httpMetaStartDelay + batches * oneNodeWorst + 15000
    const httpMetaLifetime = toInt(
      arg('http_meta_lifetime', autoLifetime),
      autoLifetime,
      10000,
      24 * 3600 * 1000
    )

    let pid = null
    let ports = []

    try {
      const startResponse = await rawRequest({
        method: 'post',
        url: `${httpMetaApi}/start`,
        timeout: 30000,
        headers: buildMetaHeaders(),
        body: JSON.stringify({
          proxies: dependencyPlan.payloadProxies,
          timeout: httpMetaLifetime,
        }),
      })

      let body = startResponse?.body
      if (typeof body === 'string') {
        try {
          body = JSON.parse(body)
        } catch (_) {}
      }

      pid = body?.pid
      ports = body?.ports

      if (
        !pid ||
        !Array.isArray(ports) ||
        ports.length !== dependencyPlan.payloadGroups.length ||
        ports.some(port => !Number.isFinite(Number(port)) || Number(port) <= 0)
      ) {
        throw new Error(
          `HTTP META 启动返回无效: ${typeof body === 'string' ? body : JSON.stringify(body)}`
        )
      }

      ports = ports.map(Number)

      $.info(
        `[LatencyRank] HTTP META start pid=${pid} targets=${dependencyPlan.targets.length} payload=${dependencyPlan.payloadGroups.length} ` +
          `lifetime=${Math.round(httpMetaLifetime / 1000)}s`
      )

      if (httpMetaStartDelay > 0) await $.wait(httpMetaStartDelay)

      let done = 0
      const progress = createProgressReporter(dependencyPlan.targets.length, current => {
        $.info(`[LatencyRank] PROGRESS ${current}/${dependencyPlan.targets.length} target routes`)
      })

      const tasks = dependencyPlan.targets.map(group => async () => {
        let evidence
        try {
          evidence = await measureOneGroup(group, ports[dependencyPlan.indexByGroup.get(group)])
        } catch (error) {
          evidence = {
            version: 1,
            measuredAt: Date.now(),
            expectedSamples: samples,
            samples: [],
            reason: `测速异常: ${error?.message || error}`,
          }
        }

        group.evidence = evidence
        applyEvidenceToGroup(group, evidence, 'fresh')
        stats.freshGroups++

        const complete = isCompleteEvidence(evidence, samples)
        if (complete) stats.freshCompleteGroups++
        else stats.freshPartialGroups++

        if (cacheEnabled) {
          const ttlMinutes = complete ? cacheSuccessMinutes : cachePartialMinutes
          if (ttlMinutes > 0) {
            writeEvidenceCache(
              cache,
              cacheKey(group.fingerprint),
              evidence,
              ttlMinutes * 60 * 1000,
              stats
            )
          }
        }

        done++
        progress(done)
      })

      await runLimited(tasks, concurrency)
    } catch (error) {
      fatalError = error
      $.error(`[LatencyRank] FATAL ${error?.message || error}`)
    } finally {
      if (pid) {
        try {
          await rawRequest({
            method: 'post',
            url: `${httpMetaApi}/stop`,
            timeout: 10000,
            headers: buildMetaHeaders(),
            body: JSON.stringify({ pid: [pid] }),
          })
          $.info(`[LatencyRank] HTTP META stop pid=${pid}`)
        } catch (error) {
          $.error(`[LatencyRank] HTTP META 关闭失败: ${error?.message || error}`)
        }
      }
    }
  }

  // 全局 HTTP META 失败时不输出“缓存命中 + 未测试新节点”的半套排序。
  if (fatalError) {
    $.info('[LatencyRank] 因 HTTP META 全局失败，保持原顺序返回；节点内容未修改')
    return proxies
  }

  const sortedRecords = [...records].sort(compareRecords)
  const reliableRecords = sortedRecords.filter(record => record.reliable)
  const completeRecords = reliableRecords.filter(record => record.complete)
  const partialRecords = reliableRecords.filter(record => !record.complete)
  const bottomRecords = sortedRecords.filter(record => !record.reliable)

  const reliableLatencies = reliableRecords
    .map(record => record.latency)
    .filter(Number.isFinite)
  const minLatency = reliableLatencies.length ? Math.min(...reliableLatencies) : null
  const maxLatency = reliableLatencies.length ? Math.max(...reliableLatencies) : null

  $.info(
    `[LatencyRank] RESULT reliable=${reliableRecords.length} complete=${completeRecords.length} ` +
      `partial=${partialRecords.length} bottom=${bottomRecords.length} ` +
      `fresh-groups=${stats.freshGroups} complete-fresh=${stats.freshCompleteGroups} ` +
      `partial-fresh=${stats.freshPartialGroups} dependency-blocked=${stats.dependencyBlockedGroups} ` +
      `cache-write-error=${stats.cacheWriteErrors}` +
      (minLatency !== null ? ` latency-range=${minLatency}-${maxLatency}ms` : '')
  )

  $.info(
    `[LatencyRank] DONE duration=${formatDuration(Date.now() - startedAt)} ` +
      `output=${sortedRecords.length}`
  )

  // 关键保证：返回最初传入的原始节点对象，只改变数组顺序。
  return sortedRecords.map(record => record.proxy)

  function cacheKey(fingerprint) {
    return `${CACHE_NAMESPACE}:v1:${measureSignature}:${fingerprint}`
  }

  async function measureOneGroup(group, port) {
    const label = group.records[0]?.proxy?.name || group.fingerprint

    for (let i = 0; i < warmup; i++) {
      try {
        await probe(port)
      } catch (_) {}
      if (sampleDelay > 0 && (i < warmup - 1 || samples > 0)) {
        await $.wait(sampleDelay)
      }
    }

    const latencies = []
    let lastError = ''

    for (let i = 0; i < samples; i++) {
      try {
        latencies.push(await probe(port))
      } catch (error) {
        lastError = String(error?.message || error)
        if (logDetails) {
          $.info(
            `[LatencyRank] ${label} sample ${i + 1}/${samples} failed: ${lastError}`
          )
        }
      }

      if (sampleDelay > 0 && i < samples - 1) await $.wait(sampleDelay)
    }

    const evidence = {
      version: 1,
      measuredAt: Date.now(),
      expectedSamples: samples,
      samples: latencies,
      reason: latencies.length < samples ? lastError || '部分采样失败' : '',
    }

    if (logDetails) {
      const summary = summarizeEvidence(evidence)
      $.info(
        `[LatencyRank] ${label} fresh success=${summary.successCount}/${samples} ` +
          `median=${Number.isFinite(summary.latency) ? `${summary.latency}ms` : '-'} ` +
          `mad=${Number.isFinite(summary.mad) ? summary.mad : '-'} ` +
          `samples=${latencies.join('/') || '-'}`
      )
    }

    return evidence
  }

  async function probe(port) {
    let lastError = null

    for (let attempt = 0; attempt <= retries; attempt++) {
      const probeStartedAt = Date.now()
      try {
        const response = await rawRequest({
          proxy: `http://${httpMetaHost}:${port}`,
          method,
          url,
          timeout,
          headers: { 'User-Agent': ua },
        })

        const status = Number(response?.status ?? response?.statusCode ?? 0)
        validStatus.lastIndex = 0
        if (!validStatus.test(String(status))) {
          throw new Error(`HTTP ${status || 'unknown'}`)
        }

        return Date.now() - probeStartedAt
      } catch (error) {
        lastError = error
        if (attempt < retries && retryDelay > 0) await $.wait(retryDelay)
      }
    }

    throw lastError || new Error('request failed')
  }

  function applyEvidenceToGroup(group, evidence, source) {
    for (const record of group.records) {
      applyEvidenceToRecord(record, evidence, source)
    }
  }

  function applyEvidenceToRecord(record, evidence, source) {
    const summary = summarizeEvidence(evidence)
    record.samples = summary.samples
    record.successCount = summary.successCount
    record.reliable = summary.successCount >= minSuccess
    record.complete = summary.successCount === samples
    record.latency = record.reliable ? summary.latency : Infinity
    record.mad = record.reliable ? summary.mad : Infinity
    record.spread = record.reliable ? summary.spread : Infinity
    record.reason = record.reliable
      ? ''
      : evidence?.reason || `成功次数不足 ${summary.successCount}/${samples}`
    record.source = source
    record.measuredAt = Number(evidence?.measuredAt || 0)

    if (logDetails && source === 'cache') {
      const age = record.measuredAt > 0 ? Date.now() - record.measuredAt : 0
      $.info(
        `[LatencyRank] ${record.proxy?.name || `#${record.index}`} cache ` +
          `success=${record.successCount}/${samples} ` +
          `median=${Number.isFinite(record.latency) ? `${record.latency}ms` : '-'} ` +
          `age=${formatDuration(age)}`
      )
    }
  }

  function compareRecords(a, b) {
    if (a.reliable !== b.reliable) return a.reliable ? -1 : 1

    // 不可靠/不兼容节点统一置底，并保持其原顺序。
    if (!a.reliable && !b.reliable) return a.index - b.index

    // 默认优先成功样本更多的节点：3/3 在 2/3 前面。
    if (reliabilityFirst && a.successCount !== b.successCount) {
      return b.successCount - a.successCount
    }

    if (a.latency !== b.latency) return a.latency - b.latency
    if (a.mad !== b.mad) return a.mad - b.mad
    if (a.spread !== b.spread) return a.spread - b.spread
    return a.index - b.index
  }

  function buildMetaHeaders() {
    const headers = { 'Content-Type': 'application/json' }
    if (httpMetaAuthorization) headers.Authorization = httpMetaAuthorization
    return headers
  }

  async function rawRequest(options) {
    const requestMethod = String(options.method || 'get').toLowerCase()
    if (!$.http?.[requestMethod]) {
      throw new Error(`当前 Sub-Store 不支持 HTTP method: ${requestMethod}`)
    }
    return $.http[requestMethod](options)
  }
}

function buildNameIndex(groups) {
  const index = new Map()
  for (const group of groups.values()) {
    for (const record of group.records || []) {
      const name = String(record?.proxy?.name || '').trim()
      if (!name) continue
      if (!index.has(name)) index.set(name, group)
      else if (index.get(name) !== group) index.set(name, null)
    }
  }
  return index
}

function extractProxyReferences(proxy) {
  const refs = []
  const stringFields = ['underlying-proxy', 'dialer-proxy', 'detour', 'prev_hop']
  for (const field of stringFields) {
    if (typeof proxy?.[field] === 'string' && proxy[field].trim()) {
      refs.push({ field, name: proxy[field].trim() })
    }
  }
  if (typeof proxy?.chain === 'string' && proxy.chain.trim()) {
    refs.push({ field: 'chain', name: proxy.chain.trim() })
  } else if (Array.isArray(proxy?.chain)) {
    for (const name of proxy.chain) {
      if (typeof name === 'string' && name.trim()) refs.push({ field: 'chain', name: name.trim() })
    }
  }
  return refs
}

function buildDependencyPlan(misses, groups, nameIndex) {
  const memo = new Map()
  const visiting = new Set()

  function validate(group) {
    if (memo.has(group)) return memo.get(group)
    if (visiting.has(group)) return { ok: true }
    visiting.add(group)

    for (const ref of extractProxyReferences(group.internalProxy)) {
      if (!nameIndex.has(ref.name)) {
        const result = { ok: false, reason: `依赖不存在 ${ref.field}=${ref.name}` }
        visiting.delete(group)
        memo.set(group, result)
        return result
      }
      const dep = nameIndex.get(ref.name)
      if (!dep) {
        const result = { ok: false, reason: `依赖名称歧义 ${ref.field}=${ref.name}` }
        visiting.delete(group)
        memo.set(group, result)
        return result
      }
      const child = validate(dep)
      if (!child.ok) {
        const result = { ok: false, reason: child.reason }
        visiting.delete(group)
        memo.set(group, result)
        return result
      }
    }

    visiting.delete(group)
    const result = { ok: true }
    memo.set(group, result)
    return result
  }

  const blocked = []
  const targets = []
  for (const group of misses) {
    const result = validate(group)
    if (result.ok) targets.push(group)
    else blocked.push({ group, reason: result.reason })
  }

  const required = new Set()
  function collect(group) {
    if (required.has(group)) return
    required.add(group)
    for (const ref of extractProxyReferences(group.internalProxy)) {
      const dep = nameIndex.get(ref.name)
      if (dep) collect(dep)
    }
  }
  targets.forEach(collect)

  const payloadGroups = [...groups.values()]
    .filter(group => required.has(group))
    .sort((a, b) => a.order - b.order)
  const indexByGroup = new Map(payloadGroups.map((group, index) => [group, index]))

  const payloadProxies = payloadGroups.map(group => {
    const proxy = deepClone(group.internalProxy)
    rewriteProxyReferences(proxy, nameIndex, indexByGroup)
    return proxy
  })

  return { blocked, targets, payloadGroups, payloadProxies, indexByGroup }
}

function rewriteProxyReferences(proxy, nameIndex, indexByGroup) {
  const stringFields = ['underlying-proxy', 'dialer-proxy', 'detour', 'prev_hop']
  for (const field of stringFields) {
    if (typeof proxy?.[field] !== 'string') continue
    const dep = nameIndex.get(proxy[field].trim())
    const index = dep ? indexByGroup.get(dep) : undefined
    if (Number.isInteger(index)) proxy[field] = `proxy-${index}`
  }

  if (typeof proxy?.chain === 'string') {
    const dep = nameIndex.get(proxy.chain.trim())
    const index = dep ? indexByGroup.get(dep) : undefined
    if (Number.isInteger(index)) proxy.chain = `proxy-${index}`
  } else if (Array.isArray(proxy?.chain)) {
    proxy.chain = proxy.chain.map(name => {
      if (typeof name !== 'string') return name
      const dep = nameIndex.get(name.trim())
      const index = dep ? indexByGroup.get(dep) : undefined
      return Number.isInteger(index) ? `proxy-${index}` : name
    })
  }
}

function readEvidenceCache(cache, key, ctx) {
  const { samples, stats } = ctx
  try {
    const value = cache.get(key)
    if (!isValidEvidence(value, samples)) return { hit: false }
    return { hit: true, evidence: value }
  } catch (_) {
    if (stats) stats.cacheReadErrors++
    return { hit: false }
  }
}

function writeEvidenceCache(cache, key, evidence, ttlMs, stats) {
  try {
    cache.set(key, evidence, ttlMs)
  } catch (_) {
    if (stats) stats.cacheWriteErrors++
  }
}

function isValidEvidence(value, expectedSamples) {
  if (!value || typeof value !== 'object') return false
  if (Number(value.version) !== 1) return false
  if (!Number.isFinite(Number(value.measuredAt)) || Number(value.measuredAt) <= 0) return false
  if (Number(value.expectedSamples) !== expectedSamples) return false
  if (!Array.isArray(value.samples)) return false
  if (value.samples.length > expectedSamples) return false
  return value.samples.every(v => Number.isFinite(Number(v)) && Number(v) >= 0)
}

function isCompleteEvidence(evidence, expectedSamples) {
  return Array.isArray(evidence?.samples) && evidence.samples.length === expectedSamples
}

function summarizeEvidence(evidence) {
  const values = (Array.isArray(evidence?.samples) ? evidence.samples : [])
    .map(Number)
    .filter(value => Number.isFinite(value) && value >= 0)

  return {
    samples: values,
    successCount: values.length,
    latency: values.length ? median(values) : Infinity,
    mad: values.length ? medianAbsoluteDeviation(values) : Infinity,
    spread: values.length > 1 ? Math.max(...values) - Math.min(...values) : 0,
  }
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b)
  if (!sorted.length) return Infinity
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2
    ? sorted[mid]
    : Math.round((sorted[mid - 1] + sorted[mid]) / 2)
}

function medianAbsoluteDeviation(values) {
  if (!values.length) return Infinity
  const m = median(values)
  return median(values.map(value => Math.abs(value - m)))
}

function nodeFingerprint(node) {
  const clean = {}
  const ignored = /^(name|collectionName|subName|id)$/i
  for (const key of Object.keys(node || {}).sort()) {
    if (/^_/i.test(key) || ignored.test(key)) continue
    clean[key] = node[key]
  }
  return hashString(stableSerialize(clean))
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value))
}

function stableSerialize(value) {
  if (value === null || value === undefined) return String(value)
  if (typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(',')}]`
  return `{${Object.keys(value)
    .sort()
    .map(key => `${JSON.stringify(key)}:${stableSerialize(value[key])}`)
    .join(',')}}`
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
  return `${(h1 >>> 0).toString(16).padStart(8, '0')}${(h2 >>> 0)
    .toString(16)
    .padStart(8, '0')}`
}

function createProgressReporter(total, callback) {
  if (!total || typeof callback !== 'function') return () => {}
  const marks = new Set([
    Math.max(1, Math.ceil(total * 0.25)),
    Math.max(1, Math.ceil(total * 0.5)),
    Math.max(1, Math.ceil(total * 0.75)),
    total,
  ])
  return done => {
    if (!marks.has(done)) return
    marks.delete(done)
    callback(done)
  }
}

async function runLimited(tasks, limit) {
  let cursor = 0

  async function worker() {
    while (true) {
      const taskIndex = cursor++
      if (taskIndex >= tasks.length) return
      await tasks[taskIndex]()
    }
  }

  const workerCount = Math.min(Math.max(1, limit), tasks.length)
  await Promise.all(Array.from({ length: workerCount }, () => worker()))
}

function formatDuration(ms) {
  const value = Math.max(0, Number(ms) || 0)
  if (value < 1000) return `${Math.round(value)}ms`
  if (value < 60000) return `${(value / 1000).toFixed(1)}s`
  return `${(value / 60000).toFixed(1)}m`
}
