// Offline GeoIP regression: node --test Sub-Store/tests/ipquality_geo.test.cjs
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')

const source = fs.readFileSync(path.join(__dirname, '../config/ipquality.js'), 'utf8')

function fixture(codes) {
  const [ii, ir, ia, i2, id, db, mm] = codes
  return {
    ii: ii && { state: 'json', data: { data: { country_code: ii } } },
    ir: ir && { state: 'json', data: { location: { country: { code: ir } } } },
    ia: ia && { state: 'json', data: { location: { country_code: ia } } },
    i2: i2 && { state: 'json', data: { country_code: i2 } },
    id: id && { state: 'json', data: { country_code: id } },
    db: db && { state: 'json', data: { countryCode: db } },
    mm: mm && { state: 'json', data: { country: { iso_code: mm } } },
  }
}

function setup(args = {}, results = fixture(['US', 'US', 'US', 'JP'])) {
  const logs = []
  const ctx = vm.createContext({
    console,
    ProxyUtils: { produce: nodes => nodes },
    $arguments: { 地址族: 'IPv4', http_meta_start_delay: 0, ...args },
    $substore: {
      info: line => logs.push(line), warn: line => logs.push(line),
      error: line => logs.push(line), wait: async () => {},
    },
  })
  vm.runInContext(source, ctx, { filename: 'ipquality.js' })
  ctx.startHttpMetaSession = async (_a, _b, _c, nodes) => ({ pid: 1, ports: nodes.map((_, i) => 10000 + i) })
  ctx.stopHttpMetaSession = async () => {}
  ctx.probeExitFamily = async (_a, _b, family) => family === 4
    ? { ok: true, ip: '203.0.113.10', source: 'mock', details: [] }
    : { ok: false, ip: '', reason: 'mock', details: [] }
  ctx.verifyDeadCandidates = async () => ({ confirmedIndices: new Set(), cacheDirty: false })
  ctx.queryProviderSet = async () => results
  return { ctx, logs }
}

const node = (name, server, extra = {}) => ({ name, server, port: 443, type: 'trojan', ...extra })
const originalName = 'JP @COS ResIP｜东京-01'

test('independent vote threshold and strict majority', () => {
  const { ctx } = setup()
  const result = ctx.buildGeoConsensus(fixture(['US', 'US', 'US', 'JP']), 3)
  assert.equal(result.country, 'US')
  assert.equal(result.valid, 4)
  assert.equal(ctx.buildGeoConsensus(fixture(['CN', 'CN']), 3).country, '')
  assert.equal(ctx.buildGeoConsensus(fixture(['US', 'US', 'JP', 'JP']), 2).country, '')
  assert.equal(ctx.buildGeoConsensus(fixture(['US', 'US', 'US', 'JP', 'JP', 'JP']), 3).country, '')
  assert.equal(ctx.buildGeoConsensus(fixture(['GB', 'GB', 'UK']), 3).country, 'UK')
  assert.equal(ctx.buildGeoConsensus(fixture(['EU', 'EU', 'EU']), 3).country, '')
})

test('only IP-location country and valid JSON count as evidence', () => {
  const { ctx } = setup()
  assert.equal(ctx.buildGeoConsensus({ ii: { state: 'json', data: { registered_country: 'US' } } }, 3).valid, 0)
  assert.equal(ctx.buildGeoConsensus({ ir: { state: 'err', data: { location: { country: { code: 'US' } } } } }, 3).valid, 0)
  assert.equal(ctx.parseGeoMode(), 'correct')
  assert.equal(ctx.parseGeoMode('观察'), 'observe')
  assert.equal(ctx.parseGeoMode('关闭'), 'off')
})

test('live operator mock: country correction, references, chain bypass, idempotency', async () => {
  const { ctx, logs } = setup()
  const sourceNodes = [
    node(originalName, 'one.example'),
    node('US @COS ResIP｜依赖节点', 'two.example', { 'underlying-proxy': originalName }),
    node('US @Chain-USHome ResIP｜落地', 'three.example', { 'dialer-proxy': 'Front Proxy' }),
  ]
  const result = await ctx.operator(sourceNodes)
  assert.match(result[0].name, /^US @COS Unrated·UnkIP·ResIP｜东京-01$/)
  assert.equal(result[1]['underlying-proxy'], result[0].name)
  assert.equal(result[2].name, sourceNodes[2].name)
  assert.equal(result[2]['dialer-proxy'], 'Front Proxy')
  assert.equal(sourceNodes[0].name, originalName)
  assert.ok(logs.some(line => line.includes('GEO RESULT')))
  const repeat = await ctx.operator(result)
  assert.equal(repeat[0].name, result[0].name)
})

test('observe/off switches and optional Geo tags', async () => {
  const observe = await setup({ 地理模式: '观察' }).ctx.operator([node(originalName, 'obs.example')])
  assert.match(observe[0].name, /^JP @COS/)
  const off = await setup({ 地理模式: '关闭' }).ctx.operator([node(originalName, 'off.example')])
  assert.match(off[0].name, /^JP @COS/)
  const tagged = await setup({ 地理模式: '观察', 地理标签: 1 }).ctx.operator([node(originalName, 'tag.example')])
  assert.match(tagged[0].name, /Geo-US-3of4/)
  const clean = await setup({ 地理模式: '关闭' }).ctx.operator(tagged)
  assert.doesNotMatch(clean[0].name, /Geo-/)
})

test('quality-tag-only rename keeps dependent node references valid even with Geo off', async () => {
  const { ctx } = setup({ 地理模式: '关闭' })
  const target = 'US @COS ResIP｜被引用节点'
  const output = await ctx.operator([
    node(target, 'reference-target.example'),
    node('US @COS ResIP｜依赖节点', 'reference-consumer.example', {
      'underlying-proxy': target,
      detour: target,
      chain: [target],
    }),
  ])
  assert.match(output[0].name, /^US @COS Unrated·UnkIP·ResIP｜被引用节点$/)
  assert.equal(output[1]['underlying-proxy'], output[0].name)
  assert.equal(output[1].detour, output[0].name)
  assert.equal(output[1].chain[0], output[0].name)
})

test('EIP-only diagnostic rename also synchronizes references', async () => {
  const { ctx } = setup({ 阶段: 'EIP', 诊断: 1 })
  const oldName = 'US @COS ResIP｜出口检测目标'
  const result = await ctx.operator([
    node(oldName, 'eip-target.example'),
    node('US @COS ResIP｜出口检测依赖', 'eip-dependent.example', { 'prev_hop': oldName }),
  ])
  assert.match(result[0].name, /EIP4-203\.0\.113\.10/)
  assert.equal(result[1].prev_hop, result[0].name)
})

test('global name collision fails closed', async () => {
  const nodes = [node('JP @COS ResIP｜相同', 'a.example'), node('US @COS ResIP｜相同', 'b.example')]
  const { ctx, logs } = setup()
  const result = await ctx.operator(nodes)
  assert.match(result[0].name, /^JP @COS/)
  assert.equal(new Set(result.map(x => x.name)).size, result.length)
  assert.ok(logs.some(line => line.includes('collision-hold=1')))
})

test('cached EIP can drive GeoIP without a new live exit probe', async () => {
  const { ctx, logs } = setup()
  const entry = node(originalName, 'cache.example')
  const fingerprint = ctx.nodeFingerprint(entry)
  const data = new Map([
    ['ipqlite:eip:v2', {
      version: 2,
      entries: { [fingerprint]: { ipv4: { ts: Date.now(), ok: true, ip: '203.0.113.10', source: 'cached' } } },
    }],
  ])
  ctx.scriptResourceCache = { get: key => data.get(key), set: (key, value) => data.set(key, value) }
  ctx.startHttpMetaSession = async () => { throw new Error('unexpected live META session') }
  ctx.providerNeedsLocalProxy = () => false
  const result = await ctx.operator([entry])
  assert.match(result[0].name, /^US @COS/)
  assert.ok(logs.some(line => line.includes('skip EIP probe')))
})

test('conflicting, unavailable EIP and EIP-only stage do not change region', async () => {
  const split = await setup({}, fixture(['US', 'JP', 'US', 'JP'])).ctx.operator([node(originalName, 'split.example')])
  assert.match(split[0].name, /^JP @COS/)
  const { ctx } = setup()
  ctx.probeExitFamily = async () => ({ ok: false, ip: '', reason: 'Timeout', details: [] })
  const none = await ctx.operator([node(originalName, 'failed.example')])
  assert.match(none[0].name, /^JP @COS/)
  const eip = await setup({ 阶段: 'EIP' }).ctx.operator([node(originalName, 'eip.example')])
  assert.equal(eip[0].name, originalName)
})

test('existing Risk and Dead filters still run before geographical rename', async () => {
  const risk = setup()
  risk.ctx.buildSimpleVerdict = () => ({ verdict: 'Risk' })
  const riskOutput = await risk.ctx.operator([node(originalName, 'risk.example')])
  assert.equal(riskOutput.length, 0)

  const dead = setup()
  dead.ctx.verifyDeadCandidates = async () => ({ confirmedIndices: new Set([0]), cacheDirty: false })
  const deadOutput = await dead.ctx.operator([node(originalName, 'dead.example')])
  assert.equal(deadOutput.length, 0)
})

test('Geo parser error does not downgrade existing Quality or Network Identity', async () => {
  const { ctx, logs } = setup()
  ctx.buildGeoConsensus = () => { throw new Error('mock geolocation provider error') }
  ctx.buildSimpleVerdict = () => ({ verdict: 'Trust' })
  ctx.buildNetworkIdentity = () => ({ verdict: 'ISPIP' })
  const result = await ctx.operator([node(originalName, 'geoerror.example')])
  assert.match(result[0].name, /^JP @COS Trust·ISPIP·ResIP｜东京-01$/)
  assert.ok(logs.some(line => line.includes('provider-parse-hold')))
})
