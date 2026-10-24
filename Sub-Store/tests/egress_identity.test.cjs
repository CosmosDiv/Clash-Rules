// Egress identity integration regression
// Run: node --test Sub-Store/tests/egress_identity.test.cjs
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const root = path.join(__dirname, '..', 'config')
const standardizer = fs.readFileSync(path.join(root, 'node_standardizer.js'), 'utf8')
const quality = fs.readFileSync(path.join(root, 'ipquality.js'), 'utf8')
const yamlFiles = ['mihomo_pro.yaml', 'openclash_pro.yaml', 'openclash_pro_smart.yaml', 'surfing_pro.yaml']
function run(nodes, args) {
  const ctx = vm.createContext({ console, $arguments: args })
  vm.runInContext(standardizer, ctx)
  return ctx.operator(nodes)
}
const original = []
for (const p of ['APAC','US','TW','JP','SG','Download','US Fixed','TW Fixed','Egress']) {
  for (let i = 1; i <= 3; i++) for (const suffix of ['', ' TLS']) {
    original.push({ name: p + ' ' + i + suffix, server: 'test' + original.length + '.example', port: 443, type: 'trojan' })
  }
}
const args = { '机场': 'Railgun', '固定IP': 'Fixed', '忽略关键词': 'TLS', '家宽': 'Egress', '美国': 'Egress', '排除': 'Download', '专用落地': 'Egress' }
const isEgress = name => /[ ·]Egress(?:[·｜]|$)/.test(name)
function regexOf(s, key) {
  const line = s.split('\n').find(x => x.startsWith(key + ':'))
  assert.ok(line, key)
  return new RegExp(line.split("'")[1].replace('(?i)',''), 'i')
}
for (const keep of [0,1]) {
  test('Railgun: 48 valid / six dedicated Egress / original=' + keep, () => {
    const nodes = run(original.map(x => ({ ...x })), { ...args, 保留原名: keep })
    assert.equal(nodes.length, 48)
    assert.equal(nodes.filter(x => isEgress(x.name)).length, 6)
    assert.equal(nodes.filter(x => x.name.startsWith('Unknown @Railgun｜')).length, 6)
    assert.equal(nodes.filter(x => x.name.includes('StaticIP')).length, 12)
    assert.equal(nodes.filter(x => x.name.startsWith('HK @Railgun')).length, 0)
    assert.equal(nodes.filter(x => x.name.startsWith('US @Railgun ResIP·Egress｜')).length, 6)
    assert.equal(new Set(nodes.map(x => x.name)).size, nodes.length)
    assert.equal(nodes.filter(x => isEgress(x.name)).every(x => keep ? /｜Egress [1-3](?: TLS)?$/.test(x.name) : /｜#[0-9A-F]{6,8}$/.test(x.name)), true)
    if (!keep) {
      const again = run(nodes.map(x => ({ ...x })), { ...args, 保留原名: keep })
      assert.deepEqual(again.map(x => x.name), nodes.map(x => x.name))
    }
    for (const file of yamlFiles) {
      const yaml = fs.readFileSync(path.join(root, file), 'utf8')
      const eg = regexOf(yaml, 'x-filter-egress')
      const ex = regexOf(yaml, 'x-exclude-special')
      assert.equal(nodes.filter(x => eg.test(x.name)).length, 6, file)
      assert.equal(nodes.filter(x => ex.test(x.name)).length, 6, file)
      assert.equal(nodes.filter(x => !isEgress(x.name) && eg.test(x.name)).length, 0, file)
      assert.equal(eg.test('JP @Railgun ResIP·Egress｜#ABC123'), false, file)
      assert.equal(ex.test('JP @Railgun ResIP·Egress｜#ABC123'), true, file)
      assert.equal(eg.test('US @Chain-USHome ResIP·Egress｜#ABC123'), false, file)
      assert.equal(eg.test('US @Railgun ResIP｜Egress 1 TLS'), false, file)
    }
  })
}
test('Independent identity mapping and keyword boundary', () => {
  const nodes = run([
    { name: 'NonEgress 1', server: 'a', port: 443, type: 'trojan' },
    { name: 'US Home 01', server: 'b', port: 443, type: 'trojan' },
  ], { 机场: 'Other', 保留原名: 0, 专用落地: 'Egress' })
  assert.equal(nodes.some(x => isEgress(x.name)), false)
  const home = run([{ name: 'US Home 01', server:'b', port:443, type:'trojan' }], { 机场: 'Other', 保留原名: 0, 专用落地:'US Home' })
  assert.equal(isEgress(home[0].name), true)
})
test('IPQuality preserves Egress through quality and Geo updates', () => {
  const ctx = vm.createContext({ console })
  vm.runInContext(quality, ctx)
  const tagged = ctx.addTempTags('US @Railgun ResIP·Egress｜#ABC123', ['Trust','ISPIP'])
  assert.equal(tagged, 'US @Railgun Trust·ISPIP·ResIP·Egress｜#ABC123')
  assert.equal(ctx.replaceGeoRegion(tagged,'JP'), 'JP @Railgun Trust·ISPIP·ResIP·Egress｜#ABC123')
})
