/**
 * Sub-Store Chain Dialer Injector v1.0.0
 *
 * 用途：
 *   给 Node Standardizer 已标记为 @Chain-* 的链式落地节点
 *   自动添加 Mihomo dialer-proxy。
 *
 * 推荐顺序：
 *   原始订阅
 *   -> node_standardizer.js
 *   -> 本脚本
 *   -> 多订阅组合
 *   -> ipquality.js
 *
 * 默认：
 *   前置组 = Front Proxy
 *
 * 示例：
 *   US @Chain-USHome ResIP｜#F9BEA4
 *
 * 处理后节点会增加：
 *   dialer-proxy: Front Proxy
 *
 * 不删除节点
 * 不修改名称
 * 不修改协议
 * 不修改服务器/端口/密码
 */

const args =
  typeof $arguments === 'object' && $arguments
    ? $arguments
    : {}

function operator(proxies = []) {
  if (!Array.isArray(proxies) || proxies.length === 0) {
    return proxies || []
  }

  const dialerProxy =
    String(args['前置组'] || 'Front Proxy').trim() || 'Front Proxy'

  return proxies.map(proxy => {
    if (!proxy || typeof proxy !== 'object') {
      return proxy
    }

    const name = String(proxy.name || '')

    // 只处理经过 Node Standardizer 标记的链式节点。
    if (!/@Chain-[^ ｜]+(?: |｜|$)/i.test(name)) {
      return proxy
    }

    return {
      ...proxy,
      'dialer-proxy': dialerProxy,
    }
  })
}
