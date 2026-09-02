// ============================================================================
// Node Standardizer V2.1.3 for Sub-Store
// ============================================================================
//
// V2.1.3 修订：
//   - 修正“代理服务商节点位置简称”与 ISO 国家代码的语义层级：
//     国家级强证据（国旗 / ISO-2 / ISO-3 / 国家名）优先，城市/落地位置简称仅在无强证据时兜底。
//   - 对 FRA/HND/CAN/AUS/IND/MCO/PER/PHL 等高频跨体系歧义代码不强猜；孤立出现时输出 Unknown，
//     一旦同名中存在明确国家级证据，则直接由明确证据裁决。
//   - 延续 V2.1.2 的全球地区识别、逐次计票、中转语境抑制、蜂窝/Cellular 与 Relay 增强。
//
// V2.1.2 集成修订：
//   - 地区自动识别扩展到全球 ISO Alpha-2 / Alpha-3、国旗 Emoji 与国家/地区名称；GB/GBR/🇬🇧 统一输出 UK。
//   - 地区改为“强证据计票”：每个独立命中都计 1 票，最高票胜出；最高票平票才输出 Unknown。
//   - 中转上下文前置处理：明确处于 Relay/Transit/中转/地区+转 语境的地区证据，在存在其它非中转地区证据时不参与地区计票。
//   - 网络关键词补充“蜂窝 / Cellular”到 Mobile；“星链 / Starlink”继续保持 SatNet。
//   - Relay 识别扩展到 中转/中轉/Relay/Transit/转发/轉發 与明确“地区+转/轉”表达。
//   - 能力关键词补充裸“游戏/遊戲”到 Gaming。
//   - 不自动过滤 Traffic/Expire/客服/公告等信息节点；仍只按用户显式“排除”参数处理。
//   - 机场私有黑话（常规/轻量/中产/移优/联优/三网优、D1/F1/X1/B1/P1、裸 Dedicated、CMI 等）继续不猜。
//   - V2.1.1 的 EU-27、命名协议、参数方向、幂等与链式引用更新逻辑全部保留。
//
// V2.1 变更：
//   - 删除 Standard / Std 标签及自动判断。
//   - 无额外属性时直接输出 Region @Source｜Tail。
//   - 继续兼容读取 V1 Standard 与 V2.0 Std，并在重新输出时自动移除。
//
// 用途：
//   将不同机场的节点名称统一识别为稳定、可筛选的标准格式，
//   便于多机场组合，并交给 Mihomo 按标准标签构建策略组。
//
// 推荐流程：
//   单机场原始订阅 -> 本脚本 -> 链式/前置代理（如需要） -> 多机场组合 -> Mihomo
//
// 最终名称：
//   Region @Source Tag·Tag·Tag｜Tail
//   无额外属性时：Region @Source｜Tail
//
// 示例：
//   US @DN Bulk·1x｜US-LA-01
//   JP @DN Bulk·BGP·Relay·1x｜JP-日本BGP-[美西转]-1x
//   US @RG ResIP·StaticIP·Stream·1x｜US-F1
//
// 其中：
//   @  = 来源机场
//   ·  = 标准标签分隔符
//   ｜ = 标准信息结束标记；Mihomo 标准筛选只应读取其左侧
//
// 所有参数均可选。机场命名规范时，可以零配置直接运行。
//
// ============================================================================
// 一、参数怎么填
// ============================================================================
//
// Sub-Store 参数区域左侧是 Key，右侧是 Value。
// 本说明中的配置示例全部统一写成：
//
//   Key = Value
//
// 例如：
//
//   默认标签 = 大流量
//
// 表示左侧 Key 填“默认标签”，右侧 Value 填“大流量”。
//
// ============================================================================
// 二、系统参数（固定 Key）
// ============================================================================
//
// 机场
//   手动指定来源名称。不填时自动读取当前 Sub-Store 订阅名称。
//   机场 = DN
//
// 默认标签
//   给本订阅所有节点增加相同的标准属性。
//   多个标准值使用英文逗号 , 分隔。
//   默认标签 = 大流量
//   默认标签 = 大流量,稳定
//
// 排除
//   删除名称中包含指定关键词的节点。
//   多个原始关键词使用 | 分隔。
//   排除 = 官网|公告|过期|剩余流量
//   如果规则会删除全部节点，脚本会取消本次排除并报警。
//
// 忽略关键词
//   指定文字不参与“自动识别”，但不会删除节点或修改原始名称，
//   也不会影响下面的人工属性映射。
//   忽略关键词 = 香港入口
//   忽略关键词 = 香港入口|实验线路
//
// 保留原名
//   1 = 保留原始名称（默认）
//   0 = Tail 改为稳定短 ID
//   保留原名 = 1
//   保留原名 = 0
//
// 关闭自动识别
//   一般无需填写。可选：地区,网络,线路,能力,倍率,全部
//   关闭自动识别 = 地区
//   关闭自动识别 = 地区,线路
//
// 调试
//   1 = 输出识别、冲突和配置提示；默认 0。
//   调试 = 1
//
// ============================================================================
// 三、人工属性映射（固定 Key -> 机场关键词 Value）
// ============================================================================
//
// 左侧 Key 使用下方列出的标准属性；右侧 Value 填机场原始节点中的关键词。
// 同一个属性对应多个机场关键词时，使用 | 分隔。
//
// 示例：
//   家宽 = aa|dd
//   固定IP = cc|dd
//   流媒体 = bb
//   中转 = Relay-A
//   美国 = US-P|US-A
//   原生IP = US-P
//
// 如果同一个机场关键词代表多个属性，就分别填写到对应 Key：
//
//   家宽 = dd
//   固定IP = dd
//
// 倍率也遵循同一方向。若机场明确规定 X1 表示 1 倍：
//
//   1x = X1
//
// 脚本不会把裸 X1 / X2 / P1 / F1 自动猜成倍率。
//
// ============================================================================
// 四、可用属性 Key 与最终显示
// ============================================================================
//
// 【地区】
//   自动识别支持全球 ISO 3166-1 Alpha-2 / Alpha-3、国旗 Emoji、国家/地区名称；
//   常见城市/机场代码继续作为辅助证据。英国统一输出 UK；跨地区 Multi；未知地区 Unknown。
//   人工地区映射仍保留 V2.1.1 已定义的常用中文 Key。
//
// 【IP / 网络 / 基础设施】
//   家宽 ResIP          固定IP StaticIP      动态IP DynIP
//   独享IP DediIP       原生IP NativeIP      运营商IP ISP
//   移动网络 Mobile     卫星网络 SatNet       IPv6 IPv6
//   独立服务器 DediSrv
//
// 【线路】
//   IEPL IEPL            IPLC IPLC            CN2 CN2
//   GIA GIA              BGP BGP              Anycast Anycast
//   中转 Relay           直连线路 DirectRt
//
// 【能力 / 用途】
//   高速 Fast            稳定 Stable          高带宽 HighBW
//   大流量 Bulk          流媒体 Stream         游戏 Gaming
//
// Netflix / NF / 奈飞等原始节点名称统一归入“流媒体”，不再单独输出 Netflix 标签。
// 人工配置时统一使用 Key“流媒体”。
//
// 【倍率】
//   倍率 Key 直接使用标准格式：0.1x / 0.5x / 1x / 1.5x / 2x / 3x ...
//   必须为“大于 0 的数字 + x”。
//
// 没有额外属性时无需添加占位标签，例如：US @Airport｜US-01
//
// ============================================================================
// 五、分隔符
// ============================================================================
//
// 标准配置值之间：英文逗号 ,
//   默认标签 = 大流量,稳定
//   关闭自动识别 = 地区,线路
//
// 原始关键词之间：|
//   家宽 = aa|home|dd
//   排除 = 官网|公告|过期
//   忽略关键词 = 香港入口|实验线路
//
// 不使用 + / ; / 中文逗号代替以上分隔符。
//
// ============================================================================
// 六、常用配置示例
// ============================================================================
//
// A. 命名规范：无需任何参数。
//
// B. 整个机场适合大流量：
//   默认标签 = 大流量
//
// C. 机场自己的节点代码：
//   机场 = DN
//   默认标签 = 大流量
//   家宽 = aa|dd
//   固定IP = cc|dd
//   流媒体 = bb
//
// D. 人工指定地区或多个属性：
//   美国 = US-P
//   原生IP = US-P
//   固定IP = US-P
//
// E. 机场有私有入口词，不希望它参与自动识别：
//   忽略关键词 = 香港入口
//   // “美西转 / 日本转 / Transit / Relay”等常见中转语义已自动识别，无需再手工配置。
//
// F. 删除公告类伪节点：
//   排除 = 官网|公告|过期|剩余流量
//
// G. 不显示机场原始名称：
//   保留原名 = 0
//   输出示例：US @DN Bulk·1x｜#19ECAD
//
// ============================================================================
// 七、使用原则
// ============================================================================
//
// 1. 能自动识别的内容不必重复配置。
// 2. 人工属性映射用于机场特殊代码、歧义命名或自动识别无法确定的信息。
// 3. 左侧 Key 只使用本说明定义的固定 Key；不要自行创建属性 Key。
// 4. 不确定的信息不要强行标记。
// 5. 推荐在单机场层运行脚本，再进行链式处理和多机场组合。
// 6. V2 参数方向与 V1.x 不兼容；旧的“机场关键词 = 标准属性”写法不再支持。
// 7. 不再使用 Standard / Std；未识别到特殊属性的节点无需额外标签。
//
// ============================================================================
// Developer Notes
// ============================================================================
//
// - 配置层、Canonical Semantic、Display Formatter 三层分离。
// - 唯一值优先级：人工属性映射 > 默认标签 > 自动识别。
// - Region 始终唯一；自动识别按强地区证据逐次计票，最高票胜出，最高票平票才输出 Unknown。
// - Multiplier 始终唯一；同层冲突不输出倍率。
// - V2.1 不再输出 Standard / Std；未识别到其它属性时，属性区允许为空。
// - V2 名称协议：Region @Source Tags｜Tail；“｜”必须始终存在。
// - V2 可读取 Raw / V1.x / V2 输入，保持重复执行幂等。
// - 输入已是 V2 时，信任“｜”左侧 Canonical Metadata，不再用 Tail 反推标签。
// - 不调用外部 GeoIP / ASN / IP 质量 API，基础分类保持确定性与 fail-soft。
//
// ============================================================================

const NS_ARGS = (typeof $arguments === 'object' && $arguments) ? $arguments : {};

const NS_VERSION = '2.1.3';

const RESERVED_KEYS = new Set([
  '机场',
  '默认标签',
  '排除',
  '忽略关键词',
  '保留原名',
  '关闭自动识别',
  '调试',
]);

// Standard configuration Key -> Canonical Semantic.
// These keys are fixed. V2 no longer accepts arbitrary provider keywords on the left.
const TAG_DICTIONARY = Object.freeze({
  // Region
  '香港': 'HK',
  '澳门': 'MO',
  '台湾': 'TW',
  '新加坡': 'SG',
  '日本': 'JP',
  '韩国': 'KR',
  '美国': 'US',
  '英国': 'UK',
  '加拿大': 'CA',
  '澳大利亚': 'AU',
  '德国': 'DE',
  '法国': 'FR',
  '荷兰': 'NL',
  '意大利': 'IT',
  '西班牙': 'ES',
  '奥地利': 'AT',
  '比利时': 'BE',
  '保加利亚': 'BG',
  '塞浦路斯': 'CY',
  '捷克': 'CZ',
  '丹麦': 'DK',
  '爱沙尼亚': 'EE',
  '希腊': 'GR',
  '克罗地亚': 'HR',
  '匈牙利': 'HU',
  '立陶宛': 'LT',
  '卢森堡': 'LU',
  '拉脱维亚': 'LV',
  '马耳他': 'MT',
  '葡萄牙': 'PT',
  '罗马尼亚': 'RO',
  '斯洛文尼亚': 'SI',
  '斯洛伐克': 'SK',
  '瑞士': 'CH',
  '俄罗斯': 'RU',
  '土耳其': 'TR',
  '阿联酋': 'AE',
  '印度': 'IN',
  '马来西亚': 'MY',
  '泰国': 'TH',
  '越南': 'VN',
  '菲律宾': 'PH',
  '印度尼西亚': 'ID',
  '巴西': 'BR',
  '墨西哥': 'MX',
  '新西兰': 'NZ',
  '瑞典': 'SE',
  '挪威': 'NO',
  '芬兰': 'FI',
  '波兰': 'PL',
  '爱尔兰': 'IE',
  '跨地区': 'MultiRegion',
  '未知地区': 'UnknownRegion',

  // Network / IP / infrastructure
  '家宽': 'Residential',
  '固定IP': 'StaticIP',
  '动态IP': 'DynamicIP',
  '独享IP': 'DedicatedIP',
  '原生IP': 'NativeIP',
  '运营商IP': 'ISP',
  '移动网络': 'Mobile',
  '卫星网络': 'Satellite',
  'IPv6': 'IPv6',
  '独立服务器': 'DedicatedServer',

  // Route
  'IEPL': 'IEPL',
  'IPLC': 'IPLC',
  'CN2': 'CN2',
  'GIA': 'GIA',
  'BGP': 'BGP',
  'Anycast': 'Anycast',
  '中转': 'Relay',
  '直连线路': 'DirectRoute',

  // Capability / usage
  '高速': 'Fast',
  '稳定': 'Stable',
  '高带宽': 'HighBandwidth',
  '大流量': 'BulkTraffic',
  '流媒体': 'Streaming',
  '游戏': 'Gaming',
});

// Global region metadata used by automatic detection.
// Canonical output intentionally uses UK rather than GB; XK is accepted for provider compatibility.
const REGION_ALPHA2_TO_CANONICAL = Object.freeze({
  "AD": "AD",
  "AE": "AE",
  "AF": "AF",
  "AG": "AG",
  "AI": "AI",
  "AL": "AL",
  "AM": "AM",
  "AO": "AO",
  "AQ": "AQ",
  "AR": "AR",
  "AS": "AS",
  "AT": "AT",
  "AU": "AU",
  "AW": "AW",
  "AX": "AX",
  "AZ": "AZ",
  "BA": "BA",
  "BB": "BB",
  "BD": "BD",
  "BE": "BE",
  "BF": "BF",
  "BG": "BG",
  "BH": "BH",
  "BI": "BI",
  "BJ": "BJ",
  "BL": "BL",
  "BM": "BM",
  "BN": "BN",
  "BO": "BO",
  "BQ": "BQ",
  "BR": "BR",
  "BS": "BS",
  "BT": "BT",
  "BV": "BV",
  "BW": "BW",
  "BY": "BY",
  "BZ": "BZ",
  "CA": "CA",
  "CC": "CC",
  "CD": "CD",
  "CF": "CF",
  "CG": "CG",
  "CH": "CH",
  "CI": "CI",
  "CK": "CK",
  "CL": "CL",
  "CM": "CM",
  "CN": "CN",
  "CO": "CO",
  "CR": "CR",
  "CU": "CU",
  "CV": "CV",
  "CW": "CW",
  "CX": "CX",
  "CY": "CY",
  "CZ": "CZ",
  "DE": "DE",
  "DJ": "DJ",
  "DK": "DK",
  "DM": "DM",
  "DO": "DO",
  "DZ": "DZ",
  "EC": "EC",
  "EE": "EE",
  "EG": "EG",
  "EH": "EH",
  "ER": "ER",
  "ES": "ES",
  "ET": "ET",
  "FI": "FI",
  "FJ": "FJ",
  "FK": "FK",
  "FM": "FM",
  "FO": "FO",
  "FR": "FR",
  "GA": "GA",
  "GB": "UK",
  "GD": "GD",
  "GE": "GE",
  "GF": "GF",
  "GG": "GG",
  "GH": "GH",
  "GI": "GI",
  "GL": "GL",
  "GM": "GM",
  "GN": "GN",
  "GP": "GP",
  "GQ": "GQ",
  "GR": "GR",
  "GS": "GS",
  "GT": "GT",
  "GU": "GU",
  "GW": "GW",
  "GY": "GY",
  "HK": "HK",
  "HM": "HM",
  "HN": "HN",
  "HR": "HR",
  "HT": "HT",
  "HU": "HU",
  "ID": "ID",
  "IE": "IE",
  "IL": "IL",
  "IM": "IM",
  "IN": "IN",
  "IO": "IO",
  "IQ": "IQ",
  "IR": "IR",
  "IS": "IS",
  "IT": "IT",
  "JE": "JE",
  "JM": "JM",
  "JO": "JO",
  "JP": "JP",
  "KE": "KE",
  "KG": "KG",
  "KH": "KH",
  "KI": "KI",
  "KM": "KM",
  "KN": "KN",
  "KP": "KP",
  "KR": "KR",
  "KW": "KW",
  "KY": "KY",
  "KZ": "KZ",
  "LA": "LA",
  "LB": "LB",
  "LC": "LC",
  "LI": "LI",
  "LK": "LK",
  "LR": "LR",
  "LS": "LS",
  "LT": "LT",
  "LU": "LU",
  "LV": "LV",
  "LY": "LY",
  "MA": "MA",
  "MC": "MC",
  "MD": "MD",
  "ME": "ME",
  "MF": "MF",
  "MG": "MG",
  "MH": "MH",
  "MK": "MK",
  "ML": "ML",
  "MM": "MM",
  "MN": "MN",
  "MO": "MO",
  "MP": "MP",
  "MQ": "MQ",
  "MR": "MR",
  "MS": "MS",
  "MT": "MT",
  "MU": "MU",
  "MV": "MV",
  "MW": "MW",
  "MX": "MX",
  "MY": "MY",
  "MZ": "MZ",
  "NA": "NA",
  "NC": "NC",
  "NE": "NE",
  "NF": "NF",
  "NG": "NG",
  "NI": "NI",
  "NL": "NL",
  "NO": "NO",
  "NP": "NP",
  "NR": "NR",
  "NU": "NU",
  "NZ": "NZ",
  "OM": "OM",
  "PA": "PA",
  "PE": "PE",
  "PF": "PF",
  "PG": "PG",
  "PH": "PH",
  "PK": "PK",
  "PL": "PL",
  "PM": "PM",
  "PN": "PN",
  "PR": "PR",
  "PS": "PS",
  "PT": "PT",
  "PW": "PW",
  "PY": "PY",
  "QA": "QA",
  "RE": "RE",
  "RO": "RO",
  "RS": "RS",
  "RU": "RU",
  "RW": "RW",
  "SA": "SA",
  "SB": "SB",
  "SC": "SC",
  "SD": "SD",
  "SE": "SE",
  "SG": "SG",
  "SH": "SH",
  "SI": "SI",
  "SJ": "SJ",
  "SK": "SK",
  "SL": "SL",
  "SM": "SM",
  "SN": "SN",
  "SO": "SO",
  "SR": "SR",
  "SS": "SS",
  "ST": "ST",
  "SV": "SV",
  "SX": "SX",
  "SY": "SY",
  "SZ": "SZ",
  "TC": "TC",
  "TD": "TD",
  "TF": "TF",
  "TG": "TG",
  "TH": "TH",
  "TJ": "TJ",
  "TK": "TK",
  "TL": "TL",
  "TM": "TM",
  "TN": "TN",
  "TO": "TO",
  "TR": "TR",
  "TT": "TT",
  "TV": "TV",
  "TW": "TW",
  "TZ": "TZ",
  "UA": "UA",
  "UG": "UG",
  "UK": "UK",
  "UM": "UM",
  "US": "US",
  "UY": "UY",
  "UZ": "UZ",
  "VA": "VA",
  "VC": "VC",
  "VE": "VE",
  "VG": "VG",
  "VI": "VI",
  "VN": "VN",
  "VU": "VU",
  "WF": "WF",
  "WS": "WS",
  "XK": "XK",
  "YE": "YE",
  "YT": "YT",
  "ZA": "ZA",
  "ZM": "ZM",
  "ZW": "ZW"
});

const REGION_ALPHA3_TO_CANONICAL = Object.freeze({
  "ABW": "AW",
  "AFG": "AF",
  "AGO": "AO",
  "AIA": "AI",
  "ALA": "AX",
  "ALB": "AL",
  "AND": "AD",
  "ARE": "AE",
  "ARG": "AR",
  "ARM": "AM",
  "ASM": "AS",
  "ATA": "AQ",
  "ATF": "TF",
  "ATG": "AG",
  "AUS": "AU",
  "AUT": "AT",
  "AZE": "AZ",
  "BDI": "BI",
  "BEL": "BE",
  "BEN": "BJ",
  "BES": "BQ",
  "BFA": "BF",
  "BGD": "BD",
  "BGR": "BG",
  "BHR": "BH",
  "BHS": "BS",
  "BIH": "BA",
  "BLM": "BL",
  "BLR": "BY",
  "BLZ": "BZ",
  "BMU": "BM",
  "BOL": "BO",
  "BRA": "BR",
  "BRB": "BB",
  "BRN": "BN",
  "BTN": "BT",
  "BVT": "BV",
  "BWA": "BW",
  "CAF": "CF",
  "CAN": "CA",
  "CCK": "CC",
  "CHE": "CH",
  "CHL": "CL",
  "CHN": "CN",
  "CIV": "CI",
  "CMR": "CM",
  "COD": "CD",
  "COG": "CG",
  "COK": "CK",
  "COL": "CO",
  "COM": "KM",
  "CPV": "CV",
  "CRI": "CR",
  "CUB": "CU",
  "CUW": "CW",
  "CXR": "CX",
  "CYM": "KY",
  "CYP": "CY",
  "CZE": "CZ",
  "DEU": "DE",
  "DJI": "DJ",
  "DMA": "DM",
  "DNK": "DK",
  "DOM": "DO",
  "DZA": "DZ",
  "ECU": "EC",
  "EGY": "EG",
  "ERI": "ER",
  "ESH": "EH",
  "ESP": "ES",
  "EST": "EE",
  "ETH": "ET",
  "FIN": "FI",
  "FJI": "FJ",
  "FLK": "FK",
  "FRA": "FR",
  "FRO": "FO",
  "FSM": "FM",
  "GAB": "GA",
  "GBR": "UK",
  "GEO": "GE",
  "GGY": "GG",
  "GHA": "GH",
  "GIB": "GI",
  "GIN": "GN",
  "GLP": "GP",
  "GMB": "GM",
  "GNB": "GW",
  "GNQ": "GQ",
  "GRC": "GR",
  "GRD": "GD",
  "GRL": "GL",
  "GTM": "GT",
  "GUF": "GF",
  "GUM": "GU",
  "GUY": "GY",
  "HKG": "HK",
  "HMD": "HM",
  "HND": "HN",
  "HRV": "HR",
  "HTI": "HT",
  "HUN": "HU",
  "IDN": "ID",
  "IMN": "IM",
  "IND": "IN",
  "IOT": "IO",
  "IRL": "IE",
  "IRN": "IR",
  "IRQ": "IQ",
  "ISL": "IS",
  "ISR": "IL",
  "ITA": "IT",
  "JAM": "JM",
  "JEY": "JE",
  "JOR": "JO",
  "JPN": "JP",
  "KAZ": "KZ",
  "KEN": "KE",
  "KGZ": "KG",
  "KHM": "KH",
  "KIR": "KI",
  "KNA": "KN",
  "KOR": "KR",
  "KWT": "KW",
  "LAO": "LA",
  "LBN": "LB",
  "LBR": "LR",
  "LBY": "LY",
  "LCA": "LC",
  "LIE": "LI",
  "LKA": "LK",
  "LSO": "LS",
  "LTU": "LT",
  "LUX": "LU",
  "LVA": "LV",
  "MAC": "MO",
  "MAF": "MF",
  "MAR": "MA",
  "MCO": "MC",
  "MDA": "MD",
  "MDG": "MG",
  "MDV": "MV",
  "MEX": "MX",
  "MHL": "MH",
  "MKD": "MK",
  "MLI": "ML",
  "MLT": "MT",
  "MMR": "MM",
  "MNE": "ME",
  "MNG": "MN",
  "MNP": "MP",
  "MOZ": "MZ",
  "MRT": "MR",
  "MSR": "MS",
  "MTQ": "MQ",
  "MUS": "MU",
  "MWI": "MW",
  "MYS": "MY",
  "MYT": "YT",
  "NAM": "NA",
  "NCL": "NC",
  "NER": "NE",
  "NFK": "NF",
  "NGA": "NG",
  "NIC": "NI",
  "NIU": "NU",
  "NLD": "NL",
  "NOR": "NO",
  "NPL": "NP",
  "NRU": "NR",
  "NZL": "NZ",
  "OMN": "OM",
  "PAK": "PK",
  "PAN": "PA",
  "PCN": "PN",
  "PER": "PE",
  "PHL": "PH",
  "PLW": "PW",
  "PNG": "PG",
  "POL": "PL",
  "PRI": "PR",
  "PRK": "KP",
  "PRT": "PT",
  "PRY": "PY",
  "PSE": "PS",
  "PYF": "PF",
  "QAT": "QA",
  "REU": "RE",
  "ROU": "RO",
  "RUS": "RU",
  "RWA": "RW",
  "SAU": "SA",
  "SDN": "SD",
  "SEN": "SN",
  "SGP": "SG",
  "SGS": "GS",
  "SHN": "SH",
  "SJM": "SJ",
  "SLB": "SB",
  "SLE": "SL",
  "SLV": "SV",
  "SMR": "SM",
  "SOM": "SO",
  "SPM": "PM",
  "SRB": "RS",
  "SSD": "SS",
  "STP": "ST",
  "SUR": "SR",
  "SVK": "SK",
  "SVN": "SI",
  "SWE": "SE",
  "SWZ": "SZ",
  "SXM": "SX",
  "SYC": "SC",
  "SYR": "SY",
  "TCA": "TC",
  "TCD": "TD",
  "TGO": "TG",
  "THA": "TH",
  "TJK": "TJ",
  "TKL": "TK",
  "TKM": "TM",
  "TLS": "TL",
  "TON": "TO",
  "TTO": "TT",
  "TUN": "TN",
  "TUR": "TR",
  "TUV": "TV",
  "TWN": "TW",
  "TZA": "TZ",
  "UAE": "AE",
  "UGA": "UG",
  "UKR": "UA",
  "UMI": "UM",
  "URY": "UY",
  "USA": "US",
  "UZB": "UZ",
  "VAT": "VA",
  "VCT": "VC",
  "VEN": "VE",
  "VGB": "VG",
  "VIR": "VI",
  "VNM": "VN",
  "VUT": "VU",
  "WLF": "WF",
  "WSM": "WS",
  "XKX": "XK",
  "YEM": "YE",
  "ZAF": "ZA",
  "ZMB": "ZM",
  "ZWE": "ZW"
});

// One primary Simplified-Chinese name + one primary English name per territory,
// plus a conservative set of traditional/common names and major city/airport aliases.
const REGION_NAME_ALIASES = Object.freeze([
  ["AD", ["安道尔", "Andorra"]],
  ["AE", ["阿拉伯联合酋长国", "United Arab Emirates", "阿联酋", "阿聯酋", "Dubai", "迪拜", "UAE"]],
  ["AF", ["阿富汗", "Afghanistan"]],
  ["AG", ["安提瓜和巴布达", "Antigua & Barbuda"]],
  ["AI", ["安圭拉", "Anguilla"]],
  ["AL", ["阿尔巴尼亚", "Albania"]],
  ["AM", ["亚美尼亚", "Armenia"]],
  ["AO", ["安哥拉", "Angola"]],
  ["AQ", ["南极洲", "Antarctica"]],
  ["AR", ["阿根廷", "Argentina"]],
  ["AS", ["美属萨摩亚", "American Samoa"]],
  ["AT", ["奥地利", "Austria", "奧地利", "Vienna", "Wien", "维也纳", "維也納", "VIE"]],
  ["AU", ["澳大利亚", "Australia", "澳大利亞", "澳洲", "Sydney", "Melbourne", "悉尼", "墨尔本", "墨爾本", "SYD", "MEL"]],
  ["AW", ["阿鲁巴", "Aruba"]],
  ["AX", ["奥兰群岛", "Åland Islands", "奧蘭群島", "Aland Islands"]],
  ["AZ", ["阿塞拜疆", "Azerbaijan"]],
  ["BA", ["波斯尼亚和黑塞哥维那", "Bosnia & Herzegovina"]],
  ["BB", ["巴巴多斯", "Barbados"]],
  ["BD", ["孟加拉国", "Bangladesh"]],
  ["BE", ["比利时", "Belgium", "比利時", "Brussels", "布鲁塞尔", "布魯塞爾", "BRU"]],
  ["BF", ["布基纳法索", "Burkina Faso"]],
  ["BG", ["保加利亚", "Bulgaria", "保加利亞", "Sofia", "索非亚", "索菲亞", "SOF"]],
  ["BH", ["巴林", "Bahrain"]],
  ["BI", ["布隆迪", "Burundi"]],
  ["BJ", ["贝宁", "Benin"]],
  ["BL", ["圣巴泰勒米", "St. Barthélemy"]],
  ["BM", ["百慕大", "Bermuda"]],
  ["BN", ["文莱", "Brunei"]],
  ["BO", ["玻利维亚", "Bolivia", "玻利維亞"]],
  ["BQ", ["荷属加勒比区", "Caribbean Netherlands", "荷属加勒比", "荷屬加勒比"]],
  ["BR", ["巴西", "Brazil", "São Paulo", "Sao Paulo", "圣保罗", "聖保羅"]],
  ["BS", ["巴哈马", "Bahamas"]],
  ["BT", ["不丹", "Bhutan"]],
  ["BV", ["布韦岛", "Bouvet Island"]],
  ["BW", ["博茨瓦纳", "Botswana"]],
  ["BY", ["白俄罗斯", "Belarus"]],
  ["BZ", ["伯利兹", "Belize"]],
  ["CA", ["加拿大", "Canada", "Toronto", "Vancouver", "YYZ", "YVR"]],
  ["CC", ["科科斯（基林）群岛", "Cocos (Keeling) Islands"]],
  ["CD", ["刚果（金）", "Congo - Kinshasa"]],
  ["CF", ["中非共和国", "Central African Republic"]],
  ["CG", ["刚果（布）", "Congo - Brazzaville"]],
  ["CH", ["瑞士", "Switzerland", "Zurich", "苏黎世", "蘇黎世", "ZRH"]],
  ["CI", ["科特迪瓦", "Côte d’Ivoire"]],
  ["CK", ["库克群岛", "Cook Islands"]],
  ["CL", ["智利", "Chile"]],
  ["CM", ["喀麦隆", "Cameroon"]],
  ["CN", ["中国", "China", "中国大陆", "中國大陸", "中國", "Mainland China"]],
  ["CO", ["哥伦比亚", "Colombia"]],
  ["CR", ["哥斯达黎加", "Costa Rica"]],
  ["CU", ["古巴", "Cuba"]],
  ["CV", ["佛得角", "Cape Verde"]],
  ["CW", ["库拉索", "Curaçao"]],
  ["CX", ["圣诞岛", "Christmas Island"]],
  ["CY", ["塞浦路斯", "Cyprus", "Nicosia", "尼科西亚", "尼科西亞"]],
  ["CZ", ["捷克", "Czechia", "Czech Republic", "Prague", "布拉格", "PRG"]],
  ["DE", ["德国", "Germany", "德國", "Frankfurt", "Berlin", "法兰克福", "法蘭克福"]],
  ["DJ", ["吉布提", "Djibouti"]],
  ["DK", ["丹麦", "Denmark", "丹麥", "Copenhagen", "哥本哈根", "CPH"]],
  ["DM", ["多米尼克", "Dominica"]],
  ["DO", ["多米尼加共和国", "Dominican Republic"]],
  ["DZ", ["阿尔及利亚", "Algeria"]],
  ["EC", ["厄瓜多尔", "Ecuador"]],
  ["EE", ["爱沙尼亚", "Estonia", "愛沙尼亞", "Tallinn", "塔林", "TLL"]],
  ["EG", ["埃及", "Egypt"]],
  ["EH", ["西撒哈拉", "Western Sahara"]],
  ["ER", ["厄立特里亚", "Eritrea"]],
  ["ES", ["西班牙", "Spain", "Madrid", "Barcelona", "马德里", "馬德里", "巴塞罗那", "巴塞羅那", "MAD", "BCN"]],
  ["ET", ["埃塞俄比亚", "Ethiopia"]],
  ["FI", ["芬兰", "Finland", "芬蘭", "Helsinki", "赫尔辛基", "赫爾辛基"]],
  ["FJ", ["斐济", "Fiji"]],
  ["FK", ["福克兰群岛", "Falkland Islands"]],
  ["FM", ["密克罗尼西亚", "Micronesia"]],
  ["FO", ["法罗群岛", "Faroe Islands"]],
  ["FR", ["法国", "France", "法國", "Paris", "巴黎", "CDG"]],
  ["GA", ["加蓬", "Gabon"]],
  ["GD", ["格林纳达", "Grenada"]],
  ["GE", ["格鲁吉亚", "Georgia"]],
  ["GF", ["法属圭亚那", "French Guiana"]],
  ["GG", ["根西岛", "Guernsey"]],
  ["GH", ["加纳", "Ghana"]],
  ["GI", ["直布罗陀", "Gibraltar"]],
  ["GL", ["格陵兰", "Greenland"]],
  ["GM", ["冈比亚", "Gambia"]],
  ["GN", ["几内亚", "Guinea"]],
  ["GP", ["瓜德罗普", "Guadeloupe"]],
  ["GQ", ["赤道几内亚", "Equatorial Guinea"]],
  ["GR", ["希腊", "Greece", "希臘", "Athens", "雅典", "ATH"]],
  ["GS", ["南乔治亚和南桑威奇群岛", "South Georgia & South Sandwich Islands"]],
  ["GT", ["危地马拉", "Guatemala"]],
  ["GU", ["关岛", "Guam"]],
  ["GW", ["几内亚比绍", "Guinea-Bissau"]],
  ["GY", ["圭亚那", "Guyana"]],
  ["HK", ["中国香港特别行政区", "Hong Kong SAR China", "香港", "Hong Kong", "Hongkong"]],
  ["HM", ["赫德岛和麦克唐纳群岛", "Heard & McDonald Islands"]],
  ["HN", ["洪都拉斯", "Honduras"]],
  ["HR", ["克罗地亚", "Croatia", "克羅地亞", "Zagreb", "萨格勒布", "薩格勒布", "ZAG"]],
  ["HT", ["海地", "Haiti"]],
  ["HU", ["匈牙利", "Hungary", "Budapest", "布达佩斯", "布達佩斯", "BUD"]],
  ["ID", ["印度尼西亚", "Indonesia", "印度尼西亞", "印尼", "Jakarta", "雅加达", "雅加達"]],
  ["IE", ["爱尔兰", "Ireland", "愛爾蘭", "Dublin", "都柏林"]],
  ["IL", ["以色列", "Israel"]],
  ["IM", ["马恩岛", "Isle of Man"]],
  ["IN", ["印度", "India", "Mumbai", "Delhi", "孟买", "孟買", "新德里"]],
  ["IO", ["英属印度洋领地", "British Indian Ocean Territory", "英屬印度洋領地"]],
  ["IQ", ["伊拉克", "Iraq"]],
  ["IR", ["伊朗", "Iran"]],
  ["IS", ["冰岛", "Iceland"]],
  ["IT", ["意大利", "Italy", "Rome", "Milan", "罗马", "羅馬", "米兰", "米蘭", "FCO", "MXP"]],
  ["JE", ["泽西岛", "Jersey"]],
  ["JM", ["牙买加", "Jamaica"]],
  ["JO", ["约旦", "Jordan"]],
  ["JP", ["日本", "Japan", "东京", "東京", "大阪", "Tokyo", "Osaka", "NRT", "KIX"]],
  ["KE", ["肯尼亚", "Kenya"]],
  ["KG", ["吉尔吉斯斯坦", "Kyrgyzstan"]],
  ["KH", ["柬埔寨", "Cambodia"]],
  ["KI", ["基里巴斯", "Kiribati"]],
  ["KM", ["科摩罗", "Comoros"]],
  ["KN", ["圣基茨和尼维斯", "St. Kitts & Nevis"]],
  ["KP", ["朝鲜", "North Korea"]],
  ["KR", ["韩国", "South Korea", "韓國", "首尔", "首爾", "春川", "Korea", "Seoul", "Chuncheon", "ICN", "GMP"]],
  ["KW", ["科威特", "Kuwait"]],
  ["KY", ["开曼群岛", "Cayman Islands"]],
  ["KZ", ["哈萨克斯坦", "Kazakhstan"]],
  ["LA", ["老挝", "Laos"]],
  ["LB", ["黎巴嫩", "Lebanon"]],
  ["LC", ["圣卢西亚", "St. Lucia"]],
  ["LI", ["列支敦士登", "Liechtenstein"]],
  ["LK", ["斯里兰卡", "Sri Lanka"]],
  ["LR", ["利比里亚", "Liberia"]],
  ["LS", ["莱索托", "Lesotho"]],
  ["LT", ["立陶宛", "Lithuania", "Vilnius", "维尔纽斯", "維爾紐斯", "VNO"]],
  ["LU", ["卢森堡", "Luxembourg", "盧森堡", "LUX"]],
  ["LV", ["拉脱维亚", "Latvia", "拉脫維亞", "Riga", "里加", "RIX"]],
  ["LY", ["利比亚", "Libya"]],
  ["MA", ["摩洛哥", "Morocco"]],
  ["MC", ["摩纳哥", "Monaco"]],
  ["MD", ["摩尔多瓦", "Moldova"]],
  ["ME", ["黑山", "Montenegro"]],
  ["MF", ["法属圣马丁", "St. Martin", "法屬聖馬丁", "Saint Martin"]],
  ["MG", ["马达加斯加", "Madagascar"]],
  ["MH", ["马绍尔群岛", "Marshall Islands"]],
  ["MK", ["北马其顿", "North Macedonia"]],
  ["ML", ["马里", "Mali"]],
  ["MM", ["缅甸", "Myanmar (Burma)"]],
  ["MN", ["蒙古", "Mongolia"]],
  ["MO", ["中国澳门特别行政区", "Macao SAR China", "澳门", "澳門", "Macao", "Macau", "MFM"]],
  ["MP", ["北马里亚纳群岛", "Northern Mariana Islands"]],
  ["MQ", ["马提尼克", "Martinique"]],
  ["MR", ["毛里塔尼亚", "Mauritania"]],
  ["MS", ["蒙特塞拉特", "Montserrat"]],
  ["MT", ["马耳他", "Malta", "馬耳他", "Valletta", "瓦莱塔", "瓦萊塔"]],
  ["MU", ["毛里求斯", "Mauritius"]],
  ["MV", ["马尔代夫", "Maldives"]],
  ["MW", ["马拉维", "Malawi"]],
  ["MX", ["墨西哥", "Mexico", "Mexico City", "墨西哥城"]],
  ["MY", ["马来西亚", "Malaysia", "馬來西亞", "Kuala Lumpur", "吉隆坡"]],
  ["MZ", ["莫桑比克", "Mozambique"]],
  ["NA", ["纳米比亚", "Namibia"]],
  ["NC", ["新喀里多尼亚", "New Caledonia"]],
  ["NE", ["尼日尔", "Niger"]],
  ["NF", ["诺福克岛", "Norfolk Island"]],
  ["NG", ["尼日利亚", "Nigeria", "尼日利亞"]],
  ["NI", ["尼加拉瓜", "Nicaragua"]],
  ["NL", ["荷兰", "Netherlands", "荷蘭", "Amsterdam", "阿姆斯特丹", "AMS"]],
  ["NO", ["挪威", "Norway", "Oslo", "奥斯陆", "奧斯陸"]],
  ["NP", ["尼泊尔", "Nepal"]],
  ["NR", ["瑙鲁", "Nauru"]],
  ["NU", ["纽埃", "Niue"]],
  ["NZ", ["新西兰", "New Zealand", "新西蘭", "Auckland", "奥克兰", "奧克蘭"]],
  ["OM", ["阿曼", "Oman"]],
  ["PA", ["巴拿马", "Panama"]],
  ["PE", ["秘鲁", "Peru"]],
  ["PF", ["法属波利尼西亚", "French Polynesia"]],
  ["PG", ["巴布亚新几内亚", "Papua New Guinea"]],
  ["PH", ["菲律宾", "Philippines", "菲律賓", "Manila", "马尼拉", "馬尼拉"]],
  ["PK", ["巴基斯坦", "Pakistan"]],
  ["PL", ["波兰", "Poland", "波蘭", "Warsaw", "华沙", "華沙"]],
  ["PM", ["圣皮埃尔和密克隆群岛", "St. Pierre & Miquelon"]],
  ["PN", ["皮特凯恩群岛", "Pitcairn Islands"]],
  ["PR", ["波多黎各", "Puerto Rico"]],
  ["PS", ["巴勒斯坦领土", "Palestinian Territories", "巴勒斯坦", "巴勒斯坦領土", "Palestine"]],
  ["PT", ["葡萄牙", "Portugal", "Lisbon", "里斯本", "LIS"]],
  ["PW", ["帕劳", "Palau"]],
  ["PY", ["巴拉圭", "Paraguay"]],
  ["QA", ["卡塔尔", "Qatar"]],
  ["RE", ["留尼汪", "Réunion", "法属留尼汪", "法屬留尼汪", "Reunion"]],
  ["RO", ["罗马尼亚", "Romania", "羅馬尼亞", "Bucharest", "布加勒斯特", "OTP"]],
  ["RS", ["塞尔维亚", "Serbia", "塞爾維亞"]],
  ["RU", ["俄罗斯", "Russia", "俄羅斯", "Moscow", "莫斯科"]],
  ["RW", ["卢旺达", "Rwanda"]],
  ["SA", ["沙特阿拉伯", "Saudi Arabia"]],
  ["SB", ["所罗门群岛", "Solomon Islands"]],
  ["SC", ["塞舌尔", "Seychelles"]],
  ["SD", ["苏丹", "Sudan"]],
  ["SE", ["瑞典", "Sweden", "Stockholm", "斯德哥尔摩", "斯德哥爾摩"]],
  ["SG", ["新加坡", "Singapore", "狮城", "獅城", "SIN"]],
  ["SH", ["圣赫勒拿", "St. Helena"]],
  ["SI", ["斯洛文尼亚", "Slovenia", "斯洛文尼亞", "Ljubljana", "卢布尔雅那", "盧布爾雅那", "LJU"]],
  ["SJ", ["斯瓦尔巴和扬马延", "Svalbard & Jan Mayen"]],
  ["SK", ["斯洛伐克", "Slovakia", "Bratislava", "布拉迪斯拉发", "布拉迪斯拉發", "BTS"]],
  ["SL", ["塞拉利昂", "Sierra Leone"]],
  ["SM", ["圣马力诺", "San Marino"]],
  ["SN", ["塞内加尔", "Senegal"]],
  ["SO", ["索马里", "Somalia"]],
  ["SR", ["苏里南", "Suriname"]],
  ["SS", ["南苏丹", "South Sudan"]],
  ["ST", ["圣多美和普林西比", "São Tomé & Príncipe"]],
  ["SV", ["萨尔瓦多", "El Salvador"]],
  ["SX", ["荷属圣马丁", "Sint Maarten", "荷屬聖馬丁"]],
  ["SY", ["叙利亚", "Syria"]],
  ["SZ", ["斯威士兰", "Eswatini"]],
  ["TC", ["特克斯和凯科斯群岛", "Turks & Caicos Islands"]],
  ["TD", ["乍得", "Chad"]],
  ["TF", ["法属南部领地", "French Southern Territories"]],
  ["TG", ["多哥", "Togo"]],
  ["TH", ["泰国", "Thailand", "泰國", "Bangkok", "曼谷"]],
  ["TJ", ["塔吉克斯坦", "Tajikistan"]],
  ["TK", ["托克劳", "Tokelau"]],
  ["TL", ["东帝汶", "Timor-Leste"]],
  ["TM", ["土库曼斯坦", "Turkmenistan"]],
  ["TN", ["突尼斯", "Tunisia"]],
  ["TO", ["汤加", "Tonga"]],
  ["TR", ["土耳其", "Türkiye", "Turkey", "Istanbul", "伊斯坦布尔", "伊斯坦堡"]],
  ["TT", ["特立尼达和多巴哥", "Trinidad & Tobago"]],
  ["TV", ["图瓦卢", "Tuvalu"]],
  ["TW", ["台湾", "Taiwan", "臺灣", "台灣", "Taipei", "台北", "新北", "TPE", "TSA", "KHH"]],
  ["TZ", ["坦桑尼亚", "Tanzania"]],
  ["UA", ["乌克兰", "Ukraine"]],
  ["UG", ["乌干达", "Uganda"]],
  ["UK", ["英国", "United Kingdom", "英國", "Great Britain", "Britain", "England", "London", "LHR", "LGW"]],
  ["UM", ["美国本土外小岛屿", "U.S. Outlying Islands"]],
  ["US", ["美国", "United States", "美國", "美东", "美東", "美西", "美中", "美南", "Los Angeles", "San Jose", "Silicon Valley", "New York", "Seattle", "Chicago", "Portland", "Dallas", "Ashburn", "NYC", "CHI", "SLC", "LAX", "SFO", "SJC", "SEA", "JFK", "IAD", "ORD"]],
  ["UY", ["乌拉圭", "Uruguay"]],
  ["UZ", ["乌兹别克斯坦", "Uzbekistan"]],
  ["VA", ["梵蒂冈", "Vatican City"]],
  ["VC", ["圣文森特和格林纳丁斯", "St. Vincent & Grenadines"]],
  ["VE", ["委内瑞拉", "Venezuela"]],
  ["VG", ["英属维尔京群岛", "British Virgin Islands"]],
  ["VI", ["美属维尔京群岛", "U.S. Virgin Islands"]],
  ["VN", ["越南", "Vietnam", "Hanoi", "Ho Chi Minh", "河内", "河內", "胡志明"]],
  ["VU", ["瓦努阿图", "Vanuatu"]],
  ["WF", ["瓦利斯和富图纳", "Wallis & Futuna"]],
  ["WS", ["萨摩亚", "Samoa"]],
  ["XK", ["科索沃", "Kosovo"]],
  ["YE", ["也门", "Yemen"]],
  ["YT", ["马约特", "Mayotte"]],
  ["ZA", ["南非", "South Africa"]],
  ["ZM", ["赞比亚", "Zambia"]],
  ["ZW", ["津巴布韦", "Zimbabwe"]]
]);

// Proxy-service node names often contain landing-city/location shorthands (NRT/LAX/NYC...).
// They are useful fallback hints, but are weaker than explicit country/region evidence.
const REGION_LOCATION_FALLBACK_ALIASES = Object.freeze({
  TW: ['Taipei', '台北', '新北', 'TPE', 'TSA', 'KHH'],
  JP: ['东京', '東京', '大阪', 'Tokyo', 'Osaka', 'NRT', 'KIX'],
  KR: ['首尔', '首爾', '春川', 'Seoul', 'Chuncheon', 'ICN', 'GMP'],
  US: ['Los Angeles', 'San Jose', 'Silicon Valley', 'New York', 'Seattle', 'Chicago', 'Portland', 'Dallas', 'Ashburn', 'NYC', 'CHI', 'SLC', 'LAX', 'SFO', 'SJC', 'SEA', 'JFK', 'IAD', 'ORD'],
  UK: ['London', 'LHR', 'LGW'],
  CA: ['Toronto', 'Vancouver', 'YYZ', 'YVR'],
  AU: ['Sydney', 'Melbourne', '悉尼', '墨尔本', '墨爾本', 'SYD', 'MEL'],
  DE: ['Frankfurt', 'Berlin', '法兰克福', '法蘭克福'],
  FR: ['Paris', '巴黎', 'CDG'],
  NL: ['Amsterdam', '阿姆斯特丹', 'AMS'],
  IT: ['Rome', 'Milan', '罗马', '羅馬', '米兰', '米蘭', 'FCO', 'MXP'],
  ES: ['Madrid', 'Barcelona', '马德里', '馬德里', '巴塞罗那', '巴塞羅那', 'MAD', 'BCN'],
  AT: ['Vienna', 'Wien', '维也纳', '維也納', 'VIE'],
  BE: ['Brussels', '布鲁塞尔', '布魯塞爾', 'BRU'],
  BG: ['Sofia', '索非亚', '索菲亞', 'SOF'],
  CY: ['Nicosia', '尼科西亚', '尼科西亞'],
  CZ: ['Prague', '布拉格', 'PRG'],
  DK: ['Copenhagen', '哥本哈根', 'CPH'],
  EE: ['Tallinn', '塔林', 'TLL'],
  GR: ['Athens', '雅典', 'ATH'],
  HR: ['Zagreb', '萨格勒布', '薩格勒布', 'ZAG'],
  HU: ['Budapest', '布达佩斯', '布達佩斯', 'BUD'],
  LT: ['Vilnius', '维尔纽斯', '維爾紐斯', 'VNO'],
  LU: ['LUX'],
  LV: ['Riga', '里加', 'RIX'],
  MT: ['Valletta', '瓦莱塔', '瓦萊塔'],
  PT: ['Lisbon', '里斯本', 'LIS'],
  RO: ['Bucharest', '布加勒斯特', 'OTP'],
  SI: ['Ljubljana', '卢布尔雅那', '盧布爾雅那', 'LJU'],
  SK: ['Bratislava', '布拉迪斯拉发', '布拉迪斯拉發', 'BTS'],
  CH: ['Zurich', '苏黎世', '蘇黎世', 'ZRH'],
  RU: ['Moscow', '莫斯科'],
  TR: ['Istanbul', '伊斯坦布尔', '伊斯坦堡'],
  AE: ['Dubai', '迪拜'],
  IN: ['Mumbai', 'Delhi', '孟买', '孟買', '新德里'],
  MY: ['Kuala Lumpur', '吉隆坡'],
  TH: ['Bangkok', '曼谷'],
  VN: ['Hanoi', 'Ho Chi Minh', '河内', '河內', '胡志明'],
  PH: ['Manila', '马尼拉', '馬尼拉'],
  ID: ['Jakarta', '雅加达', '雅加達'],
  BR: ['São Paulo', 'Sao Paulo', '圣保罗', '聖保羅'],
  MX: ['Mexico City', '墨西哥城'],
  NZ: ['Auckland', '奥克兰', '奧克蘭'],
  SE: ['Stockholm', '斯德哥尔摩', '斯德哥爾摩'],
  NO: ['Oslo', '奥斯陆', '奧斯陸'],
  FI: ['Helsinki', '赫尔辛基', '赫爾辛基'],
  PL: ['Warsaw', '华沙', '華沙'],
  IE: ['Dublin', '都柏林'],
  SG: ['SIN'],
  MO: ['MFM'],
});

const REGION_LOCATION_ALIAS_KEYS = new Set(
  Object.entries(REGION_LOCATION_FALLBACK_ALIASES)
    .flatMap(([region, aliases]) => aliases.map(alias => `${region}\u0000${String(alias).toLowerCase()}`))
);

// Some uppercase 3-letter tokens are both ISO Alpha-3 country codes and common
// landing-location shorthands used by proxy providers. A lone token is genuinely ambiguous.
// We keep both interpretations as fallback votes, so an isolated token ties -> Unknown;
// explicit country/region evidence elsewhere wins before fallback evidence is considered.
const AMBIGUOUS_ALPHA3_LOCATION = Object.freeze({
  FRA: 'DE', // France ISO-3 / Frankfurt shorthand
  HND: 'JP', // Honduras ISO-3 / Tokyo Haneda shorthand
  CAN: 'CN', // Canada ISO-3 / Guangzhou shorthand
  AUS: 'US', // Australia ISO-3 / Austin shorthand
  IND: 'US', // India ISO-3 / Indianapolis shorthand
  MCO: 'US', // Monaco ISO-3 / Orlando shorthand
  PER: 'AU', // Peru ISO-3 / Perth shorthand
  PHL: 'US', // Philippines ISO-3 / Philadelphia shorthand
});

// Precompile alias matchers once; subscriptions can contain hundreds of nodes.
const REGION_ALIAS_MATCHERS = Object.freeze(
  REGION_NAME_ALIASES.flatMap(([region, aliases]) =>
    aliases.map(alias => ({
      region,
      alias,
      kind: REGION_LOCATION_ALIAS_KEYS.has(`${region}\u0000${String(alias).toLowerCase()}`) ? 'location' : 'country',
      re: buildRegionAliasRegex(alias),
    }))
  )
);

const REGION_TAGS = new Set([
  "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW",
  "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN",
  "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG",
  "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ",
  "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI",
  "FJ", "FK", "FM", "FO", "FR", "GA", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM",
  "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT",
  "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO",
  "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB",
  "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF",
  "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV",
  "MW", "MX", "MY", "MZ", "MultiRegion", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
  "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR",
  "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD",
  "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV",
  "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
  "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UK", "UM", "US", "UY", "UZ", "UnknownRegion", "VA",
  "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW"
]);

// Display order is also the human-facing priority inside each category.
const NETWORK_TAG_ORDER = [
  'Residential', 'DedicatedIP', 'StaticIP', 'NativeIP', 'ISP', 'DynamicIP',
  'Mobile', 'Satellite', 'IPv6', 'DedicatedServer',
];
const NETWORK_TAGS = new Set(NETWORK_TAG_ORDER);

const CAPABILITY_TAG_ORDER = [
  'Fast', 'Stable', 'HighBandwidth', 'BulkTraffic', 'Streaming', 'Gaming',
];
const CAPABILITY_TAGS = new Set(CAPABILITY_TAG_ORDER);

const ROUTE_TAG_ORDER = [
  'IEPL', 'IPLC', 'CN2', 'GIA', 'BGP', 'Anycast', 'Relay', 'DirectRoute',
];
const ROUTE_TAGS = new Set(ROUTE_TAG_ORDER);

// Canonical Semantic -> short display label.
const DISPLAY_MAP = Object.freeze({
  MultiRegion: 'Multi',
  UnknownRegion: 'Unknown',
  Residential: 'ResIP',
  StaticIP: 'StaticIP',
  DynamicIP: 'DynIP',
  DedicatedIP: 'DediIP',
  NativeIP: 'NativeIP',
  ISP: 'ISP',
  Mobile: 'Mobile',
  Satellite: 'SatNet',
  IPv6: 'IPv6',
  DedicatedServer: 'DediSrv',
  IEPL: 'IEPL',
  IPLC: 'IPLC',
  CN2: 'CN2',
  GIA: 'GIA',
  BGP: 'BGP',
  Anycast: 'Anycast',
  Relay: 'Relay',
  DirectRoute: 'DirectRt',
  Fast: 'Fast',
  Stable: 'Stable',
  HighBandwidth: 'HighBW',
  BulkTraffic: 'Bulk',
  Streaming: 'Stream',
  Gaming: 'Gaming',
});

const DISPLAY_TO_CANONICAL = Object.freeze(
  Object.fromEntries(Object.entries(DISPLAY_MAP).map(([canonical, display]) => [display, canonical]))
);

const AUTO_DISABLE_VALUES = new Set(['地区', '网络', '线路', '能力', '倍率', '全部']);

function operator(proxies = []) {
  try {
    if (!Array.isArray(proxies) || proxies.length === 0) return proxies || [];

    const config = parseConfig(NS_ARGS);
    const originalInput = proxies.slice();

    // 1) Exclude first, with an all-empty safety guard.
    const exclusion = applyExclude(originalInput, config.excludeKeywords);
    let working = exclusion.kept;
    let excludedNames = exclusion.excludedNames;
    if (originalInput.length > 0 && working.length === 0 && config.excludeKeywords.length > 0) {
      warn(`排除规则会删除全部 ${originalInput.length} 个节点，已触发保护并取消本次排除。`);
      working = originalInput.slice();
      excludedNames = new Set();
    } else if (excludedNames.size > 0) {
      warnIfReferencesExcludedNodes(working, excludedNames);
    }

    // 2) Build names without mutating first, so chain references can be updated safely later.
    const records = working.map((proxy, index) => buildRecord(proxy, index, config));

    // 3) Ensure node names remain unique after standardization.
    ensureUniqueNames(records);

    // 4) Build old -> new mapping. Duplicate old names are ambiguous and are not rewritten.
    const oldNameCounts = new Map();
    for (const record of records) {
      oldNameCounts.set(record.oldName, (oldNameCounts.get(record.oldName) || 0) + 1);
    }
    warnIfAmbiguousReferences(records, oldNameCounts);

    const renameMap = new Map();
    for (const record of records) {
      if (oldNameCounts.get(record.oldName) === 1) {
        renameMap.set(record.oldName, record.newName);
      }
    }

    // 5) Apply new names.
    for (const record of records) {
      record.proxy.name = record.newName;
    }

    // 6) Keep common chain / detour name references in sync.
    for (const record of records) {
      updateProxyReferences(record.proxy, renameMap);
    }

    if (config.debug) {
      log(`Node Standardizer V${NS_VERSION}: 输入 ${originalInput.length}，输出 ${records.length}。`);
    }

    return records.map(r => r.proxy);
  } catch (error) {
    // Fail-soft: classification errors should not break the whole subscription.
    warn(`脚本发生异常，已返回原节点。${error && error.message ? ` ${error.message}` : ''}`);
    return proxies;
  }
}

function parseConfig(args) {
  const debug = parse01(args['调试'], false, '调试');
  const keepOriginal = parse01(args['保留原名'], true, '保留原名');
  const sourceOverride = cleanSource(args['机场']);
  const defaultParsed = parseTagList(args['默认标签'], '默认标签', debug);
  const excludeKeywords = unique(splitStrict(args['排除'], '|'));
  const ignoreKeywords = unique(splitStrict(args['忽略关键词'], '|'));
  const disabledAuto = parseDisabledAuto(args['关闭自动识别'], debug);

  const manualMappings = [];
  for (const [rawKey, rawValue] of Object.entries(args)) {
    if (RESERVED_KEYS.has(rawKey)) continue;

    const key = String(rawKey || '').trim();
    if (!key) continue;

    let canonical = null;
    let multiplier = null;

    if (Object.prototype.hasOwnProperty.call(TAG_DICTIONARY, key)) {
      canonical = TAG_DICTIONARY[key];
    } else {
      multiplier = normalizeMultiplierTag(key);
      if (!multiplier) {
        warn(`未知配置 Key“${key}”，已忽略。V2 左侧只接受表头列出的标准属性 Key 或标准倍率（如 1x）。`);
        continue;
      }
    }

    const keywords = unique(splitStrict(rawValue, '|'));
    if (keywords.length === 0) continue;

    manualMappings.push({
      key,
      canonical,
      multiplier,
      keywords,
    });
  }

  return {
    debug,
    keepOriginal,
    sourceOverride,
    defaultTags: defaultParsed.tags,
    defaultMultiplier: defaultParsed.multiplier,
    excludeKeywords,
    ignoreKeywords,
    disabledAuto,
    manualMappings,
  };
}
function buildRecord(proxy, index, config) {
  const oldName = String(proxy && proxy.name != null ? proxy.name : '').trim();

  const restored = restoreOriginalName(proxy, oldName);
  const originalName = restored.originalName;
  if (!restored.generatedId) rememberOriginalName(proxy, originalName);

  const source = config.sourceOverride
    || cleanSource(restored.managedSource)
    || cleanSource(proxy?._subName)
    || cleanSource(proxy?._subDisplayName)
    || 'UnknownSource';

  // If keepOriginal=0 output was serialized and fed back into this script, the real
  // original name is no longer recoverable. Reuse managed canonical metadata instead
  // of degrading to Unknown. Normal Sub-Store refreshes still start from raw nodes.
  const autoAnalysisName = applyIgnoreKeywords(originalName, config.ignoreKeywords);
  const existingManaged = classifyExistingManagedTags(restored.managedTags, restored.managedRegion);
  let auto;
  if (restored.format === 'v2' && (restored.managedRegion || restored.managedTags?.length)) {
    // V2's left side is trusted canonical metadata. Never re-infer it from Tail, because
    // Tail is explicitly outside the machine-readable boundary and may contain conflicting words.
    // Normal Sub-Store refreshes still start from raw nodes, so detector upgrades can reclassify raw input.
    auto = existingManaged;
  } else if (restored.generatedId && (restored.managedRegion || restored.managedTags?.length)) {
    // Legacy generated-ID input may have lost its original name; preserve managed metadata.
    auto = existingManaged;
  } else {
    const freshAuto = detectAuto(autoAnalysisName, config.disabledAuto);
    auto = restored.format === 'v1'
      ? mergeLegacyManagedWithFreshAuto(existingManaged, freshAuto)
      : freshAuto;
  }

  const defaults = classifyCanonical(config.defaultTags, config.defaultMultiplier);
  const manual = collectManual(originalName, config.manualMappings);

  const region = resolveExclusiveRegion(auto.regions, defaults.regions, manual.regions, config.debug, originalName);
  const multiplier = resolveExclusiveMultiplier(auto.multipliers, defaults.multipliers, manual.multipliers, config.debug, originalName);

  const network = orderedUnion(NETWORK_TAG_ORDER, auto.network, defaults.network, manual.network);
  const capability = orderedUnion(CAPABILITY_TAG_ORDER, auto.capability, defaults.capability, manual.capability);
  const route = orderedUnion(ROUTE_TAG_ORDER, auto.route, defaults.route, manual.route);

  const displayRegion = displayTag(region);
  const displayTags = [
    ...network.map(displayTag),
    ...capability.map(displayTag),
    ...route.map(displayTag),
  ];
  if (multiplier) displayTags.push(multiplier);

  const stableHash = shortHash(proxyFingerprint(proxy, restored.generatedId ? '' : originalName));
  const preservedGeneratedTail = restored.generatedId ? normalizeExistingGeneratedTail(originalName) : '';
  const baseTail = preservedGeneratedTail
    || (config.keepOriginal ? originalName : `#${stableHash.slice(0, 6)}`);

  const newName = formatV2Name(displayRegion, source, displayTags, baseTail);

  if (config.debug) {
    if (autoAnalysisName !== originalName) {
      log(`忽略关键词：${originalName} -> 自动分析文本：${autoAnalysisName}`);
    }
    log(`${oldName || '(空名称)'} -> ${newName}`);
  }

  return {
    proxy,
    index,
    oldName,
    originalName,
    source,
    region,
    network,
    capability,
    route,
    multiplier,
    displayTags,
    baseTail,
    stableHash,
    newName,
  };
}
function mergeLegacyManagedWithFreshAuto(legacy, fresh) {
  return {
    // Fresh detector wins exclusive dimensions when it has usable evidence.
    regions: (fresh.regions && fresh.regions.length) ? fresh.regions : (legacy.regions || []),
    multipliers: (fresh.multipliers && fresh.multipliers.length) ? fresh.multipliers : (legacy.multipliers || []),
    // Additive dimensions keep legacy canonical facts during V1 -> V2 migration.
    network: unique([...(legacy.network || []), ...(fresh.network || [])]),
    route: unique([...(legacy.route || []), ...(fresh.route || [])]),
    capability: unique([...(legacy.capability || []), ...(fresh.capability || [])]),
  };
}

function detectAuto(name, disabledAuto) {
  const result = {
    regions: [],
    network: [],
    route: [],
    capability: [],
    multipliers: [],
  };

  if (!isAutoDisabled(disabledAuto, '地区')) {
    result.regions = detectRegions(name);
  }
  if (!isAutoDisabled(disabledAuto, '网络')) {
    result.network = detectNetworkTags(name);
  }
  if (!isAutoDisabled(disabledAuto, '线路')) {
    result.route = detectRouteTags(name);
  }
  if (!isAutoDisabled(disabledAuto, '能力')) {
    result.capability = detectCapabilityTags(name);
  }
  if (!isAutoDisabled(disabledAuto, '倍率')) {
    result.multipliers = detectMultipliers(name);
  }

  return result;
}

function detectRegions(name) {
  const text = String(name || '');
  if (/(?:cross[-\s]?region|multi[-\s]?region|global\s*pool|跨地区|跨區域|跨区域)/i.test(text)) {
    return ['MultiRegion'];
  }

  // Region resolution is deliberately layered:
  // 1) suppress geographic mentions that only describe a relay/transfer route when possible;
  // 2) explicit country/region evidence wins (flag / ISO-2 / unambiguous ISO-3 / country name);
  // 3) landing-city/location shorthand is only fallback evidence when no strong evidence exists;
  // 4) every surviving mention is one vote; top vote wins, exact top tie -> Unknown via caller.
  const allEvidence = collectRegionEvidence(text);
  if (!allEvidence.length) return [];

  const nonRelayEvidence = allEvidence.filter(item => !isRegionEvidenceInRelayContext(text, item));
  const relayFiltered = nonRelayEvidence.length ? nonRelayEvidence : allEvidence;

  const strongEvidence = relayFiltered.filter(item => item.strength === 'strong');
  const effectiveEvidence = strongEvidence.length ? strongEvidence : relayFiltered;

  const votes = new Map();
  for (const item of effectiveEvidence) {
    votes.set(item.region, (votes.get(item.region) || 0) + 1);
  }
  if (!votes.size) return [];

  const maxVotes = Math.max(...votes.values());
  return [...votes.entries()]
    .filter(([, count]) => count === maxVotes)
    .map(([region]) => region)
    .sort();
}

function collectRegionEvidence(name) {
  const text = String(name || '');
  const evidence = [];

  // 1) Flag Emoji: strong country/region evidence.
  const flagRe = /([\u{1F1E6}-\u{1F1FF}]{2})/gu;
  let fm;
  while ((fm = flagRe.exec(text)) !== null) {
    const rawCode = flagEmojiToAlpha2(fm[1]);
    const region = REGION_ALPHA2_TO_CANONICAL[rawCode];
    if (region) evidence.push({ region, start: fm.index, end: fm.index + fm[0].length, kind: 'flag', strength: 'strong' });
  }

  // 2) ISO Alpha-3. Uppercase-only avoids ordinary English words.
  // Known proxy-location collisions are intentionally NOT treated as strong evidence.
  const code3Re = /(^|[^A-Za-z0-9])([A-Z]{3})(?=$|[^A-Za-z0-9])/g;
  let m3;
  while ((m3 = code3Re.exec(text)) !== null) {
    const token = m3[2];
    const countryRegion = REGION_ALPHA3_TO_CANONICAL[token];
    if (!countryRegion) continue;
    const start = m3.index + m3[1].length;
    const end = start + token.length;
    const locationRegion = AMBIGUOUS_ALPHA3_LOCATION[token];
    if (locationRegion && locationRegion !== countryRegion) {
      evidence.push({ region: countryRegion, start, end, kind: 'alpha3-ambiguous-country', strength: 'fallback' });
      evidence.push({ region: locationRegion, start, end, kind: 'alpha3-ambiguous-location', strength: 'fallback' });
    } else {
      evidence.push({ region: countryRegion, start, end, kind: 'alpha3', strength: 'strong' });
    }
  }

  // 3) ISO Alpha-2: strong evidence. Uppercase-only prevents in/no/to/as in ordinary text.
  const code2Re = /(^|[^A-Za-z0-9])([A-Z]{2})(?=$|[^A-Za-z0-9])/g;
  let m2;
  while ((m2 = code2Re.exec(text)) !== null) {
    const token = m2[2];
    const region = REGION_ALPHA2_TO_CANONICAL[token];
    if (!region) continue;
    const start = m2.index + m2[1].length;
    const end = start + token.length;
    if (isLikelyNonRegionCodeContext(text, start, end, token)) continue;
    evidence.push({ region, start, end, kind: 'alpha2', strength: 'strong' });
  }

  // 4) Human-readable aliases. Country/territory names are strong; cities and landing-location
  // shorthands are fallback only. This preserves provider naming convenience without allowing
  // a city code to overrule an explicit country code/name/flag.
  for (const matcher of REGION_ALIAS_MATCHERS) {
    const { region, alias, kind, re } = matcher;
    re.lastIndex = 0;
    let am;
    while ((am = re.exec(text)) !== null) {
      const matched = am[2] != null ? am[2] : am[0];
      const prefix = am[1] || '';
      const start = am.index + prefix.length;
      evidence.push({
        region,
        start,
        end: start + matched.length,
        kind,
        alias,
        strength: kind === 'location' ? 'fallback' : 'strong',
      });
      if (re.lastIndex === am.index) re.lastIndex++;
    }
  }

  return resolveOverlappingRegionEvidence(evidence);
}

function isLikelyNonRegionCodeContext(text, start, end, token) {
  // GB is also a very common traffic unit. “5.08 GB / 100 GB” must not become UK.
  if (token === 'GB') {
    const before = String(text || '').slice(Math.max(0, start - 16), start);
    if (/\d(?:\.\d+)?\s*$/.test(before)) return true;
  }
  return false;
}

function buildRegionAliasRegex(alias) {
  const escaped = escapeRegExp(String(alias || ''));
  // Latin aliases require letter/digit boundaries. CJK aliases use literal matching;
  // overlap resolution below keeps “巴布亚新几内亚” from also counting “几内亚”.
  if (/^[A-Za-zÀ-ÖØ-öø-ÿ0-9 .,'’()\-]+$/.test(alias)) {
    return new RegExp(`(^|[^A-Za-zÀ-ÖØ-öø-ÿ0-9])(${escaped})(?=$|[^A-Za-zÀ-ÖØ-öø-ÿ0-9])`, 'gi');
  }
  return new RegExp(`()(${escaped})`, 'gi');
}

function resolveOverlappingRegionEvidence(items) {
  const sorted = (items || []).slice().sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    const lenA = a.end - a.start;
    const lenB = b.end - b.start;
    if (lenA !== lenB) return lenB - lenA;
    return String(a.region).localeCompare(String(b.region));
  });

  const kept = [];
  for (const item of sorted) {
    const overlaps = kept.filter(k => item.start < k.end && item.end > k.start);
    if (!overlaps.length) {
      kept.push(item);
      continue;
    }

    // Same textual span/phrase should only be one vote. Prefer the longest geographic phrase.
    const itemLen = item.end - item.start;
    const maxOverlapLen = Math.max(...overlaps.map(k => k.end - k.start));
    if (itemLen > maxOverlapLen) {
      for (let i = kept.length - 1; i >= 0; i--) {
        const k = kept[i];
        if (item.start < k.end && item.end > k.start) kept.splice(i, 1);
      }
      kept.push(item);
    } else if (itemLen === maxOverlapLen) {
      // Equal-length ambiguous aliases are retained if they point at different regions;
      // that naturally becomes a tie instead of silently guessing.
      const exactSameRegion = overlaps.some(k => k.start === item.start && k.end === item.end && k.region === item.region);
      if (!exactSameRegion && !overlaps.some(k => k.start === item.start && k.end === item.end && k.region !== item.region)) {
        kept.push(item);
      } else if (!exactSameRegion && overlaps.some(k => k.start === item.start && k.end === item.end && k.region !== item.region)) {
        kept.push(item);
      }
    }
  }
  return kept.sort((a, b) => a.start - b.start || a.end - b.end);
}

function isRegionEvidenceInRelayContext(name, evidence) {
  const text = String(name || '');
  const after = text.slice(evidence.end, evidence.end + 24);

  // “日本转 / 美国-Transit / 香港 Relay / 美西轉”等明确结构。
  if (/^[\s\-_/.:|]*?(?:中转|中轉|转发|轉發|Transit|Relay)(?=$|[\s\-_/.:|\[\](){}0-9])/i.test(after)) return true;
  if (/^[\s\-_/.:|]*?[转轉](?=$|[\s\-_/.:|\[\](){}0-9])/i.test(after)) return true;

  // Bracketed route labels are common: [美西转] / [日本 Transit].
  const bracketPairs = [['[', ']'], ['【', '】'], ['(', ')'], ['（', '）']];
  for (const [leftChar, rightChar] of bracketPairs) {
    const left = text.lastIndexOf(leftChar, evidence.start);
    if (left < 0) continue;
    const lastRightBefore = text.lastIndexOf(rightChar, evidence.start);
    if (lastRightBefore > left) continue;
    const right = text.indexOf(rightChar, evidence.end);
    if (right < 0) continue;
    const segment = text.slice(left, right + rightChar.length);
    if (/(?:中转|中轉|转发|轉發|Transit|Relay|[转轉](?=[\]】)）\s\-_/.:|0-9]|$))/i.test(segment)) return true;
  }
  return false;
}

function flagEmojiToAlpha2(flag) {
  const points = [...String(flag || '')].map(ch => ch.codePointAt(0));
  if (points.length !== 2) return '';
  if (points.some(cp => cp < 0x1F1E6 || cp > 0x1F1FF)) return '';
  return String.fromCharCode(points[0] - 0x1F1E6 + 65, points[1] - 0x1F1E6 + 65);
}

function detectNetworkTags(name) {
  const rules = [
    ['Residential', /(家宽|家寬|住宅|Residential)/i],
    ['StaticIP', /(Static\s*IP|Fixed\s*IP|固定\s*IP|静态\s*IP|靜態\s*IP)/i],
    ['DynamicIP', /(Dynamic\s*IP|动态\s*IP|動態\s*IP)/i],
    ['DedicatedIP', /(Dedicated\s*IP|独享\s*IP|獨享\s*IP)/i],
    ['NativeIP', /(Native\s*IP|原生\s*IP)/i],
    ['ISP', /(?:^|[^A-Za-z])ISP(?:[^A-Za-z]|$)|运营商\s*IP|運營商\s*IP/i],
    ['Mobile', /(蜂窝(?:网络|網絡|5G|4G)?|蜂窩(?:网络|網絡|5G|4G)?|Cellular(?:\s*(?:Network|5G|4G))?|5G网络|5G網絡|4G网络|4G網絡|(?:^|[^A-Za-z])LTE(?:[^A-Za-z]|$)|Mobile\s*(?:Network|IP)?)/i],
    ['Satellite', /(Starlink|星链|星鏈|卫星网络|衛星網絡)/i],
    ['IPv6', /IPv6/i],
    ['DedicatedServer', /(Bare\s*Metal|Baremetal|Dedicated\s*Server|独立服务器|獨立服務器|独服|獨服)/i],
  ];
  return matchTagRules(name, rules);
}

function detectRouteTags(name) {
  const rules = [
    ['IEPL', /(?:^|[^A-Za-z])IEPL(?:[^A-Za-z]|$)/i],
    ['IPLC', /(?:^|[^A-Za-z])IPLC(?:[^A-Za-z]|$)/i],
    ['CN2', /(?:^|[^A-Za-z0-9])CN2(?:[^A-Za-z0-9]|$)/i],
    ['GIA', /(?:^|[^A-Za-z])GIA(?:[^A-Za-z]|$)/i],
    ['BGP', /(?:^|[^A-Za-z])BGP(?:[^A-Za-z]|$)/i],
    ['Anycast', /Anycast/i],
    ['DirectRoute', /(直连线路|直連線路|Direct\s*Route|DirectRoute)/i],
  ];
  const out = matchTagRules(name, rules);
  if (containsRelaySignal(name)) out.push('Relay');
  return unique(out);
}

function containsRelaySignal(name) {
  const text = String(name || '');
  if (/(?:中转|中轉|转发|轉發|(?:^|[^A-Za-z])Relay(?:[^A-Za-z]|$)|(?:^|[^A-Za-z])Transit(?:[^A-Za-z]|$))/i.test(text)) return true;

  // Region + bare “转/轉” is accepted only when the region evidence is explicit.
  // This avoids treating an arbitrary standalone “转” as Relay and avoids a second
  // geographic scan on the overwhelming majority of ordinary node names.
  if (!/[转轉]/.test(text)) return false;
  const evidence = collectRegionEvidence(text);
  return evidence.some(item => {
    const after = text.slice(item.end, item.end + 16);
    return /^[\s\-_/.:|]*?[转轉](?=$|[\s\-_/.:|\[\](){}0-9])/i.test(after);
  });
}

function detectCapabilityTags(name) {
  const rules = [
    ['Fast', /(?:^|[^A-Za-z])Fast(?:[^A-Za-z]|$)|Speed\s*Priority|速度优先|速度優先/i],
    ['Stable', /(?:^|[^A-Za-z])Stable(?:[^A-Za-z]|$)|Availability\s*Priority|稳定优先|穩定優先|(?:^|[^A-Za-z])Balancer(?:[^A-Za-z]|$)/i],
    ['HighBandwidth', /(High\s*Bandwidth|HighBandwidth|高带宽|高帶寬|不限速|Download\s*Optimized)/i],
    ['BulkTraffic', /(BulkTraffic|Bulk\s*Traffic|大流量)/i],
    // Netflix / NF / 奈飞 are intentionally normalized into Streaming in V2.
    ['Streaming', /(Streaming|流媒体|流媒體|Netflix|奈飞|奈飛|(?:^|[^A-Za-z0-9])NF(?:[^A-Za-z0-9]|$))/i],
    ['Gaming', /Gaming|Game\s*Optimized|游戏(?:优化|優化)?|遊戲(?:优化|優化)?/i],
  ];
  return matchTagRules(name, rules);
}
function detectMultipliers(name) {
  const out = [];
  const text = String(name || '');

  // Auto-detection intentionally does NOT treat a bare prefix form such as X1 as a
  // multiplier, because many providers use X1/N1/F1 as product-series identifiers.
  // Explicit numeric-first forms and explicit “倍率” forms are safe enough to infer.
  const patterns = [
    /(?:^|[^0-9A-Za-z])(\d+(?:\.\d+)?)\s*(?:[xX×]|倍)(?=$|[^0-9A-Za-z])/g,
    /倍率\s*[:：=]?\s*(?:[xX×]\s*)?(\d+(?:\.\d+)?)/g,
  ];

  for (const re of patterns) {
    let m;
    while ((m = re.exec(text)) !== null) {
      const normalized = normalizeMultiplier(m[1]);
      if (normalized) out.push(normalized);
    }
  }

  // Superscript notation such as ˣ² / ˣ¹⁰ is common in subscription names.
  const superscriptRe = /ˣ([⁰¹²³⁴⁵⁶⁷⁸⁹]+)/g;
  let sm;
  while ((sm = superscriptRe.exec(text)) !== null) {
    const normalDigits = superscriptToAscii(sm[1]);
    const normalized = normalizeMultiplier(normalDigits);
    if (normalized) out.push(normalized);
  }

  return unique(out);
}

function superscriptToAscii(value) {
  const table = { '⁰': '0', '¹': '1', '²': '2', '³': '3', '⁴': '4', '⁵': '5', '⁶': '6', '⁷': '7', '⁸': '8', '⁹': '9' };
  return [...String(value || '')].map(ch => table[ch] || '').join('');
}
function collectManual(originalName, mappings) {
  const result = { regions: [], network: [], route: [], capability: [], multipliers: [] };

  for (const mapping of mappings || []) {
    const matched = mapping.keywords.some(keyword => manualKeywordMatches(originalName, keyword));
    if (!matched) continue;

    if (mapping.multiplier) {
      result.multipliers.push(mapping.multiplier);
      continue;
    }

    const classified = classifyCanonical(mapping.canonical ? [mapping.canonical] : [], null);
    result.regions.push(...classified.regions);
    result.network.push(...classified.network);
    result.route.push(...classified.route);
    result.capability.push(...classified.capability);
  }

  result.regions = unique(result.regions);
  result.network = unique(result.network);
  result.route = unique(result.route);
  result.capability = unique(result.capability);
  result.multipliers = unique(result.multipliers);
  return result;
}
function classifyCanonical(tags, multiplier) {
  const result = { regions: [], network: [], route: [], capability: [], multipliers: [] };
  for (const tag of tags || []) {
    if (REGION_TAGS.has(tag)) result.regions.push(tag);
    else if (NETWORK_TAGS.has(tag)) result.network.push(tag);
    else if (ROUTE_TAGS.has(tag)) result.route.push(tag);
    else if (CAPABILITY_TAGS.has(tag)) result.capability.push(tag);
  }
  if (multiplier) result.multipliers.push(multiplier);
  return result;
}

function classifyExistingManagedTags(tags, managedRegion) {
  const result = { regions: [], network: [], route: [], capability: [], multipliers: [] };

  if (managedRegion && REGION_TAGS.has(managedRegion)) {
    result.regions.push(managedRegion);
  }

  for (const rawTag of tags || []) {
    // V1.x Netflix is migrated into Streaming.
    const tag = rawTag === 'Netflix' ? 'Streaming' : rawTag;
    if (REGION_TAGS.has(tag)) result.regions.push(tag);
    else if (NETWORK_TAGS.has(tag)) result.network.push(tag);
    else if (ROUTE_TAGS.has(tag)) result.route.push(tag);
    else if (CAPABILITY_TAGS.has(tag)) result.capability.push(tag);
    else if (/^\d+(?:\.\d+)?x$/i.test(tag)) {
      const m = normalizeMultiplierTag(tag);
      if (m) result.multipliers.push(m);
    } else if (tag === 'Standard') {
      // Legacy V1/V2.0 Standard is intentionally discarded in V2.1+.
    }
  }

  result.regions = unique(result.regions);
  result.network = unique(result.network);
  result.route = unique(result.route);
  result.capability = unique(result.capability);
  result.multipliers = unique(result.multipliers);
  return result;
}
function resolveExclusiveRegion(autoValues, defaultValues, manualValues, debug, name) {
  const levels = [
    ['人工关键词', unique(manualValues)],
    ['默认标签', unique(defaultValues)],
    ['自动识别', unique(autoValues)],
  ];

  for (const [label, values] of levels) {
    if (values.length === 0) continue;
    if (values.length === 1) return values[0];
    if (debug) log(`地区冲突：${name}；${label}同时得到 ${values.join(', ')}，使用 UnknownRegion。`);
    return 'UnknownRegion';
  }
  return 'UnknownRegion';
}

function resolveExclusiveMultiplier(autoValues, defaultValues, manualValues, debug, name) {
  const levels = [
    ['人工关键词', unique(manualValues)],
    ['默认标签', unique(defaultValues)],
    ['自动识别', unique(autoValues)],
  ];

  for (const [label, values] of levels) {
    if (values.length === 0) continue;
    if (values.length === 1) return values[0];
    if (debug) log(`倍率冲突：${name}；${label}同时得到 ${values.join(', ')}，本节点不输出倍率标签。`);
    return null;
  }
  return null;
}

function parseTagList(value, context, debug) {
  const tags = [];
  const multipliers = [];
  if (value == null || value === '' || value === false) return { tags, multiplier: null };

  const rawItems = String(value).split(',').map(v => v.trim()).filter(Boolean);
  for (const item of rawItems) {
    if (Object.prototype.hasOwnProperty.call(TAG_DICTIONARY, item)) {
      tags.push(TAG_DICTIONARY[item]);
      continue;
    }

    const m = normalizeMultiplierTag(item);
    if (m) {
      multipliers.push(m);
      continue;
    }

    warn(`${context} 使用了未定义的标准值“${item}”，已忽略。请从脚本表头字典复制。`);
  }

  const uniqueMultipliers = unique(multipliers);
  let multiplier = null;
  if (uniqueMultipliers.length === 1) {
    multiplier = uniqueMultipliers[0];
  } else if (uniqueMultipliers.length > 1) {
    warn(`${context} 中同时填写多个倍率（${uniqueMultipliers.join(', ')}），该配置项倍率将被忽略。`);
  }

  return { tags: unique(tags), multiplier };
}

function normalizeMultiplierTag(value) {
  const m = String(value).match(/^(\d+(?:\.\d+)?)x$/i);
  return m ? normalizeMultiplier(m[1]) : null;
}

function normalizeMultiplier(numberText) {
  const n = Number(numberText);
  if (!Number.isFinite(n) || n <= 0) return null;
  const normalizedNumber = Number.isInteger(n) ? String(n) : String(n).replace(/0+$/, '').replace(/\.$/, '');
  return `${normalizedNumber}x`;
}

function parseDisabledAuto(value, debug) {
  const set = new Set();
  if (value == null || value === '') return set;

  for (const item of String(value).split(',').map(v => v.trim()).filter(Boolean)) {
    if (AUTO_DISABLE_VALUES.has(item)) set.add(item);
    else warn(`关闭自动识别 中存在未知值“${item}”，已忽略。允许：地区,网络,线路,能力,倍率,全部。`);
  }
  if (debug && set.size) log(`已关闭自动识别：${[...set].join(', ')}`);
  return set;
}

function isAutoDisabled(set, category) {
  return set.has('全部') || set.has(category);
}

function parse01(value, defaultValue, key) {
  if (value == null || value === '') return defaultValue;
  if (value === 1 || value === '1' || value === true || value === 'true') return true;
  if (value === 0 || value === '0' || value === false || value === 'false') return false;
  warn(`${key} 只接受 1 或 0，当前值“${value}”无效，使用默认值 ${defaultValue ? 1 : 0}。`);
  return defaultValue;
}

function escapeRegExp(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function splitStrict(value, separator) {
  if (value == null || value === '') return [];
  return String(value).split(separator).map(v => v.trim()).filter(Boolean);
}

function applyIgnoreKeywords(name, keywords) {
  let text = String(name || '');
  if (!Array.isArray(keywords) || keywords.length === 0) return text;

  // Replace matched fragments with a space instead of deleting them outright.
  // This preserves token boundaries so “JP美西转US” will not accidentally become “JPUS”.
  for (const keyword of keywords) {
    const rawKeyword = String(keyword || '').trim();
    if (!rawKeyword) continue;

    const compactKeyword = rawKeyword.replace(/\s+/g, '');
    if (!compactKeyword) continue;

    // Code-like keywords use alphanumeric boundaries, consistent with manual matching.
    // Example: 忽略关键词=US will match “JP-US-01” but not “BUS-01”.
    if (/^[A-Za-z0-9._-]+$/.test(compactKeyword)) {
      const escaped = compactKeyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`(^|[^A-Za-z0-9])(${escaped})(?=$|[^A-Za-z0-9])`, 'gi');
      text = text.replace(re, (match, prefix) => `${prefix || ''} `);
      continue;
    }

    // Chinese / mixed human-readable phrases use literal substring replacement.
    // Regex meta characters are escaped; user-supplied regular expressions are not supported.
    const escaped = rawKeyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(escaped, 'gi');
    text = text.replace(re, ' ');
  }

  return text.replace(/\s+/g, ' ').trim();
}

function applyExclude(proxies, keywords) {
  if (!keywords.length) return { kept: proxies.slice(), excludedNames: new Set() };
  const normalizedKeywords = keywords.map(normalizeMatchText).filter(Boolean);
  const kept = [];
  const excludedNames = new Set();

  for (const proxy of proxies) {
    const currentName = String(proxy?.name || '');
    const restored = restoreOriginalName(proxy, currentName);
    const normalizedName = normalizeMatchText(restored.originalName);
    const excluded = normalizedKeywords.some(k => normalizedName.includes(k));
    if (excluded) excludedNames.add(currentName);
    else kept.push(proxy);
  }

  return { kept, excludedNames };
}

function warnIfReferencesExcludedNodes(proxies, excludedNames) {
  for (const proxy of proxies) {
    const refs = [];
    for (const field of ['underlying-proxy', 'dialer-proxy', 'detour', 'prev_hop']) {
      if (typeof proxy?.[field] === 'string') refs.push([field, proxy[field]]);
    }
    if (typeof proxy?.chain === 'string') refs.push(['chain', proxy.chain]);
    else if (Array.isArray(proxy?.chain)) {
      for (const ref of proxy.chain) if (typeof ref === 'string') refs.push(['chain', ref]);
    }

    for (const [field, ref] of refs) {
      if (excludedNames.has(ref)) {
        warn(`节点“${proxy.name}”的 ${field} 引用了已被排除的节点“${ref}”，链式关系可能失效。`);
      }
    }
  }
}

function restoreOriginalName(proxy, currentName) {
  // Non-enumerable memory makes sequential runs in the same process fully idempotent.
  if (proxy && typeof proxy.__nodeStandardizerOriginalName === 'string') {
    return {
      originalName: proxy.__nodeStandardizerOriginalName,
      managed: true,
      managedTags: [],
      managedRegion: '',
      managedSource: '',
      generatedId: false,
      format: 'memory',
    };
  }

  const text = String(currentName || '').trim();

  // V2: Region @Source Tag·Tag｜Tail
  const v2 = parseV2Name(text);
  if (v2) {
    const generatedId = /^#[0-9A-F]{6,8}(?:-\d+)?$/i.test(v2.tail);
    return {
      originalName: v2.tail,
      managed: true,
      managedTags: v2.canonicalTags,
      managedRegion: v2.canonicalRegion,
      managedSource: v2.source,
      generatedId,
      format: 'v2',
    };
  }

  // Legacy V1.x: [Tag][Tag][Source:xxx] Original
  let pos = 0;
  let foundSource = false;
  let managedSource = '';
  const managedTags = [];

  while (text[pos] === '[') {
    const end = text.indexOf(']', pos + 1);
    if (end === -1) break;
    const token = text.slice(pos + 1, end);
    pos = end + 1;
    if (token.startsWith('Source:')) {
      foundSource = true;
      managedSource = token.slice('Source:'.length);
      break;
    }
    managedTags.push(token);
  }

  if (foundSource) {
    while (/\s/.test(text[pos] || '')) pos++;
    let originalName = text.slice(pos).trim();
    originalName = originalName.replace(/\s+·NS-[0-9A-F]{8}(?:-\d+)?$/i, '').trim();
    const generatedId = /^Node-[0-9A-F]{8}(?:-\d+)?$/i.test(originalName);
    return {
      originalName,
      managed: true,
      managedTags,
      managedRegion: '',
      managedSource,
      generatedId,
      format: 'v1',
    };
  }

  return {
    originalName: text,
    managed: false,
    managedTags: [],
    managedRegion: '',
    managedSource: '',
    generatedId: false,
    format: 'raw',
  };
}
function displayTag(canonical) {
  return DISPLAY_MAP[canonical] || canonical;
}

function canonicalFromDisplay(display) {
  if (REGION_TAGS.has(display)) return display;
  if (display === 'Multi') return 'MultiRegion';
  if (display === 'Unknown') return 'UnknownRegion';
  return DISPLAY_TO_CANONICAL[display] || null;
}

function normalizeExistingGeneratedTail(value) {
  const text = String(value || '').trim();
  const v2 = text.match(/^#([0-9A-F]{6,8})(?:-(\d+))?$/i);
  if (v2) return `#${v2[1].toUpperCase()}${v2[2] ? `-${v2[2]}` : ''}`;

  const v1 = text.match(/^Node-([0-9A-F]{8})(?:-(\d+))?$/i);
  if (v1) return `#${v1[1].slice(0, 6).toUpperCase()}${v1[2] ? `-${v1[2]}` : ''}`;
  return '';
}

function formatV2Name(displayRegion, source, displayTags, tail) {
  const region = String(displayRegion || 'Unknown').trim() || 'Unknown';
  const safeSource = cleanSource(source) || 'UnknownSource';
  const tags = unique((displayTags || []).map(v => String(v || '').trim()).filter(Boolean));
  const tagArea = tags.length ? ` ${tags.join('·')}` : '';
  const safeTail = String(tail == null ? '' : tail).trim() || '#UNKNOWN';
  return `${region} @${safeSource}${tagArea}｜${safeTail}`;
}

function parseV2Name(text) {
  const value = String(text || '').trim();
  const boundary = value.indexOf('｜');
  if (boundary <= 0) return null;

  const metadata = value.slice(0, boundary).trim();
  const tail = value.slice(boundary + 1).trim();
  // V2.1 allows an empty attribute area: `US @Airport｜Tail`.
  // The optional third group also keeps V2.0 (`... Std｜Tail`) readable for migration.
  const match = metadata.match(/^(\S+)\s+@([^\s｜]+)(?:\s+(.+))?$/);
  if (!match) return null;

  const displayRegion = match[1];
  const source = match[2];
  const displayTags = match[3] ? match[3].split('·').map(v => v.trim()).filter(Boolean) : [];
  const canonicalRegion = canonicalFromDisplay(displayRegion);
  if (!canonicalRegion || !REGION_TAGS.has(canonicalRegion)) return null;

  const canonicalTags = [];
  for (const display of displayTags) {
    const multiplier = normalizeMultiplierTag(display);
    if (multiplier) {
      canonicalTags.push(multiplier);
      continue;
    }
    if (display === 'Std') {
      // Backward compatibility: V2.0 nodes may contain Std.
      // Keep a legacy marker so generated-ID nodes retain managed metadata; output drops it.
      canonicalTags.push('Standard');
      continue;
    }
    const canonical = canonicalFromDisplay(display);
    if (!canonical || REGION_TAGS.has(canonical)) return null;
    canonicalTags.push(canonical);
  }

  return {
    displayRegion,
    canonicalRegion,
    source,
    displayTags,
    canonicalTags,
    tail,
  };
}

function groupRecordsByName(records) {
  const groups = new Map();
  for (const record of records) {
    const list = groups.get(record.newName) || [];
    list.push(record);
    groups.set(record.newName, list);
  }
  return groups;
}

function rememberOriginalName(proxy, originalName) {
  if (!proxy || typeof proxy !== 'object') return;
  try {
    Object.defineProperty(proxy, '__nodeStandardizerOriginalName', {
      value: originalName,
      writable: true,
      configurable: true,
      enumerable: false,
    });
  } catch (_) {
    // Non-critical; fail silently.
  }
}

function ensureUniqueNames(records) {
  if (!records.length) return;

  // First pass: keepOriginal=0 already has #6; different nodes may theoretically collide.
  // For all duplicate formatted names, expand the tail to #8 where possible.
  let groups = groupRecordsByName(records);
  for (const group of groups.values()) {
    if (group.length <= 1) continue;
    for (const record of group) {
      if (/^#[0-9A-F]{6}$/i.test(record.baseTail)) {
        record.baseTail = `#${record.stableHash}`;
        record.newName = formatV2Name(displayTag(record.region), record.source, record.displayTags, record.baseTail);
      }
    }
  }

  // Second pass: remaining duplicates (usually same original name) get a stable identity suffix.
  groups = groupRecordsByName(records);
  for (const group of groups.values()) {
    if (group.length <= 1) continue;

    // If Tail is a real original name, add #6/#8 after it. If it is already an ID,
    // use the existing ID and only add an ordinal when the proxies are truly identical.
    const hashCounts = new Map();
    for (const record of group) {
      hashCounts.set(record.stableHash, (hashCounts.get(record.stableHash) || 0) + 1);
    }

    const seenHash = new Map();
    for (const record of group) {
      let tail;
      if (/^#[0-9A-F]{6,8}$/i.test(record.baseTail)) {
        tail = `#${record.stableHash}`;
      } else {
        const shortId = record.stableHash.slice(0, 6);
        tail = `${record.baseTail} #${shortId}`;
      }

      const sameHashCount = hashCounts.get(record.stableHash) || 0;
      if (sameHashCount > 1) {
        const n = (seenHash.get(record.stableHash) || 0) + 1;
        seenHash.set(record.stableHash, n);
        if (n > 1) tail += `-${n}`;
      }

      record.newName = formatV2Name(displayTag(record.region), record.source, record.displayTags, tail);
    }
  }

  // Final hard guard. Order-based suffix is used only for completely indistinguishable duplicates.
  const used = new Set();
  for (const record of records) {
    let candidate = record.newName;
    let n = 2;
    while (used.has(candidate)) {
      const parsed = parseV2Name(candidate);
      const tail = parsed ? `${parsed.tail}-${n++}` : `${candidate}-${n++}`;
      candidate = parsed
        ? formatV2Name(parsed.displayRegion, parsed.source, parsed.displayTags, tail)
        : tail;
    }
    used.add(candidate);
    record.newName = candidate;
  }
}
function warnIfAmbiguousReferences(records, oldNameCounts) {
  const ambiguous = new Set(
    [...oldNameCounts.entries()].filter(([, count]) => count > 1).map(([name]) => name)
  );
  if (!ambiguous.size) return;

  for (const record of records) {
    const proxy = record.proxy;
    const refs = [];
    for (const field of ['underlying-proxy', 'dialer-proxy', 'detour', 'prev_hop']) {
      if (typeof proxy?.[field] === 'string') refs.push([field, proxy[field]]);
    }
    if (typeof proxy?.chain === 'string') refs.push(['chain', proxy.chain]);
    else if (Array.isArray(proxy?.chain)) {
      for (const ref of proxy.chain) if (typeof ref === 'string') refs.push(['chain', ref]);
    }

    for (const [field, ref] of refs) {
      if (ambiguous.has(ref)) {
        warn(`节点“${record.oldName}”的 ${field} 引用了重名节点“${ref}”。标准化后无法可靠判断应指向哪一个，已保留原引用，请先消除原订阅重名或在标准化后建立链式关系。`);
      }
    }
  }
}
function proxyFingerprint(proxy, originalName) {
  const pluginOpts = proxy?.['plugin-opts'] || {};
  const wsOpts = proxy?.['ws-opts'] || {};
  const grpcOpts = proxy?.['grpc-opts'] || {};
  const obfsOpts = proxy?.['obfs-opts'] || {};
  const parts = [
    originalName,
    proxy?.type,
    proxy?.server,
    proxy?.port,
    proxy?.plugin,
    pluginOpts?.host,
    proxy?.sni,
    proxy?.servername,
    proxy?.network,
    wsOpts?.path,
    wsOpts?.headers?.Host,
    grpcOpts?.['grpc-service-name'],
    obfsOpts?.host,
  ];
  return parts.map(v => v == null ? '' : String(v)).join('|');
}

function shortHash(text) {
  let hash = 0x811c9dc5;
  const str = String(text || '');
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).toUpperCase().padStart(8, '0');
}

function updateProxyReferences(proxy, renameMap) {
  if (!proxy || typeof proxy !== 'object' || renameMap.size === 0) return;
  const stringFields = ['underlying-proxy', 'dialer-proxy', 'detour', 'prev_hop'];
  for (const field of stringFields) {
    if (typeof proxy[field] === 'string' && renameMap.has(proxy[field])) {
      proxy[field] = renameMap.get(proxy[field]);
    }
  }

  if (typeof proxy.chain === 'string' && renameMap.has(proxy.chain)) {
    proxy.chain = renameMap.get(proxy.chain);
  } else if (Array.isArray(proxy.chain)) {
    proxy.chain = proxy.chain.map(v => typeof v === 'string' && renameMap.has(v) ? renameMap.get(v) : v);
  }
}

function orderedUnion(order, ...lists) {
  const set = new Set();
  for (const list of lists) {
    for (const item of list || []) set.add(item);
  }
  return order.filter(item => set.has(item));
}

function matchTagRules(name, rules) {
  const out = [];
  for (const [tag, re] of rules) {
    if (re.test(name)) out.push(tag);
  }
  return unique(out);
}

function manualKeywordMatches(name, keyword) {
  const rawKeyword = String(keyword || '').trim();
  if (!rawKeyword) return false;

  const compactName = String(name || '').replace(/\s+/g, '');
  const compactKeyword = rawKeyword.replace(/\s+/g, '');

  // Provider codes and code-like literals (aa, B1, US-P, premium-us...) use
  // alphanumeric boundaries. This avoids X matching 1x and US-P matching BUS-P.
  if (/^[A-Za-z0-9._-]+$/.test(compactKeyword)) {
    const escaped = compactKeyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(^|[^A-Za-z0-9])${escaped}([^A-Za-z0-9]|$)`, 'i');
    return re.test(compactName);
  }

  return normalizeMatchText(name).includes(normalizeMatchText(rawKeyword));
}
function normalizeMatchText(value) {
  return String(value || '').toLowerCase().replace(/\s+/g, '');
}

function cleanSource(value) {
  if (value == null) return '';
  let text = String(value).normalize ? String(value).normalize('NFKC') : String(value);
  text = text
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/[\s@·｜|#]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .trim();
  return text;
}
function unique(values) {
  return [...new Set((values || []).filter(Boolean))];
}

function log(message) {
  try { console.log(`[NodeStandardizer] ${message}`); } catch (_) {}
}

function warn(message) {
  try { console.warn(`[NodeStandardizer] ${message}`); } catch (_) {
    try { console.log(`[NodeStandardizer][WARN] ${message}`); } catch (_) {}
  }
}
