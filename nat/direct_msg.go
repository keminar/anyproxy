package nat

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
)

// QUIC 直连的信令方法。数据面完全不经服务端, 服务端只负责在两个订阅方之间
// 转交下面这几条控制消息(见 nat/direct_broker.go)。
//
// 一次直连的完整时序(请求驱动, C 平时不占端口):
//
//	A --d_request--> B     A 有入口连接进来, 报上自己的端点和本次 token
//	B --d_punch-->   C     有人要连你: 起监听 -> 探测自己的端点 -> 朝它打洞
//	C --d_ready-->   B     C 回自己的端点+证书指纹(或失败原因)
//	B --d_offer-->   A     B 把 C 的端点转给 A
//	A ==QUIC 直连==> C     A 拨号, 流首部带 token 与 port
//
// A 声明 TwoPhase 且走中继(DirectRequest.Via 非空)时, 这条链更长, 而且 B 会把 offer 拆成
// 两段发, 好让 A 的打洞与 C 的信令重叠(详见 DirectRequest.TwoPhase):
//
//	A --d_request(Via)--> B   A 要求经 VPS 盲转发
//	B --d_relay_open--> VPS   VPS 开专用 socket、探到自己的公网中继端点 E
//	B --d_offer(E, 半截)--> A **第一段**: 只有 E, 指纹还没到 —— A 立刻朝 E 打洞 + nudge
//	B --d_punch(E)-->   C     C 朝 E 打洞, 并回自己的候选与指纹
//	C --d_ready-->      B
//	B --d_offer(E+指纹)--> A  **第二段**: 指纹到齐, A 按打洞结果择路拨号
//	A ==经 VPS 盲转发==> C
//
// 为什么是请求驱动而不是 C 一上线就通告:
//   - C 平时不必占着 UDP 端口和监听, 空闲时零后台流量;
//   - 端点是**当场探的**, 不存在"通告完就过期"的窗口 —— 外网地址(隐私临时地址轮换)
//     和外网端口(NAT 映射老化重建)都可能变, 缓存下来的端点随时可能是死的。
//
// 其中 d_punch 这步是必需的: IPv6 虽然没有 NAT, 但家用路由器默认对 IPv6 开有状态
// 防火墙、拦截主动入站, C 必须先朝 A 发包, 才能在自己这侧开出返回通道。
const (
	METHOD_DIRECT_REQUEST  = "d_request"  //A -> B
	METHOD_DIRECT_PUNCH    = "d_punch"    //B -> C
	METHOD_DIRECT_READY    = "d_ready"    //C -> B
	METHOD_DIRECT_OFFER    = "d_offer"    //B -> A
	METHOD_DIRECT_PUNCHING = "d_punching" //A -> B -> C: A 已开打, 让 C 现在打(见 DirectPunching)

	// METHOD_DIRECT_RELAY_OPEN 是 VPS 盲转发中继唯一新增的信令(B -> VPS): 让 VPS 为这一对
	// A-C 开一个专用 UDP socket、问反射器探到自己的公网中继端点 E, 用 d_ready 把 E 报回。
	// 其余中继信令全部复用现有直连信令(d_request 加 Via、d_punch 加 Relay/Email 转达候选与
	// 打洞、d_offer 把 E 给 A、d_punching 两腿的 nudge)。详见 docs/direct-relay-design.md。
	METHOD_DIRECT_RELAY_OPEN = "d_relay_open" //B -> VPS
)

// isDirectMethod 判断是否为直连信令, 用于在读消息时与数据面消息分流。
func isDirectMethod(method string) bool {
	switch method {
	case METHOD_DIRECT_REQUEST, METHOD_DIRECT_PUNCH, METHOD_DIRECT_READY, METHOD_DIRECT_OFFER,
		METHOD_DIRECT_PUNCHING, METHOD_DIRECT_RELAY_OPEN:
		return true
	}
	return false
}

// DirectReady C 收到 punch 后的回复: 监听已就绪, 这是我的端点。
//
// Endpoint 是**C 用 QUIC 那个 socket 当场问 UDP 反射器要来的**完整地址+端口, 不是本机
// 自报, 也不是服务端从 websocket 连接上观测的 —— websocket 是 TCP、是另一个 socket,
// 而一台机器可能同时持有多个全局 IPv6 地址(含会轮换的隐私临时地址), 内核按 RFC 6724
// 按目的地分别选源; 外网端口同理由沿途 NAT/端口映射决定。详见 nat/direct_reflect.go。
type DirectReady struct {
	// Candidates 是 C 的全部候选端点(IPv4 / IPv6 / 端口映射 / 本机接口地址), A 会朝
	// 它们同时打, 谁先通谁被观测到, 都通则按 RTT + 地址类型偏置择优。
	Candidates  []directCandidate `json:"candidates"`
	Fingerprint string            `json:"fingerprint"` //自签证书的 SHA-256 指纹, 供对端固定校验
	Err         string            `json:"err"`         //非空表示 C 这边没法接受直连(没开 directAccept 等)

	// Endpoint 是 Candidates 出现之前的单端点字段, 只为兼容旧版对端而保留(填第一条
	// 候选)。新版两边都优先看 Candidates。
	Endpoint string `json:"endpoint,omitempty"`
}

// DirectRequest A 向服务端申请连接某个 email 的订阅方。
type DirectRequest struct {
	Email      string            `json:"email"`      //目标订阅方
	Port       uint16            `json:"port"`       //要用对方 client.forward 里的哪条规则
	Token      string            `json:"token"`      //本次会话的一次性凭证, A 生成, 经 B 转交给 C, 最后由 A 在 QUIC 流首部出示
	Candidates []directCandidate `json:"candidates"` //A 的全部候选端点, 供 C 朝它们同时打洞

	// Endpoint 同 DirectReady.Endpoint, 只为兼容旧版对端。
	Endpoint string `json:"endpoint,omitempty"`

	// Encrypt 为 true 表示 A 这台机器开启了 websocket.client.directEncrypt, 要求本次
	// 会话的 PUNCH/PONG 加密。密钥从本次 token 派生(不用 uuid), 见 nat/direct_crypto.go。
	Encrypt bool `json:"encrypt,omitempty"`

	// PunchFirst 为 true 表示发起方 A 在受限 CGNAT 后(配了 directPunchFirst), 要求本次
	// 由 A 先打洞、接受方 C 推迟自己的打洞(见 docs/direct-punch-order.md)。
	PunchFirst bool `json:"punchFirst,omitempty"`

	// Via 非空表示 A 要经这个 email 对应的 VPS 做盲转发中继到 Email(最终目标 C), 而非直连。
	// B 见 Via 非空即进中继模式(见 nat/direct_broker.go 的 onRelayRequest)。取自
	// conf.ClientDirect.Via。详见 docs/direct-relay-design.md。
	Via string `json:"via,omitempty"`

	// TwoPhase 为 true 表示 A 支持**两段式 offer**(见 DirectOffer.EndpointOnly): 中继会话
	// 里 B 先把中继端点 E 单独发来, A 立刻开始打洞, C 的证书指纹随后随完整 offer 补发。
	// 这一段重叠省掉的正是"等 C 打完洞、信令绕回来"的时间(实测秒级)。
	//
	// 做成"由 A 声明"的能力位而不是服务端直接发两段: 老 A 遇到两段式会在第一段(无指纹)上
	// 判成 incomplete offer, 直接连不上; 声明之后, 老 A 只会在老服务端/直连路径上收到一段
	// 完整的 offer, 行为与以前完全一致。新 A 遇老服务端同理(收不到半截 offer, 照旧一段)。
	TwoPhase bool `json:"twoPhase,omitempty"`
}

// DirectPunch 服务端转交给 C 的连接请求。
//
// 不带发起方的文件传输身份: 那部分声明改由 A 直接在已加密的 QUIC 流里自己带上
// (见 nat/file.go 的 fileAuth), 不需要 B 在信令里额外转告——B 本就不该知道这些。
//
// 但下面的 Email 字段例外: 它不是"身份声明"本身, 只是 B 处理 onRequest 时已经必然
// 知道的事实("c.Email 要连 req.Email")的透传, 用于 C 在打洞开始前(此时还没有任何
// 加密通道)就能按 email 查 receive.allow 得到 A 的 uuid, 从而派生出与 A 一致的
// 打洞会话密钥, 不需要另起一轮密钥交换。这是 B 自己认证过的 c.Email, 不是 A 自报的,
// 不可被 A 伪造成别的 email。
type DirectPunch struct {
	PeerAddrs []directCandidate `json:"peerAddrs"` //A 的全部候选端点, C 朝它们同时打洞
	Token     string            `json:"token"`     //期望 A 出示的凭证
	Port      uint16            `json:"port"`      //A 要访问的转发规则端口, 0 表示文件传输

	// PeerAddr 同 DirectReady.Endpoint, 只为兼容旧版对端。
	PeerAddr string `json:"peerAddr,omitempty"`

	// Email 是 B 已认证过的 A 的 email(即 onRequest 里的 c.Email), 由 B 现填。
	//
	// 中继腿(Relay=true, B->VPS)里 Email 另有一层用途: 标明这条 d_punch 是"哪条腿"的
	// 候选——VPS 有 A、C 两条腿, 都用同一个 token, 靠 Email 区分登记的是谁、以及收到
	// 哪条腿的 nudge 时该朝谁主动发包(见 nat/direct_relay.go 的 registerRelayLeg/
	// fireRelayLeg)。
	Email string `json:"email,omitempty"`
	// Encrypt 原样透传自 DirectRequest.Encrypt。
	Encrypt bool `json:"encrypt,omitempty"`
	// PunchFirst 原样透传自 DirectRequest.PunchFirst: A 要求先打, C 推迟自己的打洞。
	PunchFirst bool `json:"punchFirst,omitempty"`

	// Relay 为 true 表示这是 VPS 盲转发中继里的一条打洞腿:
	//   - B -> VPS 时: PeerAddrs 是某个居民(A 或 C, 由 Email 标明)的候选, VPS 只登记,
	//     停着等这条腿的 nudge 才朝它主动发包(见 direct_relay.go 的 registerRelayLeg/
	//     punchLeg), 且 VPS 不是"接受 QUIC 监听", 只盲转发。
	//   - B -> C 时: PeerAddrs 是 VPS 的中继端点 E, C(是居民、必先发)主动朝 E 打洞并
	//     **主动**发一个 nudge(见 DirectPunching), 让 VPS 知道可以朝 C 打回来了; 之后
	//     接受经 VPS 转来的 e2e QUIC。
	// 详见 docs/direct-relay-design.md。
	Relay bool `json:"relay,omitempty"`
}

// DirectRelayOpen B -> VPS: 让 VPS 为本次会话(Token)开一个专用中继 socket、探到自己的
// 公网中继端点 E, 用 d_ready(Candidates=[E], 无 Fingerprint)把 E 报回 B。这是整套中继里
// 唯一新增的信令类型。VPS 记住 Token->socket, 之后按 B 转来的 d_punch(Relay=true)朝 A、C
// 两腿打洞并盲转发。详见 docs/direct-relay-design.md。
type DirectRelayOpen struct {
	Token string `json:"token"` //本次中继会话标识, 与 A 的 DirectRequest.Token 一致
}

// DirectPunching A(发起方)开打后发出的 nudge: A -> B -> C, 通知 C"我已开始打洞, 你
// 现在可以打了"。仅在 A 设了 directPunchFirst(A 在受限 CGNAT 后、必须先打)时发。
//
// 为什么要它: order Y 里 A 必须先发出第一个包, C 才能后打(否则 A 的 CGNAT 映射被 C 先
// 到的包毒化)。但 A 只有拿到 offer 才知道 C 的地址、才开始打, C 却在更早的 d_punch 时
// 就想打——只能让 C 先"停下等信号"。这个 nudge 就是那个信号: A 一开打就发, 经 B 路由到
// C(按 Email 找 C), C 用 Token 对上自己停着的那次打洞、立即打。见 docs/direct-punch-order.md。
//
// A -> B 时带 Email(供 B 路由到 C)与 Token; B -> C 时 Email 可省(只需 Token 对上)。
//
// 中继场景里 nudge 的路由与语义不同(见 nat/direct_relay.go、direct_broker.go 的 onPunching):
// A、C 两个居民都朝 VPS 的中继端点打洞, 且都要先打, 所以两腿各发一个 nudge 给 VPS。B 按
// Token 认出这是中继会话, 把 nudge 转给 VPS 并**保留发出方的 email**(A 的或 C 的), VPS 靠
// 这个 email 认出是"哪条腿"该打回去。
type DirectPunching struct {
	Email string `json:"email,omitempty"` //A->B: 目标订阅方(C)供 B 路由; 中继腿里则是发出方(A/C)自己的 email
	Token string `json:"token"`           //与对端停着的那次打洞的 token 对上
}

// DirectOffer 服务端回给 A 的结果。Err 非空表示这次直连没法建立(对方不在线、没开
// directAccept 等), 此时按"直接失败"处理, 不做中继回落。
type DirectOffer struct {
	PeerAddrs   []directCandidate `json:"peerAddrs"`   //C 的全部候选端点
	Fingerprint string            `json:"fingerprint"` //C 的证书指纹
	Err         string            `json:"err"`         //非空即失败原因

	// PeerAddr 同 DirectReady.Endpoint, 只为兼容旧版对端。
	PeerAddr string `json:"peerAddr,omitempty"`

	// EndpointOnly 为 true 表示**这是两段式 offer 的第一段**: 只给端点(中继场景里就是 E),
	// 证书指纹还没到(Fingerprint 为空)。A 收到即可开始打洞, 再等第二段(完整 offer, 带指纹)
	// 才拨号。这么拆是为了让"A 打洞"与"C 那边的信令 + 打洞"重叠 —— 中继会话里那一段是
	// 秒级的, 见 DirectRequest.TwoPhase 与 docs/direct-relay-design.md。
	//
	// 只有在 A 声明了 TwoPhase 时服务端才会发这种半截 offer, 所以老 A 永远收不到它。
	EndpointOnly bool `json:"endpointOnly,omitempty"`
}

// mergeCandidates 把新旧两种字段合成一份候选列表。旧版对端只会填单端点字段, 新版两个
// 都填(单端点填第一条), 所以这里以列表为主、单端点兜底, 再去重。
func mergeCandidates(list []directCandidate, single string) []directCandidate {
	if single != "" {
		list = append(list, directCandidate{Addr: single, Source: candSrcReflectV6})
	}
	return dedupCandidates(list)
}

// firstAddr 取列表里第一条地址, 用于填兼容字段。
func firstAddr(cands []directCandidate) string {
	if len(cands) == 0 {
		return ""
	}
	return cands[0].Addr
}

// newDirectToken 生成一次性会话凭证。
func newDirectToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// 控制消息体统一用 JSON 塞进 Message.Body: 量很小, 且出问题时日志里直接可读,
// 不像 gob 那样还要解码才能看。
func encodeDirect(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func decodeDirect(body []byte, v interface{}) error {
	return json.Unmarshal(body, v)
}
