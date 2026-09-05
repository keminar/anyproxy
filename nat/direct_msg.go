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
// 为什么是请求驱动而不是 C 一上线就通告:
//   - C 平时不必占着 UDP 端口和监听, 空闲时零后台流量;
//   - 端点是**当场探的**, 不存在"通告完就过期"的窗口 —— 外网地址(隐私临时地址轮换)
//     和外网端口(NAT 映射老化重建)都可能变, 缓存下来的端点随时可能是死的。
//
// 其中 d_punch 这步是必需的: IPv6 虽然没有 NAT, 但家用路由器默认对 IPv6 开有状态
// 防火墙、拦截主动入站, C 必须先朝 A 发包, 才能在自己这侧开出返回通道。
const (
	METHOD_DIRECT_REQUEST = "d_request" //A -> B
	METHOD_DIRECT_PUNCH   = "d_punch"   //B -> C
	METHOD_DIRECT_READY   = "d_ready"   //C -> B
	METHOD_DIRECT_OFFER   = "d_offer"   //B -> A
)

// isDirectMethod 判断是否为直连信令, 用于在读消息时与数据面消息分流。
func isDirectMethod(method string) bool {
	switch method {
	case METHOD_DIRECT_REQUEST, METHOD_DIRECT_PUNCH, METHOD_DIRECT_READY, METHOD_DIRECT_OFFER:
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
}

// DirectPunch 服务端转交给 C 的连接请求。
type DirectPunch struct {
	PeerAddrs []directCandidate `json:"peerAddrs"` //A 的全部候选端点, C 朝它们同时打洞
	Token     string            `json:"token"`     //期望 A 出示的凭证
	Port      uint16            `json:"port"`      //A 要访问的转发规则端口, 0 表示文件传输
	FromEmail string            `json:"fromEmail"` //发起方身份, 由服务端填(C 自己看不到对端是谁)

	// PeerAddr 同 DirectReady.Endpoint, 只为兼容旧版对端。
	PeerAddr string `json:"peerAddr,omitempty"`
}

// DirectOffer 服务端回给 A 的结果。Err 非空表示这次直连没法建立(对方不在线、没开
// directAccept 等), 此时按"直接失败"处理, 不做中继回落。
type DirectOffer struct {
	PeerAddrs   []directCandidate `json:"peerAddrs"`   //C 的全部候选端点
	Fingerprint string            `json:"fingerprint"` //C 的证书指纹
	Err         string            `json:"err"`         //非空即失败原因

	// PeerAddr 同 DirectReady.Endpoint, 只为兼容旧版对端。
	PeerAddr string `json:"peerAddr,omitempty"`
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
