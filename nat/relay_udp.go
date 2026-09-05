package nat

import (
	"encoding/binary"
	"errors"
	"time"
)

// UDP 中继(路径 B 的第二条通道)。
//
// 现有的中继路径只有 TCP: 入口在 B 上起 net.Listen("tcp"), 数据经 websocket 转给 C。
// 这里补一条**并行**的 UDP 通道, 两条各走各的:
//
//	mstsc --TCP 3389--> B:2222 --websocket(TCP)--> C --> 127.0.0.1:3389   (原有)
//	mstsc --UDP 3389--> B:2222 ====UDP============> C --> 127.0.0.1:3389   (本文件)
//
// 关键是 UDP 全程还是 UDP。把 UDP 塞进 websocket 是行不通的 —— websocket 跑在 TCP 上,
// 等于给每个数据报重新套上重传和保序, 丢一个包后面已经到达的帧全得排队等它, 正是
// RDP 的 UDP 通道特意要绕开的东西, 只会比纯 TCP 更卡。
//
// 三段都是 UDP, 且两头都由 NAT 内侧主动发起, 所以中间不需要打洞:
//
//	A(mstsc) --> B    A 主动发, B 是公网, 天然可达
//	C        --> B    C 主动发, 在自己 NAT 上开出映射; B 之后就能顺着这条映射回发
//
// C 的上行 socket 是**请求驱动**的, 和直连那边一个思路: B 收到第一个客户端数据报时
// 才通过 websocket 让 C 建上行(u_open), 空闲一段后 C 自己撤掉。这样 C 平时不占端口、
// 不发保活包; 代价是第一个数据报要等一个 B->C->B 的来回, 而 RDP 的 UDP 通道是在 TCP
// 主通道之后才协商的, 本来就有富余, 且它自己会重试。
const (
	METHOD_RELAY_UDP_OPEN  = "u_open"  //B -> C, 让 C 建上行
	METHOD_RELAY_UDP_READY = "u_ready" //C -> B, 报告建上行的结果
)

// isRelayUDPMethod 判断是否为 UDP 中继信令, 用于在读消息时与数据面消息分流。
func isRelayUDPMethod(method string) bool {
	return method == METHOD_RELAY_UDP_OPEN || method == METHOD_RELAY_UDP_READY
}

// RelayUDPOpen B 让 C 建上行。
//
// 只给端口不给地址: C 该往哪个主机发, 用它自己 websocket 配置里的 connect 主机就行,
// 那是它确实连得通的地址; 让 B 自报公网地址反而容易报错(B 可能在 NAT/负载均衡后面,
// 也可能有多个出口地址)。
type RelayUDPOpen struct {
	Port  uint16 `json:"port"`  //B 上这条中继入口的端口, 同时也是 C 要查的 client.forward 端口
	Token string `json:"token"` //一次性凭证, C 在注册包里原样出示, 防止别人冒充上行
}

// RelayUDPReady C 回报结果。Err 非空表示这条中继建不起来(没配 forward 目标、发不出包等),
// B 据此立刻放弃并打日志, 而不是让客户端干等到超时。
type RelayUDPReady struct {
	Port uint16 `json:"port"`
	Err  string `json:"err"`
}

const (
	// relayUDPMagic B<->C 上行包的头一个字节。客户端(mstsc)的数据报是裸 RDP-UDP,
	// 不会带它; B 靠"魔数 + 来源等于已注册的上行端点"来区分两类包, 两个条件都要满足。
	relayUDPMagic = 0xA5

	relayKindRegister  = 1 //C -> B, 注册上行, payload 是 token
	relayKindKeepalive = 2 //C -> B, 保活, 维持 C 侧 NAT 映射
	relayKindData      = 3 //双向, payload 是原始数据报
	relayKindClose     = 4 //B -> C, 会话结束, C 可以关掉对应的本地 socket

	// relayUDPHeadLen 上行包定长头: magic(1) + kind(1) + session(4) + port(2)。
	//
	// port 每个数据报都带, 不只带在首包: UDP 会乱序, 首包未必先到, 把"这条会话用哪个
	// forward 端口"绑在首包上, 一旦乱序就查不到目标。多这 2 字节不值得省。
	relayUDPHeadLen = 8
)

const (
	// relayUDPBufSize 单个数据报的读缓冲。RDP-UDP 实际负载在 1200 上下, 这里留到
	// 64KB 以免截断别的用途(截断的表现是静默的数据损坏, 比丢包难查得多)。
	relayUDPBufSize = 64 * 1024

	// relayUDPKeepalive C 维持上行 NAT 映射的保活间隔。常见 UDP 映射老化在 30s 上下,
	// 取 20s 留出余量。只在上行存在时发, 上行是按需建的, 所以空闲时没有后台流量。
	relayUDPKeepalive = 20 * time.Second

	// relayUDPOpenWait B 等 C 建上行的上限。信令走已建立的 websocket, 正常是毫秒级。
	relayUDPOpenWait = 8 * time.Second

	// relayUDPPendingMax 等上行期间为一条中继暂存的数据报个数。存在的意义只是别把
	// 握手头几个包丢光, 不是做缓冲区 —— 存太多只会在上行始终建不起来时白占内存,
	// 而且积压的老包发出去对 RDP 也没有价值。
	relayUDPPendingMax = 16

	// relayUDPSessionIdle 一条会话(一个客户端端点)多久没有数据就回收。
	//
	// 取 30 分钟而不是几十秒: mstsc 挂着没人操作时 UDP 通道可以长时间一个包都没有,
	// 按短空闲回收会把好端端的会话掐掉, 用户回来一动鼠标才发现要重连。
	relayUDPSessionIdle = 30 * time.Minute

	// relayUDPReapEvery 空闲回收的检查间隔。
	relayUDPReapEvery = 60 * time.Second
)

var errRelayUDPShort = errors.New("relay udp packet too short")

// relayUDPHead 上行包头。
type relayUDPHead struct {
	kind    byte
	session uint32
	port    uint16
}

// encodeRelayUDP 拼一个上行包。payload 可为空(保活/关闭)。
func encodeRelayUDP(h relayUDPHead, payload []byte) []byte {
	buf := make([]byte, relayUDPHeadLen+len(payload))
	buf[0] = relayUDPMagic
	buf[1] = h.kind
	binary.BigEndian.PutUint32(buf[2:6], h.session)
	binary.BigEndian.PutUint16(buf[6:8], h.port)
	copy(buf[relayUDPHeadLen:], payload)
	return buf
}

// decodeRelayUDP 解一个上行包。返回的 payload 是入参的切片, 调用方要自己复制后再留存。
func decodeRelayUDP(buf []byte) (relayUDPHead, []byte, error) {
	if len(buf) < relayUDPHeadLen || buf[0] != relayUDPMagic {
		return relayUDPHead{}, nil, errRelayUDPShort
	}
	h := relayUDPHead{
		kind:    buf[1],
		session: binary.BigEndian.Uint32(buf[2:6]),
		port:    binary.BigEndian.Uint16(buf[6:8]),
	}
	return h, buf[relayUDPHeadLen:], nil
}

// hasRelayUDPMagic 快速判断一个包**看起来**像上行包。只是必要条件, 调用方还要核对来源
// 端点或 token, 否则任何人发个 0xA5 开头的包就能冒充 C。
func hasRelayUDPMagic(buf []byte) bool {
	return len(buf) >= relayUDPHeadLen && buf[0] == relayUDPMagic
}
