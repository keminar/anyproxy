package nat

import (
	"bytes"
	"encoding/gob"
)

// METHOD_CREATE 创建连接命令
const METHOD_CREATE = "create"

// METHOD_CLOSE 关闭连接命令
const METHOD_CLOSE = "close"

// 连接类型: 与 ID 组成复合键, 使 http 与 tcp 两路的 id 即便同号也不会在同一个
// BridgeHub(服务端全局 ServerBridge, 或订阅方每条 server 连接各自的 bridge)中
// 互相串扰(两路各自的采番器都可从 1 起步)。
const (
	ConnHTTP uint8 = 0 //现有 HTTP 转发路径
	ConnTCP  uint8 = 1 //裸 TCP 端口转发路径
)

// SEND_CHAN_LEN 发送通道长度
const SEND_CHAN_LEN = 200

// AuthMessage 认证
type AuthMessage struct {
	User  string
	Email string
	Token string
	Xtime int64

	// Direct 表示本订阅方参与 QUIC 直连(配了 directAccept 或 direct[])。
	//
	// 服务端据此放行空订阅: 直连拓扑下入口在订阅方自己机器上, 服务端不需要配
	// server.forward, 订阅方也不需要 subscribe 头部规则, 两边都为空时若不放行,
	// 直连的双方都会在握手阶段被 "subscribe empty err" 拒掉。
	// 不参与 token 计算; 旧版客户端不发这个字段, 反序列化为 false, 行为不变。
	Direct bool

	// KeyAuth 表示本端要走密钥对鉴权(client.key), 此时 Token/Xtime 无意义。
	// 服务端见到它会回一个 AuthChallenge 而不是 "ok", 客户端签名后再发
	// AuthSignature, 见 authkey.go。旧版客户端不发这个字段, 走原来的密码流程。
	KeyAuth bool
}

// SubscribeMessage 订阅
type SubscribeMessage struct {
	Key string
	Val string
}

// Message 普通消息体
type Message struct {
	ID     uint
	Type   uint8 //连接类型(ConnHTTP/ConnTCP), 与 ID 组成复合键
	Method string
	// Body 数据消息(Method 为空)时是要转发的业务字节; METHOD_CLOSE 时借用同一个字段
	// 承载拒绝/关闭原因(可为空), 两种用法按 Method 互斥, 不会混淆(见 Bridge.CloseReason)。
	Body []byte
	Port uint16 //仅 METHOD_CREATE 用: 服务端裸TCP入口端口, 订阅方据此查固定 target
}

// CMessage 普通消息体的复合类型，标记要向哪个Client发送
type CMessage struct {
	client  *Client
	message *Message
}

// 转成二进制
func (m *Message) encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(*m)
	return buf.Bytes(), err
}

// 转成struct
func decodeMessage(data []byte) (*Message, error) {
	var buf bytes.Buffer
	var m Message
	_, err := buf.Write(data)
	if err != nil {
		return &m, err
	}
	dec := gob.NewDecoder(&buf)
	err = dec.Decode(&m)
	return &m, err
}
