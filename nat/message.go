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
	Body   []byte
	Port   uint16 //仅 METHOD_CREATE 用: 服务端裸TCP入口端口, 订阅方据此查固定 target
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
