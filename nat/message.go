package nat

import (
	"bytes"
	"encoding/gob"
)

// 创建连接命令
const METHOD_CREATE = "create"

// 关闭连接命令
const METHOD_CLOSE = "close"

// 发送通道长度
const SEND_CHAN_LEN = 200

// 认证
type AuthMessage struct {
	User  string
	Token string
	Xtime int64
}

// 订阅
type SubscribeMessage struct {
	Key string
	Val string
}

// 普通消息体
type Message struct {
	ID     uint
	Method string
	Body   []byte
}

// 普通消息体的复合类型，标记要向哪个Client发送
type CMessage struct {
	Client  *Client
	Message *Message
}

func (m *Message) encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(*m)
	return buf.Bytes(), err
}

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
