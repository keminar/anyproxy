package nat

// 创建连接命令
const METHOD_CREATE = "create"

// 关闭连接命令
const METHOD_CLOSE = "close"

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

// 回答
type AnswerMessage struct {
	State int
	Msg   string
}

// 普通消息体
type Message struct {
	ID     uint
	Method string
	Body   []byte
}
