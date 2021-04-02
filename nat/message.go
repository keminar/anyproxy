package nat

type AuthMessage struct {
	User  string
	Token string
}

type SubscribeMessage struct {
	Key string
	Val string
}

type AnswerMessage struct {
	State int
	Msg   string
}

type Message struct {
	ID     string
	Method string
	Body   []byte
}
