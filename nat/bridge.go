package nat

import "net"

type Bridge struct {
	reqID uint
	conn  *net.TCPConn

	// Buffered channel of outbound messages.
	send chan []byte
}
