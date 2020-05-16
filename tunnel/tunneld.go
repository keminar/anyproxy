package main

import (
	"flag"
	"net"

	"github.com/keminar/anyproxy/grace"
)

var appHandler func(conn *net.TCPConn) error

func main() {
	flag.Parse()

	server := grace.NewServer(":3001", appHandler)
	server.ListenAndServe()
}
