package main

import (
	"flag"
	"net"

	"github.com/keminar/anyproxy/grace"
)

var appHandler func(conn net.Conn) error

func main() {
	flag.Parse()

	server := grace.NewServer(":3000", appHandler)
	server.ListenAndServe()
}
