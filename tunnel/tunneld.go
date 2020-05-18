package main

import (
	"flag"

	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/proto"
)

func main() {
	flag.Parse()

	c := proto.NewServer()
	server := grace.NewServer(":3001", c.Handler)
	server.ListenAndServe()
}
