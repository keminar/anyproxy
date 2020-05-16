package main

import (
	"flag"
	"github.com/keminar/anyproxy/proto"
	"github.com/keminar/anyproxy/grace"
)

func main() {
	flag.Parse()

	c := proto.NewClient()
	server := grace.NewServer(":3000", c.Handler)
	server.ListenAndServe()
}
