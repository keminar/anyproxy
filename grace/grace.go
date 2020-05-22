// Copyright 2014 beego Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package grace use to hot reload
// Description: http://grisha.org/blog/2014/06/03/graceful-restart-in-golang/

// examples
// package main
//
// import (
// 	"flag"
// 	"net"
//
// 	"github.com/keminar/anyproxy/grace"
// )
//
// var appHandler func(conn net.Conn) error
//
// func main() {
// 	flag.Parse()
//
// 	server := grace.NewServer(":3000", appHandler)
// 	server.ListenAndServe()
// }

package grace

import (
	"flag"
	"os"
	"strings"
	"sync"
	"syscall"
)

const (
	// PreSignal is the position to add filter before signal
	PreSignal = iota
	// PostSignal is the position to add filter after signal
	PostSignal
	// StateInit represent the application inited
	StateInit
	// StateRunning represent the application is running
	StateRunning
	// StateShuttingDown represent the application is shutting down
	StateShuttingDown
	// StateTerminate represent the application is killed
	StateTerminate
)

var (
	regLock              *sync.Mutex
	runningServers       map[string]*Server
	runningServersOrder  []string
	socketPtrOffsetMap   map[string]uint
	runningServersForked bool

	isChild     bool
	socketOrder string

	hookableSignals []os.Signal
)

func init() {
	flag.BoolVar(&isChild, "graceful", false, "listen on open fd (after forking)")
	flag.StringVar(&socketOrder, "socketorder", "", "previous initialization order - used when more than one listener was started")

	regLock = &sync.Mutex{}
	runningServers = make(map[string]*Server)
	runningServersOrder = []string{}
	socketPtrOffsetMap = make(map[string]uint)

	hookableSignals = []os.Signal{
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
	}
}

// NewServer returns a new graceServer.
func NewServer(addr string, handler ConnHandler) (srv *Server) {
	regLock.Lock()
	defer regLock.Unlock()

	if !flag.Parsed() {
		flag.Parse()
	}
	if len(socketOrder) > 0 {
		for i, addr := range strings.Split(socketOrder, ",") {
			socketPtrOffsetMap[addr] = uint(i)
		}
	} else {
		socketPtrOffsetMap[addr] = uint(len(runningServersOrder))
	}

	srv = &Server{
		Addr:    addr,
		Handler: handler,
		sigChan: make(chan os.Signal),
		isChild: isChild,
		SignalHooks: map[int]map[os.Signal][]func(){
			PreSignal: {
				syscall.SIGHUP:  {},
				syscall.SIGINT:  {},
				syscall.SIGTERM: {},
			},
			PostSignal: {
				syscall.SIGHUP:  {},
				syscall.SIGINT:  {},
				syscall.SIGTERM: {},
			},
		},
		state:        StateInit,
		Network:      "tcp",
		terminalChan: make(chan error), //no cache channel
	}

	runningServersOrder = append(runningServersOrder, addr)
	runningServers[addr] = srv
	return srv
}
