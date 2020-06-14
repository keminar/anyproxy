package main

import (
	"flag"
	"strings"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/logging"
	"github.com/keminar/anyproxy/proto"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/daemon"
	"github.com/keminar/anyproxy/utils/help"
)

var (
	gListenAddrPort  string
	gProxyServerSpec string
	gHelp            bool
	gDebug           int
)

func init() {
	flag.Usage = help.Usage
	flag.StringVar(&gListenAddrPort, "l", ":3000", "Address and port to listen on")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use")
	flag.IntVar(&gDebug, "d", 0, "debug mode")
	flag.BoolVar(&gHelp, "h", false, "This usage message")

}

func main() {
	flag.Parse()
	if gHelp {
		flag.Usage()
		return
	}

	// 是否后台运行
	daemon.Daemonize()

	// 支持只输入端口的形式
	if !strings.Contains(gListenAddrPort, ":") {
		gListenAddrPort = ":" + gListenAddrPort
	}
	config.SetDebugLevel(gDebug)
	logging.SetDefaultLogger("./logs/", "anyproxy", true, 3)
	// 设置代理
	config.SetProxyServer(gProxyServerSpec)

	conf.LoadAllConfig()
	server := grace.NewServer(gListenAddrPort, proto.ClientHandler)
	server.ListenAndServe()
}
