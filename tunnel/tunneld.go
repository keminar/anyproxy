package main

import (
	"flag"
	"fmt"
	"io"
	"os"
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
	flag.StringVar(&gListenAddrPort, "l", ":3001", "Address and port to listen on")
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

	config.SetDebugLevel(gDebug)
	conf.LoadAllConfig()
	// 检查配置是否存在
	if conf.RouterConfig == nil {
		os.Exit(2)
	}

	cmdName := "tunneld"
	logDir := "./logs/"
	envRunMode := fmt.Sprintf("%s_run_mode", cmdName)
	fd := logging.ErrlogFd(logDir, cmdName)
	// 是否后台运行
	daemon.Daemonize(envRunMode, fd)

	// 支持只输入端口的形式
	if !strings.Contains(gListenAddrPort, ":") {
		gListenAddrPort = ":" + gListenAddrPort
	}

	var writer io.Writer
	// 前台执行，daemon运行根据环境变量识别
	if daemon.IsForeground(envRunMode) {
		// 同时输出到日志和标准输出
		writer = io.Writer(os.Stdout)
	}

	logging.SetDefaultLogger(logDir, cmdName, true, 3, writer)
	// 设置代理
	config.SetProxyServer(gProxyServerSpec)

	server := grace.NewServer(gListenAddrPort, proto.ServerHandler)
	server.ListenAndServe()
}
