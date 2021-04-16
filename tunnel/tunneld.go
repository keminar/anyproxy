package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/logging"
	"github.com/keminar/anyproxy/proto"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/daemon"
	"github.com/keminar/anyproxy/utils/help"
	"github.com/keminar/anyproxy/utils/tools"
)

var (
	gListenAddrPort  string
	gProxyServerSpec string
	gHelp            bool
	gDebug           int
)

func init() {
	flag.Usage = help.TunnelUsage
	flag.StringVar(&gListenAddrPort, "l", "", "Address and port to listen on")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use")
	//CONNECT请求不支持ws-listen 和 ws-connect，且tunnel只做接收anyproxy的安全转发，不需要支持ws
	flag.IntVar(&gDebug, "debug", 0, "debug mode (0, 1, 2)")
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
	if conf.RouterConfig.Log.Dir != "" {
		logDir = conf.RouterConfig.Log.Dir
	}
	envRunMode := fmt.Sprintf("%s_run_mode", cmdName)
	fd := logging.ErrlogFd(logDir, cmdName)
	// 是否后台运行
	daemon.Daemonize(envRunMode, fd)

	gListenAddrPort = config.IfEmptyThen(gListenAddrPort, conf.RouterConfig.Listen, ":3001")
	gListenAddrPort = tools.FillPort(gListenAddrPort)

	var writer io.Writer
	// 前台执行，daemon运行根据环境变量识别
	if daemon.IsForeground(envRunMode) {
		// 同时输出到日志和标准输出
		writer = io.Writer(os.Stdout)
	}

	logging.SetDefaultLogger(logDir, cmdName, true, 3, writer)
	// 设置代理
	gProxyServerSpec = config.IfEmptyThen(gProxyServerSpec, conf.RouterConfig.Default.Proxy, "")
	config.SetProxyServer(gProxyServerSpec)

	// 与anyproxy不同之处在ServerHandler
	server := grace.NewServer(gListenAddrPort, proto.ServerHandler)
	server.ListenAndServe()
}
