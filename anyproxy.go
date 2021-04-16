package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/logging"
	"github.com/keminar/anyproxy/nat"
	"github.com/keminar/anyproxy/proto"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/daemon"
	"github.com/keminar/anyproxy/utils/help"
	"github.com/keminar/anyproxy/utils/tools"
)

var (
	gListenAddrPort  string
	gProxyServerSpec string
	gWebsocketListen string
	gWebsocketConn   string
	gHelp            bool
	gDebug           int
	gPprof           string
)

func init() {
	flag.Usage = help.Usage
	flag.StringVar(&gListenAddrPort, "l", "", "Address and port to listen on")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use")
	flag.StringVar(&gWebsocketListen, "ws-listen", "", "Websocket address and port to listen on")
	flag.StringVar(&gWebsocketConn, "ws-connect", "", "Websocket Address and port to connect")
	flag.IntVar(&gDebug, "debug", 0, "debug mode (0, 1, 2)")
	flag.StringVar(&gPprof, "pprof", "", "pprof port, disable if empty")
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

	cmdName := "anyproxy"
	logDir := "./logs/"
	if conf.RouterConfig.Log.Dir != "" {
		logDir = conf.RouterConfig.Log.Dir
	}
	envRunMode := fmt.Sprintf("%s_run_mode", cmdName)
	fd := logging.ErrlogFd(logDir, cmdName)
	// 是否后台运行
	daemon.Daemonize(envRunMode, fd)

	gListenAddrPort = config.IfEmptyThen(gListenAddrPort, conf.RouterConfig.Listen, ":3000")
	gListenAddrPort = tools.FillPort(gListenAddrPort)
	config.SetListenPort(gListenAddrPort)

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

	// 调试模式
	if len(gPprof) > 0 {
		go func() {
			gPprof = tools.FillPort(gPprof)
			//浏览器访问: http://:5001/debug/pprof/
			log.Println("Starting pprof debug server ...")
			// 这里不要使用log.Fatal会在平滑重启时导致进程退出
			// 因为http server现在没办法加入平滑重启，第一次重启会报端口冲突，可以通过重启两次来启动到pprof
			log.Println(http.ListenAndServe(gPprof, nil))
		}()
	}

	// websocket 配置
	gWebsocketListen = config.IfEmptyThen(gWebsocketListen, conf.RouterConfig.Websocket.Listen, "")
	if gWebsocketListen != "" {
		gWebsocketListen = tools.FillPort(gWebsocketListen)
		go nat.NewServer(&gWebsocketListen)
	}

	gWebsocketConn = config.IfEmptyThen(gWebsocketConn, conf.RouterConfig.Websocket.Connect, "")
	if gWebsocketConn != "" {
		gWebsocketConn = tools.FillPort(gWebsocketConn)
		go nat.ConnectServer(&gWebsocketConn)
	}
	server := grace.NewServer(gListenAddrPort, proto.ClientHandler)
	server.ListenAndServe()
}
