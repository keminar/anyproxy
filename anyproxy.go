package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

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
	gConfigFile      string
	gWebsocketListen string
	gWebsocketConn   string
	gMode            string
	gHelp            bool
	gDebug           int
	gPprof           string
	gVersion         bool
)

func init() {
	flag.Usage = help.Usage
	flag.StringVar(&gListenAddrPort, "l", "", "Address and port to listen on")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use")
	flag.StringVar(&gConfigFile, "c", "", "Config file path, default is router.yaml")
	flag.StringVar(&gWebsocketListen, "ws-listen", "", "Websocket address and port to listen on")
	flag.StringVar(&gWebsocketConn, "ws-connect", "", "Websocket Address and port to connect")
	flag.StringVar(&gMode, "mode", "", "Run mode(proxy, tunnel). proxy mode default")
	flag.IntVar(&gDebug, "debug", 0, "debug mode (0, 1, 2)")
	flag.StringVar(&gPprof, "pprof", "", "pprof port, disable if empty")
	flag.BoolVar(&gVersion, "v", false, "Show build version")
	flag.BoolVar(&gHelp, "h", false, "This usage message")
}

func main() {
	flag.Parse()
	if gHelp {
		flag.Usage()
		return
	}
	if gVersion {
		help.ShowVersion()
		return
	}

	config.SetDebugLevel(gDebug)
	conf.LoadAllConfig(gConfigFile)
	// 检查配置是否存在
	if conf.RouterConfig == nil {
		os.Exit(2)
	}

	cmdName := "anyproxy"
	logDir := config.IfEmptyThen(conf.RouterConfig.Log.Dir, "./logs/", "")
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
			// 因为http server现在没办法一次平滑重启，会报端口冲突，可以通过多次重试来启动pprof
			for i := 0; i < 10; i++ {
				log.Println(http.ListenAndServe(gPprof, nil))
				time.Sleep(10 * time.Second)
			}
		}()
	}

	// websocket 服务端
	gWebsocketListen = config.IfEmptyThen(gWebsocketListen, conf.RouterConfig.Websocket.Listen, "")
	if gWebsocketListen != "" {
		gWebsocketListen = tools.FillPort(gWebsocketListen)
		go nat.NewServer(&gWebsocketListen)
	}
	// websocket 客户端
	gWebsocketConn = config.IfEmptyThen(gWebsocketConn, conf.RouterConfig.Websocket.Connect, "")
	if gWebsocketConn != "" {
		gWebsocketConn = tools.FillPort(gWebsocketConn)
		go nat.ConnectServer(&gWebsocketConn)
	}

	// 运行模式
	if gMode == "tunnel" {
		server := grace.NewServer(gListenAddrPort, proto.ServerHandler)
		server.ListenAndServe()
	} else {
		server := grace.NewServer(gListenAddrPort, proto.ClientHandler)
		server.ListenAndServe()
	}
}
