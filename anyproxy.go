package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
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
	gPprof           string
)

func init() {
	flag.Usage = help.Usage
	flag.StringVar(&gListenAddrPort, "l", ":3000", "Address and port to listen on")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use")
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

	// 支持只输入端口的形式
	if !strings.Contains(gListenAddrPort, ":") {
		gListenAddrPort = ":" + gListenAddrPort
	}
	config.SetListenPort(gListenAddrPort)

	var writer io.Writer
	// 前台执行，daemon运行根据环境变量识别
	if daemon.IsForeground(envRunMode) {
		// 同时输出到日志和标准输出
		writer = io.Writer(os.Stdout)
	}

	logging.SetDefaultLogger(logDir, cmdName, true, 3, writer)
	// 设置代理
	config.SetProxyServer(gProxyServerSpec)

	// 调试模式
	if len(gPprof) > 0 {
		go func() {
			// 支持只输入端口的形式
			if !strings.Contains(gPprof, ":") {
				gPprof = ":" + gPprof
			}
			//浏览器访问: http://:5001/debug/pprof/
			log.Println("Starting pprof debug server ...")
			// 这里不要使用log.Fatal会在平滑重启时导致进程退出
			// 因为http server现在没办法加入平滑重启，第一次重启会报端口冲突，可以通过重启两次来启动到pprof
			log.Println(http.ListenAndServe(gPprof, nil))
		}()
	}
	server := grace.NewServer(gListenAddrPort, proto.ClientHandler)
	server.ListenAndServe()
}
