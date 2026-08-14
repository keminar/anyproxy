package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/logging"
	"github.com/keminar/anyproxy/nat"
	"github.com/keminar/anyproxy/proto"
	"github.com/keminar/anyproxy/tun"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/daemon"
	"github.com/keminar/anyproxy/utils/help"
	"github.com/keminar/anyproxy/utils/rss"
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
	flag.StringVar(&gListenAddrPort, "l", "", "listen address of socks5 and http proxy")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use")
	flag.StringVar(&gConfigFile, "c", "", "Config file path, default is router.yaml")
	flag.StringVar(&gWebsocketListen, "ws-listen", "", "Websocket address and port to listen on")
	flag.StringVar(&gWebsocketConn, "ws-connect", "", "Websocket Address and port to connect")
	flag.StringVar(&gMode, "mode", "", "Run mode: proxy (default) | tunnel | tun (build TUN NIC, needs admin/root) | bypass (bind physical NIC only, escape another process's TUN)")
	flag.IntVar(&gDebug, "debug", 0, "debug mode (0, 1, 2, 3)")
	flag.StringVar(&gPprof, "pprof", "", "pprof port, disable if empty")
	flag.BoolVar(&gVersion, "v", false, "Show build version")
	flag.BoolVar(&gHelp, "h", false, "This usage message")
}

func main() {
	// 尽早设置 GODEBUG=madvdontneed=1 并 exec 重启自身，使归还的内存立即扣 RSS。
	// 必须在任何堆分配/goroutine 之前，保证 runtime 读到该开关(幂等，二次进入直接跳过)。
	rss.Ensure()

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
		time.Sleep(60 * time.Second)
		os.Exit(2)
	}

	cmdName := "anyproxy"
	defLogDir := fmt.Sprintf("%s%s%s%s", conf.AppPath, string(os.PathSeparator), "logs", string(os.PathSeparator))
	logDir := config.IfEmptyThen(conf.RouterConfig.Log.Dir, defLogDir, "")
	if _, err := os.Stat(logDir); err != nil {
		log.Println(err)
		time.Sleep(60 * time.Second)
		os.Exit(2)
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

	logging.SetDefaultLogger(logDir, fmt.Sprintf("%s.%d", cmdName, config.ListenPort), true, 3, writer)
	// 设置代理。命令行 -p 为固定值(记入 ProxyCmdline, 优先于配置);
	// 未指定 -p 时请求侧实时读取 default.proxy, 使其支持热加载。
	config.ProxyCmdline = gProxyServerSpec
	// 启动时按「-p > default.proxy」解析首个代理, 供 tun_windows 排除捕获与日志用
	config.SetProxyServer(config.IfEmptyThen(config.ProxyCmdline, conf.RouterConfig.Default.Proxy, ""))

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

	// TUN 虚拟网卡全局代理
	// 使用可取消的 context，在收到 SIGINT/SIGTERM 时关闭设备，
	// 确保 wintun 虚拟网卡在进程退出前被清理。
	tunCtx, tunCancel := context.WithCancel(context.Background())
	var tunWG sync.WaitGroup
	// 解析运行模式: 命令行 -mode > 配置 mode > proxy
	mode := config.IfEmptyThen(gMode, conf.RouterConfig.Mode, "proxy")
	switch mode {
	case "tun":
		// autoRoute 不配置时默认 true(自动加路由); 显式设 false 才关闭
		autoRoute := true
		if conf.RouterConfig.Tun.AutoRoute != nil {
			autoRoute = *conf.RouterConfig.Tun.AutoRoute
		}
		tunCfg := tun.Config{
			Name:         conf.RouterConfig.Tun.Name,
			Addr:         conf.RouterConfig.Tun.Addr,
			MTU:          conf.RouterConfig.Tun.MTU,
			AutoRoute:    autoRoute,
			BypassIPs:    conf.RouterConfig.Tun.BypassIPs,
			ExcludeProcs: conf.RouterConfig.Tun.ExcludeProcs,
			InboundPorts: conf.RouterConfig.Tun.InboundPorts,
		}
		tunWG.Add(1)
		go func() {
			defer tunWG.Done()
			if err := tun.Run(tunCtx, tunCfg); err != nil {
				log.Println("tun run err:", err)
			}
		}()
	case "bypass":
		// 仅初始化物理网卡绕行参数，不建TUN网卡；Windows 下会启用 /32 例外路由(逃他机TUN)
		tun.InitBypassOnly(tun.BypassConfig{
			ExcludeNics:  conf.RouterConfig.Bypass.ExcludeNics,
			Device:       conf.RouterConfig.Bypass.Device,
			ExcludeProcs: conf.RouterConfig.Bypass.ExcludeProcs,
			BypassIPs:    conf.RouterConfig.Bypass.BypassIPs,
		})
		// 退出/平滑重启前清理 bypass 加的 /32 例外路由(复用 tunCtx 取消信号 + tunWG 等待)
		tunWG.Add(1)
		go func() {
			defer tunWG.Done()
			<-tunCtx.Done()
			tun.CleanupBypass()
		}()
	case "proxy", "tunnel":
		// 不接管全局流量，仅按监听端口收流
	case "tcpcopy":
		// 端口转发: 不接管全局流量, 每个连接改投到 tcpcopy.ip:port(见 proto/request.go)。
		// 命令行 -mode tcpcopy 时配置里可能没有 mode 字段, 这里补上归一(配置文件写 mode:
		// tcpcopy 时已在 LoadRouterConfig 归一)。
		conf.RouterConfig.TcpCopy.Enable = true
	default:
		log.Printf("unknown mode %q, expect proxy|tunnel|tun|bypass|tcpcopy, fallback proxy\n", mode)
		mode = "proxy"
	}

	// tcp   同是监听IPv4 和 IPv6
	// tcp4  仅监听使用IPv4
	// tcp6  仅监听使用IPv6
	network := "tcp"
	if conf.RouterConfig.Network != "" {
		network = conf.RouterConfig.Network
	}
	// tunnel 为服务端(tunneld); proxy/tun/bypass 均为客户端
	handler := proto.ClientHandler
	if mode == "tunnel" {
		handler = proto.ServerHandler
	}
	server := grace.NewServer(gListenAddrPort, handler, network)
	registerTUNCleanup(server, tunCancel, &tunWG)
	server.ListenAndServe()
}

// registerTUNCleanup 注册 SIGHUP/SIGINT/SIGTERM 的 PreSignal 钩子，
// 在 grace server fork 子进程或关闭 TCP 监听之前，先取消 TUN context 并等待设备关闭。
//   - SIGHUP(平滑重启): fork 前主动释放 TUN 设备，让新进程能立即接管，
//     否则新进程创建同名设备会 EBUSY(TUN 设备独占)。
//   - SIGINT/SIGTERM(退出): 确保 TUN 虚拟网卡在进程退出前被清理。
//
// PreSignal 钩子在 fork()/shutdown() 之前执行，保证释放先于接管/退出。
func registerTUNCleanup(server *grace.Server, cancel context.CancelFunc, wg *sync.WaitGroup) {
	cleanup := func() {
		cancel()
		wg.Wait()
	}
	server.RegisterSignalHook(grace.PreSignal, syscall.SIGHUP, cleanup)
	server.RegisterSignalHook(grace.PreSignal, syscall.SIGINT, cleanup)
	server.RegisterSignalHook(grace.PreSignal, syscall.SIGTERM, cleanup)
}
