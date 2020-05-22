package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/logging"
	"github.com/keminar/anyproxy/proto"
)

const VERSION = "0.2"

var (
	gListenAddrPort  string
	gProxyServerSpec string
	gHelp            bool
	gDebug           int
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "%s\n\n", versionString())
		fmt.Fprintf(os.Stdout, "usage: %s -l listenaddress -p proxies \n", os.Args[0])
		fmt.Fprintf(os.Stdout, "       Proxies any tcp port transparently using Linux netfilter\n\n")
		fmt.Fprintf(os.Stdout, "Mandatory\n")
		fmt.Fprintf(os.Stdout, "  -l=ADDRPORT      Address and port to listen on (e.g., :3128 or 127.0.0.1:3128)\n")
		fmt.Fprintf(os.Stdout, "Optional\n")
		fmt.Fprintf(os.Stdout, "  -p=PROXIES       Address and ports of upstream proxy servers to use\n")
		fmt.Fprintf(os.Stdout, "  -h               This usage message\n\n")

		fmt.Fprintf(os.Stdout, "Before starting anyproxy, be sure to change the number of available file handles to at least 65535\n")
		fmt.Fprintf(os.Stdout, "with \"ulimit -n 65535\"\n")
		fmt.Fprintf(os.Stdout, "Some other tunables that enable higher performance:\n")
		fmt.Fprintf(os.Stdout, "  net.core.netdev_max_backlog = 2048\n")
		fmt.Fprintf(os.Stdout, "  net.core.somaxconn = 1024\n")
		fmt.Fprintf(os.Stdout, "  net.core.rmem_default = 8388608\n")
		fmt.Fprintf(os.Stdout, "  net.core.rmem_max = 16777216\n")
		fmt.Fprintf(os.Stdout, "  net.core.wmem_max = 16777216\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.ip_local_port_range = 2000 65000\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_window_scaling = 1\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_max_syn_backlog = 3240000\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_max_tw_buckets = 1440000\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_mem = 50576 64768 98152\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_rmem = 4096 87380 16777216\n")
		fmt.Fprintf(os.Stdout, "  NOTE: if you see syn flood warnings in your logs, you need to adjust tcp_max_syn_backlog, tcp_synack_retries and tcp_abort_on_overflow\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_syncookies = 1\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_wmem = 4096 65536 16777216\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_congestion_control = cubic\n\n")
		fmt.Fprintf(os.Stdout, "Report bugs to <linuxphp@126.com>.\n")
		fmt.Fprintf(os.Stdout, "Thanks to https://github.com/ryanchapman/go-any-proxy.git\n")
	}
	flag.StringVar(&gListenAddrPort, "l", ":3001", "Address and port to listen on")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use")
	flag.IntVar(&gDebug, "d", 0, "debug mode")
	flag.BoolVar(&gHelp, "h", false, "This usage message")

}

func versionString() (v string) {
	now := time.Now().Unix()
	buildNum := strings.ToUpper(strconv.FormatInt(now, 36))
	buildDate := time.Unix(now, 0).Format(time.UnixDate)
	v = fmt.Sprintf("tunneld %s (build %v, %v)", VERSION, buildNum, buildDate)
	return
}

func main() {
	flag.Parse()
	if gHelp {
		flag.Usage()
		return
	}

	// 支持只输入端口的形式
	if !strings.Contains(gListenAddrPort, ":") {
		gListenAddrPort = ":" + gListenAddrPort
	}
	config.SetDebugLevel(gDebug)
	logging.SetDefaultLogger("./logs/", "tunneld", true, 3)
	// 设置代理
	config.SetProxyServer(gProxyServerSpec)

	server := grace.NewServer(gListenAddrPort, proto.ServerHandler)
	server.ListenAndServe()
}
