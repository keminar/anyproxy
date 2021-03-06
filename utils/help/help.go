package help

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	version   string
	gitHash   string
	goVersion string
)

// Usage 帮助
func Usage() {
	fmt.Fprintf(os.Stdout, "%s\n\n", versionString("anyproxy"))
	fmt.Fprintf(os.Stdout, "Usage: %s -l listenaddress -p proxies \n", os.Args[0])
	fmt.Fprintf(os.Stdout, "       Proxies any tcp port transparently\n\n")
	fmt.Fprintf(os.Stdout, "Mandatory\n")
	fmt.Fprintf(os.Stdout, "  -l=ADDRPORT      Address and port to listen on (e.g., :3000 or 127.0.0.1:3000)\n")
	fmt.Fprintf(os.Stdout, "  -p=PROXIES       Address and ports of upstream proxy servers to use\n")
	fmt.Fprintf(os.Stdout, "                   (e.g., 10.1.1.1:80 will use http proxy, socks5://10.2.2.2:3128 use socks5 proxy,\n")
	fmt.Fprintf(os.Stdout, "                   tunnel://10.2.2.2:3001 use tunnel proxy)\n")
	fmt.Fprintf(os.Stdout, "  -c=FILEPATH      Config file path, default is router.yaml\n")
	fmt.Fprintf(os.Stdout, "Optional\n")
	fmt.Fprintf(os.Stdout, "  -ws-listen       Websocket address and port to listen on\n")
	fmt.Fprintf(os.Stdout, "  -ws-connect      Websocket Address and port to connect\n")
	fmt.Fprintf(os.Stdout, "  -daemon          Run as a Unix daemon\n")
	fmt.Fprintf(os.Stdout, "  -mode            Run mode(proxy, tunnel). proxy mode default\n")
	fmt.Fprintf(os.Stdout, "  -debug           Debug mode (0, 1, 2, 3)\n")
	fmt.Fprintf(os.Stdout, "  -pprof           Pprof port, disable if empty\n")
	fmt.Fprintf(os.Stdout, "  -v               Show build version\n\n")
	fmt.Fprintf(os.Stdout, "  -h               This usage message\n\n")

	fmt.Fprintf(os.Stdout, "Before starting anyproxy, be sure to change the number of available file handles to at least 65535\n")
	fmt.Fprintf(os.Stdout, "with \"ulimit -n 65535\"\n") //重要
	fmt.Fprintf(os.Stdout, "Some other tunables that enable higher performance:\n")
	fmt.Fprintf(os.Stdout, "  net.core.netdev_max_backlog = 2048\n")
	fmt.Fprintf(os.Stdout, "  net.core.somaxconn = 1024\n")
	fmt.Fprintf(os.Stdout, "  net.core.rmem_default = 8388608\n")
	fmt.Fprintf(os.Stdout, "  net.core.rmem_max = 16777216\n")
	fmt.Fprintf(os.Stdout, "  net.core.wmem_max = 16777216\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_tw_reuse = 1 \n")    //重要 ，//sysctl -w net.ipv4.tcp_tw_reuse=1
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_fin_timeout = 30\n") //重要， //sysctl -w net.ipv4.tcp_fin_timeout=30
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

	fmt.Fprintf(os.Stdout, "Report bugs to https://github.com/keminar/anyproxy or <linuxphp@126.com>.\n")
	fmt.Fprintf(os.Stdout, "Thanks to https://github.com/ryanchapman/go-any-proxy.git\n")
}

// 版本
func ShowVersion() {
	fmt.Fprintf(os.Stdout, "%s\n\n", versionString("anyproxy"))
}

func versionString(name string) (v string) {
	now := time.Now().Unix()
	buildNum := strings.ToUpper(strconv.FormatInt(now, 36))
	buildDate := time.Unix(now, 0).Format(time.UnixDate)
	v = fmt.Sprintf("%s %s (build %v, %v)", name, version, buildNum, buildDate)
	v += fmt.Sprintf("\nGit Commit Hash: %s", gitHash)
	v += fmt.Sprintf("\nGoLang Version: %s", goVersion)
	return
}
