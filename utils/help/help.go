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
	fmt.Fprintf(os.Stdout, "  -daemon          Run as a Unix daemon\n")
	fmt.Fprintf(os.Stdout, "  -mode            Run mode: proxy (default) | tunnel | tun (build TUN NIC, needs admin/root) | bypass (bind physical NIC only, escape another process's TUN) | tcpcopy (forward every connection to tcpcopy.ip:port)\n")
	fmt.Fprintf(os.Stdout, "  -debug           Debug mode (0, 1, 2, 3)\n")
	fmt.Fprintf(os.Stdout, "  -pprof           Pprof port, disable if empty\n")
	fmt.Fprintf(os.Stdout, "  -geo-extract     Extract categories from a geoip.dat/geosite.dat and exit\n")
	fmt.Fprintf(os.Stdout, "                   (with -geo-in <src.dat> -geo-cat cn,google -geo-out <small.dat>)\n")
	fmt.Fprintf(os.Stdout, "  -genkey          Generate a websocket auth key pair and exit\n")
	fmt.Fprintf(os.Stdout, "                   (private key -> websocket.client.key, public key -> websocket.server.users[].key)\n")
	fmt.Fprintf(os.Stdout, "  -send PATH       Send a file/dir to another subscriber over a direct connection and exit\n")
	fmt.Fprintf(os.Stdout, "                   (with -to <email>; extra paths may follow as arguments)\n")
	fmt.Fprintf(os.Stdout, "  -check           Check system tuning (sysctl/ulimit) vs recommendations and exit (Linux)\n")
	fmt.Fprintf(os.Stdout, "  -check-fix       Apply recommended sysctl tuning (needs root) and exit (Linux)\n")
	fmt.Fprintf(os.Stdout, "  -v               Show build version\n\n")
	fmt.Fprintf(os.Stdout, "  -h               This usage message\n\n")

	fmt.Fprintf(os.Stdout, "Before starting anyproxy, be sure to change the number of available file handles to at least 65535\n")
	fmt.Fprintf(os.Stdout, "with \"ulimit -n 65535\"\n") //重要
	fmt.Fprintf(os.Stdout, "Some other tunables that enable higher performance (append to /etc/sysctl.conf, then run \"sysctl -p\"):\n")
	fmt.Fprintf(os.Stdout, "  # TCP BBR congestion control (needs kernel >= 4.9)\n")
	fmt.Fprintf(os.Stdout, "  net.core.default_qdisc = fq\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_congestion_control = bbr\n")
	fmt.Fprintf(os.Stdout, "  # TCP/IP tuning\n")
	fmt.Fprintf(os.Stdout, "  fs.file-max = 1000000\n")
	fmt.Fprintf(os.Stdout, "  net.core.rmem_max = 67108864\n")
	fmt.Fprintf(os.Stdout, "  net.core.wmem_max = 67108864\n")
	fmt.Fprintf(os.Stdout, "  net.core.netdev_max_backlog = 250000\n")
	fmt.Fprintf(os.Stdout, "  net.core.somaxconn = 4096\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_syncookies = 1\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_tw_reuse = 1\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_fin_timeout = 30\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_keepalive_time = 1200\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.ip_local_port_range = 10000 65000\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_max_syn_backlog = 8192\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_max_tw_buckets = 524288\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_fastopen = 3\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_window_scaling = 1\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_rmem = 4096 131072 67108864\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_wmem = 4096 65536 67108864\n")
	fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_mtu_probing = 1\n")
	fmt.Fprintf(os.Stdout, "  NOTE: if you see syn flood warnings in your logs, you need to adjust tcp_max_syn_backlog, tcp_synack_retries and tcp_abort_on_overflow\n")
	fmt.Fprintf(os.Stdout, "  verify BBR: sysctl net.ipv4.tcp_congestion_control (=> bbr) ; lsmod | grep bbr (=> tcp_bbr)\n\n")

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
