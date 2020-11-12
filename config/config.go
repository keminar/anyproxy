package config

import (
	"log"
	"strconv"
	"strings"

	"github.com/keminar/anyproxy/utils/tools"
)

// ProxyScheme 协议
var ProxyScheme string = "http"

// ProxyServer 代理服务器
var ProxyServer string

// ProxyPort 代理端口
var ProxyPort uint16

// TimeFormat 格式化时间
var TimeFormat string = "2006-01-02 15:04:05"

// DebugLevel 调试级别
var DebugLevel int

// ListenPort 监听端口
var ListenPort uint16

const (
	// LevelShort 简短格式
	LevelShort int = iota
	// LevelLong 长格式日志
	LevelLong
	// LevelDebug 长日志 + 更多日志
	LevelDebug
	// LevelDebugBody 打印body
	LevelDebugBody
)

// SetProxyServer 设置代理服务器
func SetProxyServer(gProxyServerSpec string) {
	if gProxyServerSpec == "" {
		return
	}

	// 先检查协议
	tmp := strings.Split(gProxyServerSpec, "://")
	if len(tmp) == 2 {
		ProxyScheme = tmp[0]
		gProxyServerSpec = tmp[1]
	}
	// 检查端口，和上面的顺序不能反
	tmp = strings.Split(gProxyServerSpec, ":")
	if len(tmp) == 2 {
		portInt, err := strconv.Atoi(tmp[1])
		if err == nil {
			ProxyServer = tmp[0]
			ProxyPort = uint16(portInt)
			log.Printf("Proxy server is %s://%s:%d\n", ProxyScheme, ProxyServer, ProxyPort)
		} else {
			log.Printf("Set proxy port err %s\n", err.Error())
		}
	}
}

// SetDebugLevel 调试级别
func SetDebugLevel(gDebug int) {
	DebugLevel = gDebug
}

// SetListenPort 端口
func SetListenPort(gListenAddrPort string) {
	intStr := tools.GetPort(gListenAddrPort)
	intNum, err := strconv.Atoi(intStr)
	if err != nil {
		log.Printf("SetListenPort err %s\n", err.Error())
	}
	ListenPort = uint16(intNum)
}
