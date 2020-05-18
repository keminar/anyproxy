package config

import (
	"log"
	"strconv"
	"strings"
)

// ProxyServer 代理服务器
var ProxyServer string

// ProxyPort 代理端口
var ProxyPort uint16

// SetProxyServer 设置代理服务器
func SetProxyServer(gProxyServerSpec string) {
	if gProxyServerSpec == "" {
		return
	}
	tmp := strings.Split(gProxyServerSpec, ":")
	if len(tmp) == 2 {
		portInt, err := strconv.Atoi(tmp[1])
		if err == nil {
			ProxyServer = tmp[0]
			ProxyPort = uint16(portInt)
			log.Printf("Proxy server is %s:%d\n", ProxyServer, ProxyPort)
		} else {
			log.Printf("Set proxy port err %s\n", err.Error())
		}
	}
}
