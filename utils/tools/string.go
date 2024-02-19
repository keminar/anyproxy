package tools

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// GetPort 从 127.0.0.1:3000 结构中取出3000
func GetPort(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i+1:]
		}
	}
	return ""
}

// GetIp 从 127.0.0.1:3000 结构中取出127.0.0.1
func GetRemoteIp(addr string) string {
	for i := len(addr) - 1; i >= 1; i-- {
		if addr[i] == ':' {
			return addr[0:i]
		}
	}
	return addr
}

func Md5Str(str string) (string, error) {
	h := md5.New()
	h.Write([]byte(str))
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr), nil
}

// 支持只输入端口的形式
func FillPort(port string) string {
	if !strings.Contains(port, ":") {
		d, err := strconv.Atoi(port)
		if err == nil && strconv.Itoa(d) == port { //说明输入为纯数字
			port = ":" + port
		}
	}
	return port
}
