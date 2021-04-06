package tools

import (
	"crypto/md5"
	"encoding/hex"
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

func Md5Str(str string) (string, error) {
	h := md5.New()
	h.Write([]byte(str))
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr), nil
}
