package tools

// GetPort 从 127.0.0.1:3000 结构中取出3000
func GetPort(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i+1:]
		}
	}
	return ""
}
