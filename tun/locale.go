package tun

import (
	"os"
	"strings"
)

// isChinese 判断系统语言是否为中文。
// 先查标准 POSIX 环境变量（Linux 通常已设置），再回退到平台 API。
func isChinese() bool {
	for _, env := range []string{"LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"} {
		if v := os.Getenv(env); v != "" {
			return strings.HasPrefix(strings.ToLower(v), "zh")
		}
	}
	return systemIsChinese()
}
