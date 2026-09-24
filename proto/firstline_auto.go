package proto

import (
	"fmt"
	"log"
	"sync"

	"github.com/keminar/anyproxy/utils/trace"
)

// firstLineLearned 记录运行时自动探测到的"首行带 scheme+host 会触发后端自重定向死循环"的域名,
// 学到后等同于在 firstLine.custom 里把该域名配成 off, 直到进程重启(不写回配置文件,
// 重启后会重新探测)。key 的格式和 firstLine.custom 一致: 域名和端口中间的冒号换成点。
//
// 典型触发场景: 某些后端(如 Next.js dev server)收到绝对形式首行(GET http://host/path)时,
// 会对这个"path"做规范化判断, 判定不匹配后发 3xx 跳转, 且 Location 和刚发的请求完全一致,
// 导致客户端每次都经代理重新发起同样的绝对形式请求、又被同样重定向, 反复循环, 在短时间内
// 产生大量连接。见 proto/http.go 的 peekSelfRedirect。
var (
	firstLineLearnedMu sync.RWMutex
	firstLineLearned   = map[string]bool{}
)

// isFirstLineLearnedOff 域名是否已被自动判定为需要 off。
func isFirstLineLearnedOff(key string) bool {
	firstLineLearnedMu.RLock()
	defer firstLineLearnedMu.RUnlock()
	return firstLineLearned[key]
}

// learnFirstLineOff 记学该域名以后按 off 处理(首行去掉 scheme+host), 一次性打断死循环。
// 同一域名只在首次命中时打日志, 避免每个请求都重复刷屏。
func learnFirstLineOff(id uint, key, reqURL string) {
	firstLineLearnedMu.Lock()
	already := firstLineLearned[key]
	firstLineLearned[key] = true
	firstLineLearnedMu.Unlock()
	if already {
		return
	}
	log.Println(trace.ID(id), fmt.Sprintf(
		"firstline: detected self-redirect loop for %s (backend redirected %s back to itself), "+
			"auto switch to origin-form firstline for this domain from now on; "+
			"to make it permanent across restarts, add to router.yaml: firstLine.custom: {%s: off}",
		key, reqURL, key))
}
