package conf

import (
	"fmt"
	"log"
	"unicode/utf8"
)

// MinPassLen websocket.server.users[].pass 的最短长度(按字符数, 不是字节数)。只在
// 没配 key、真要靠这个密码鉴权时才卡这一关(见 IsValidPass 的调用方 validateServerUsers)
// ——配了 key 的账号走密钥挑战-应答, 不受密码强度限制。这条校验只在服务端做, 订阅端
// (websocket.client(s).pass)不判断, 好让新版本订阅端也能连尚未升级的旧服务端(或者
// 密码还没改达标的账号), 服务端这关本来就够了。
const MinPassLen = 18

// IsValidPass 校验密码强度: 长度至少 MinPassLen, 且至少各出现一个英文字母和一个
// 数字——纯数字、纯字母或者位数不够, 都太容易被离线爆破。
func IsValidPass(pass string) bool {
	if utf8.RuneCountInString(pass) < MinPassLen {
		return false
	}
	var hasLetter, hasDigit bool
	for _, r := range pass {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
		if hasLetter && hasDigit {
			return true
		}
	}
	return false
}

// validateServerUsers 逐个检查 websocket.server.users: 配了 key 的账号走密钥鉴权,
// 密码强度无所谓; 没配 key 却密码不达标(含没配密码)的账号直接标记 Disable——复用
// 已有的"停用账号"语义(见 ServerUser.Disable), serveWs 会直接拒绝这个账号的鉴权
// (见 nat/conn.go), 而不是放一个弱密码/空密码账号继续能登录。
func validateServerUsers(configPath string, w *Websocket) {
	for i := range w.Server.Users {
		u := &w.Server.Users[i]
		if u.Key != "" || u.Disable {
			continue
		}
		if !IsValidPass(u.Pass) {
			u.Disable = true
			log.Printf("config file %s: websocket.server.users[].user=%s has a pass that is empty or weaker than required (min %d chars, must contain both a letter and a digit); this account is disabled until it is fixed", configPath, u.User, MinPassLen)
		}
	}
}

// warnSendRecvOnlyReceive 提示一个自相矛盾的组合: sendRecvOnly 让常驻进程跳过这条
// client 配置的连接(见 conf.WsClient.SendRecvOnly), 但同时又配了 receive.dir——
// 接收文件靠的正是那条被跳过的常驻连接(对端 -send/-recv 时服务端要能在 hub 里查到
// 这个 email 当前在线, 见 nat/file_relay.go GetClientByEmail), 常驻进程不连接就永远
// 收不到任何人发来的文件, 这不太可能是本意, 只打日志、不阻断加载(留给用户自己判断)。
func warnSendRecvOnlyReceive(configPath string, w *Websocket) {
	check := func(c WsClient, label string) {
		if c.SendRecvOnly && c.Receive.Dir != "" {
			log.Printf("config file %s: websocket.%s has both sendRecvOnly and receive.dir set; the resident process will skip connecting for it, so it can never actually receive a file (sendRecvOnly is meant for entries used only to run -send/-recv, not as a receive target)", configPath, label)
		}
	}
	if w.Client.Connect != "" {
		check(w.Client, "client")
	}
	for i, c := range w.Clients {
		check(c, fmt.Sprintf("clients[%d]", i))
	}
}
