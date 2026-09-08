package conf

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ensureClientUUID 确保用到的 websocket.client(s) 都有一个身份 uuid: UUID 字段没有
// yaml 标签, 配置文件里没法配, 只能靠这里填——先看这份配置对应的状态文件(见
// clientUUIDStateFile)存过没有, 存过就复用, 没有就现生成一个并存下来——这样重启
// 不会变, 不需要也不允许手动配置。
//
// 身份按**配置文件**分, 不是按机器: 同一份配置文件下的所有 client 块共用这一个
// (代表同一份配置里描述的这台机器/这个身份); 但用 -c 指向不同配置文件(哪怕在同一
// 目录下)相当于换一个独立身份, 各自持久化, 不会共用——这与"一份配置文件本身就是
// 一份独立、可拷贝到别处的设置"这个前提一致, 不去猜"这是不是同一台物理机器"。
func ensureClientUUID(configPath string, w *Websocket) error {
	needShared := w.Client.Connect != "" && w.Client.UUID == ""
	for i := range w.Clients {
		if w.Clients[i].UUID == "" {
			needShared = true
		}
	}
	if !needShared {
		return nil
	}
	shared, err := loadOrCreateUUID(configPath)
	if err != nil {
		return err
	}
	if w.Client.Connect != "" && w.Client.UUID == "" {
		w.Client.UUID = shared
	}
	for i := range w.Clients {
		if w.Clients[i].UUID == "" {
			w.Clients[i].UUID = shared
		}
	}
	return nil
}

// clientUUIDStateFile 持久化文件路径: 配置文件同目录下、同名(去掉扩展名)加点前缀的
// 隐藏文件——router.yaml 对应 .router.uuid, office.yaml 对应 .office.uuid, 不同的配置
// 文件(哪怕在同一目录)各自独立, 不会共用同一个身份; 不写回 yaml 本身是为了不打乱
// 手工排版的格式/注释。
//
// 用隐藏文件是因为这是程序自己维护的状态, 不是给人编辑的配置: 混在 conf/ 目录里
// 跟 router.yaml 平起平坐, 太容易被当成配置的一部分去改、或者拷贝配置时顺手带走
// (uuid 是身份, 带过去等于两台机器同一个身份)。
func clientUUIDStateFile(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "."+uuidBaseName(configPath))
}

// legacyUUIDStateFile 旧版(不带点前缀)的状态文件路径, 只用于迁移: 老机器上已经
// 有一个 router.uuid, 换名字后如果不认它, 重启就等于换了个身份, 对端 receive.allow
// 里配的值全部失效。
func legacyUUIDStateFile(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), uuidBaseName(configPath))
}

func uuidBaseName(configPath string) string {
	base := filepath.Base(configPath)
	return strings.TrimSuffix(base, filepath.Ext(base)) + ".uuid"
}

// loadOrCreateUUID 读状态文件; 不存在(或内容不是合法 uuid, 比如文件被手改坏了)则
// 生成一个新的并写入, 顺带打日志——只有第一次(文件还不存在)才会打, 热加载重复
// 调用不会刷屏。
func loadOrCreateUUID(configPath string) (string, error) {
	path := clientUUIDStateFile(configPath)
	if id, ok := readUUIDFile(path); ok {
		return id, nil
	}
	// 旧版非隐藏状态文件的迁移: 身份不变是第一位的, 改名失败也照旧用旧文件里的值,
	// 只打日志提示——为了换个文件名把对端的 receive.allow 全废掉, 得不偿失。
	if legacy := legacyUUIDStateFile(configPath); legacy != path {
		if id, ok := readUUIDFile(legacy); ok {
			if err := os.Rename(legacy, path); err != nil {
				log.Printf("failed to move the uuid state file %s to %s: %v (identity unchanged, still reading the old path)", legacy, path, err)
				return id, nil
			}
			hideFile(path)
			log.Printf("moved the uuid state file %s -> %s (hidden; websocket.client.uuid unchanged: %s)", legacy, path, id)
			return id, nil
		}
	}
	id, err := newUUID()
	if err != nil {
		return "", fmt.Errorf("generate websocket.client.uuid: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		// 生成出来了但落不了盘: 这次能用, 但下次启动/热加载会再生成一个不同的值,
		// 对端配的 receive.allow 就跟着失效——必须打日志暴露出来, 不能悄悄吞掉。
		log.Printf("failed to persist websocket.client.uuid to %s: %v (uuid will not survive a restart until this is fixed)", path, err)
		return "", fmt.Errorf("persist websocket.client.uuid to %s: %w", path, err)
	}
	hideFile(path)
	log.Printf("generated a new websocket.client.uuid: %s (saved to %s; copy it into the peer's websocket.client.receive.allow)", id, path)
	return id, nil
}

// readUUIDFile 读一个状态文件并校验内容。ok=false 表示文件不存在、是空的、或者内容
// 不是合法 uuid(被手改坏了), 调用方据此决定生成新的。
func readUUIDFile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return "", false
	}
	if !IsValidUUID(id) {
		log.Printf("uuid state file %s content %q is not a valid uuid, regenerating", path, id)
		return "", false
	}
	return id, true
}

// newUUID 生成一个标准格式(v4)的随机 uuid 字符串。
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// uuidPattern 标准 8-4-4-4-12 十六进制格式, 不区分大小写; 不校验 version/variant 位,
// 只要求形状对——够用来拦截空值、手误、篡改这些明显不是 uuid 的输入。
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsValidUUID 校验一个字符串是不是合法 uuid 格式。文件传输(nat/file.go、
// nat/file_relay.go)在拿 uuid 做身份比对/派生加密密钥之前都要先过这一关——空值
// 或者格式不对的字符串没有资格再往下走, 一律当作禁止传输处理, 而不是当成"比对
// 失败"悄悄放过或者传给 KDF 产出一把看似正常实则毫无意义的密钥。
func IsValidUUID(s string) bool {
	return uuidPattern.MatchString(s)
}
