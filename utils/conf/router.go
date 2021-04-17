package conf

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// Host 域名
type Host struct {
	Name   string `yaml:"name"`   //域名关键字
	Match  string `yaml:"match"`  //contain 包含, equal 完全相等, preg 正则
	Target string `yaml:"target"` //local 当前环境, remote 远程, deny 禁止, auto根据dial选择
	DNS    string `yaml:"dns"`    //local 当前环境, remote 远程, 仅当target使用remote有效
	IP     string `yaml:"ip"`     //本地解析ip
	Proxy  string `yaml:"proxy"`  //指定代理服务器
}

// Log 日志
type Log struct {
	Dir string `yaml:"dir"`
}

// Subscribe 订阅标志
type Subscribe struct {
	Key string `yaml:"key"` //Header的key
	Val string `yaml:"val"` //Header的val
}

// Websocket 与服务端websocket通信
type Websocket struct {
	Listen    string      `yaml:"listen"`    //websocket 监听
	Connect   string      `yaml:"connect"`   //websocket 连接
	Host      string      `yaml:"host"`      //connect的域名
	User      string      `yaml:"user"`      //认证用户
	Pass      string      `yaml:"pass"`      //密码
	Email     string      `yaml:"email"`     //邮箱
	Subscribe []Subscribe `yaml:"subscribe"` //订阅信息
}

// Default 域名
type Default struct {
	Match     string `yaml:"match"`     //默认域名比对
	Target    string `yaml:"target"`    //http默认访问策略
	DNS       string `yaml:"dns"`       //默认的DNS服务器
	Proxy     string `yaml:"proxy"`     //全局代理服务器
	TCPTarget string `yaml:"tcpTarget"` //tcp默认访问策略
}

// Router 配置文件模型
type Router struct {
	Listen    string    `yaml:"listen"`    //监听端口
	Log       Log       `yaml:"log"`       //日志目录
	Watcher   bool      `yaml:"watcher"`   //是否监听配置文件变化
	Token     string    `yaml:"token"`     //加密值, 和tunnel通信密钥, 必须16位长度
	Default   Default   `yaml:"default"`   //默认配置
	Hosts     []Host    `yaml:"hosts"`     //域名列表
	AllowIP   []string  `yaml:"allowIP"`   //可以访问的客户端IP
	Websocket Websocket `yaml:"websocket"` //会话订阅请求信息
}

// LoadRouterConfig 加载配置
func LoadRouterConfig(configPath string) (cnf Router, err error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return
	}
	err = yaml.Unmarshal(data, &cnf)
	return
}

// 获取文件路径
func GetPath(filename string) (string, error) {
	// 当前登录用户所在目录
	workPath, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	configPath := filepath.Join(workPath, "conf", filename)
	if !fileExists(configPath) {
		configPath = filepath.Join(AppPath, "conf", filename)
		if !fileExists(configPath) {
			configPath = filepath.Join(AppSrcPath, "conf", filename)
			if !fileExists(configPath) {
				return "", errors.New("conf/" + filename + " not found")
			}
		}
	}
	return configPath, nil
}

// fileExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
