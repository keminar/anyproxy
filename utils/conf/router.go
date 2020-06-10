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
	Name     string `yaml:"name"`
	Match    string `yaml:"match"`    //contain 包含, equal 完全相等, preg 正则
	Target   string `yaml:"target"`   //local 当前环境, remote 远程, deny 禁止
	LocalDNS string `yaml:"localDns"` //false 当前环境， true远程
}

// Router 配置文件模型
type Router struct {
	LocalDNS string `yaml:"localDns"` //false 当前环境， true远程
	Hosts    []Host
}

// LoadRouterConfig 加载配置
func LoadRouterConfig(configName string) (cnf Router, err error) {
	configPath, err := getPath(configName + ".yaml")
	if err != nil {
		return cnf, err
	}
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return cnf, err
	}
	t := Router{}
	err = yaml.Unmarshal(data, &t)
	return t, err
}

// 获取文件路径
func getPath(filename string) (string, error) {
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
				return "", errors.New(filename + " not found")
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
