package conf

import (
	"fmt"
	"log"
)

// RouterConfig 配置
var RouterConfig *Router

// LoadAllConfig 加载顺序要求，不写成init
func LoadAllConfig() {
	conf, err := LoadRouterConfig("router")
	if err != nil {
		log.Println(fmt.Sprintf("yaml.load: %s loadYaml err:%s", "router", err.Error()))
		return
	}
	RouterConfig = &conf
}
