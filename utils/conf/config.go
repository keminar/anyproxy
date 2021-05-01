package conf

import (
	"fmt"
	"log"

	"github.com/fsnotify/fsnotify"
)

// RouterConfig 配置
var RouterConfig *Router

// LoadAllConfig 加载顺序要求，不写成init
func LoadAllConfig(filePath string) {
	var err error
	if filePath == "" {
		filePath, err = GetPath("router.yaml")
	} else if !fileExists(filePath) {
		filePath, err = GetPath(filePath)
	}
	if err != nil {
		log.Println(fmt.Sprintf("config file %s path err:%s", "router", err.Error()))
		return
	}
	conf, err := LoadRouterConfig(filePath)
	if err != nil {
		log.Println(fmt.Sprintf("config file %s load err:%s", "router", err.Error()))
		return
	}
	RouterConfig = &conf
	if conf.Watcher {
		go notify(filePath)
	}
}

func notify(filePath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println("config new notify watcher err", err)
		return
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		defer close(done)
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					conf, err := LoadRouterConfig(filePath)
					if err != nil {
						log.Println(fmt.Sprintf("config file %s load err:%s", "router", err.Error()))
					} else {
						RouterConfig = &conf
						log.Println("config file reloaded:", filePath)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("config notify watcher error:", err)
			}
		}
	}()

	err = watcher.Add(filePath)
	if err != nil {
		log.Println("config notify add file err", err)
		return
	}
	<-done
}
