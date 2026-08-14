package conf

import (
	"fmt"
	"log"
	"path/filepath"
	"time"

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

	// 监听所在「目录」而非文件本身。很多编辑器/工具在 Linux 上采用「写临时文件再 rename
	// 覆盖」的原子保存(vim 默认、VS Code、sed -i 等), 会替换文件的 inode。直接 watch 文件时
	// inotify 只收到 RENAME/REMOVE 且 watch 随之失效, 收不到 WRITE, 因此 Linux 不会重载;
	// Windows 多为就地写入才恰好触发 WRITE。改为 watch 目录后, 对目标文件的 Write/Create/
	// Rename 都能捕获, 且目录 watch 不因 inode 变化而失效。
	dir := filepath.Dir(filePath)
	target := filepath.Clean(filePath)

	reload := func() {
		conf, err := LoadRouterConfig(filePath)
		if err != nil {
			log.Println(fmt.Sprintf("config file %s load err:%s", "router", err.Error()))
			return
		}
		RouterConfig = &conf
		log.Println("config file reloaded:", filePath)
	}

	done := make(chan bool)
	go func() {
		defer close(done)
		// 合并短时间内的多次事件: 原子保存常一次触发 Rename+Create+Chmod 多个事件,
		// 就地写入也可能触发多次 Write, 用防抖定时器只重载一次。
		const debounceWait = 200 * time.Millisecond
		var debounce *time.Timer
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// 只关心目标文件, 忽略同目录下其它文件的事件
				if filepath.Clean(event.Name) != target {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
					continue
				}
				if debounce == nil {
					debounce = time.AfterFunc(debounceWait, reload)
				} else {
					debounce.Reset(debounceWait)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("config notify watcher error:", err)
			}
		}
	}()

	err = watcher.Add(dir)
	if err != nil {
		log.Println("config notify add dir err", err)
		return
	}
	<-done
}
