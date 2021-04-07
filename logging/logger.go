package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/keminar/anyproxy/config"
)

// SetDefaultLogger 设置日志
func SetDefaultLogger(dir, prefix string, compress bool, reserveDay int, w io.Writer) {
	timeWriter := &TimeWriter{
		Dir:        dir,
		Prefix:     prefix,
		Compress:   compress,
		ReserveDay: reserveDay,
	}
	// 同时输出到日志和标准输出
	writers := []io.Writer{
		timeWriter,
	}
	if w != nil {
		writers = append(writers, w)
	}
	log.SetOutput(io.MultiWriter(writers...))
	switch config.DebugLevel {
	case config.LevelLong:
		log.SetFlags(log.Lshortfile | log.Ldate | log.Lmicroseconds)
	case config.LevelDebug:
		log.SetFlags(log.Llongfile | log.Ldate | log.Lmicroseconds)
	default:
		log.SetFlags(log.Lshortfile | log.LstdFlags)
	}
}

// ErrlogFd 标准输出错误输出文件
func ErrlogFd(logDir string, cmdName string) *os.File {
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		err = os.Mkdir(logDir, 0777)
		if err != nil {
			log.Fatalln("logs dir create error", err.Error())
		}
	}
	errFile := filepath.Join(logDir, fmt.Sprintf("%s.err.log", cmdName))
	fd, err := os.OpenFile(errFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0664)
	if err != nil {
		//报错并退出
		log.Fatalln("open log file error", err.Error())
	}
	return fd
}
