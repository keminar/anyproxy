package logging

import (
	"io"
	"log"
	"os"

	"github.com/keminar/anyproxy/config"
)

// SetDefaultLogger 设置日志
func SetDefaultLogger(dir, prefix string, compress bool, reserveDay int) {
	timeWriter := &TimeWriter{
		Dir:        dir,
		Prefix:     prefix,
		Compress:   compress,
		ReserveDay: reserveDay,
	}
	// 同时输出到日志和标准输出
	writers := []io.Writer{
		timeWriter,
		os.Stdout,
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
