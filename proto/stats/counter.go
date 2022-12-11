package stats

import (
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type Counter struct {
	access sync.RWMutex
	name   string
	active int64 // 活跃时间, 判断计数器是否可以清理
	minute int   // 打印日志时间, 当前分钟数不再打印
	value  int64
}

func (c *Counter) Add(delta int64) int64 {
	defer func() {
		if err := recover(); err != nil {
			const size = 32 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("panic stats: %v\n%s", err, buf)
		}
	}()
	c.access.Lock()
	defer c.access.Unlock()
	tmp := atomic.AddInt64(&c.value, delta)

	now := time.Now().Minute()
	if now != c.minute {
		// 打印上一分钟的上行下行字节数
		if tmp > 1e6 {
			log.Println(c.name, tmp/1e6, "MB")
		} else if tmp > 1e3 {
			log.Println(c.name, tmp/1e3, "KB")
		} else {
			log.Println(c.name, tmp, "Bytes")
		}
		c.minute = now
		c.active = time.Now().Unix()
		tmp = atomic.SwapInt64(&c.value, 0)
	}
	return tmp
}
