package stats

import (
	"fmt"
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
	id     uint // 最后一次写入的连接ID, 日志中关联连接
}

func (c *Counter) Add(id uint, delta int64) int64 {
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
	c.id = id
	tmp := atomic.AddInt64(&c.value, delta)

	now := time.Now().Minute()
	if now != c.minute {
		// 打印上一分钟的上行下行字节数
		tag := fmt.Sprintf("ID #%d,", id)
		if tmp > 1e6 {
			log.Println(tag, c.name, tmp/1e6, "MB")
		} else if tmp > 1e3 {
			log.Println(tag, c.name, tmp/1e3, "KB")
		} else {
			log.Println(tag, c.name, tmp, "Bytes")
		}
		c.minute = now
		c.active = time.Now().Unix()
		tmp = atomic.SwapInt64(&c.value, 0)
	}
	return tmp
}
