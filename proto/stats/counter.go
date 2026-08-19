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
		logBytes(id, c.name, tmp)
		c.minute = now
		c.active = time.Now().Unix()
		tmp = atomic.SwapInt64(&c.value, 0)
	}
	return tmp
}

// Flush 立即输出并清零当前累计值(不等分钟翻转)。用于连接结束或计数器回收时,
// 把「本分钟内已传、但还没到翻转点」的字节补记进日志——否则快速完成的连接
// (整段传输都在同一分钟内、之后再无 Add 触发翻转)其字节会一直留在 value 里,
// 最终被 UnregisterCounter 静默丢弃, 造成漏统计。id 传 0 时用最后一次写入的连接ID。
func (c *Counter) Flush(id uint) {
	c.access.Lock()
	defer c.access.Unlock()
	v := atomic.SwapInt64(&c.value, 0)
	if v <= 0 {
		return
	}
	if id == 0 {
		id = c.id
	}
	c.active = time.Now().Unix()
	logBytes(id, c.name, v)
}

// logBytes 按大小选择单位打印一条统计日志。
func logBytes(id uint, name string, v int64) {
	tag := fmt.Sprintf("ID #%d,", id)
	if v > 1e6 {
		log.Println(tag, name, v/1e6, "MB")
	} else if v > 1e3 {
		log.Println(tag, name, v/1e3, "KB")
	} else {
		log.Println(tag, name, v, "Bytes")
	}
}
