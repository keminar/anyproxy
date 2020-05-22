//autoInc.go

package autoinc

// UintMax 最大值
const UintMax = ^uint(0)

// AutoInc 自增
type AutoInc struct {
	start, step uint
	queue       chan uint
}

// New 实例化
func New(start, step uint) (ai *AutoInc) {
	ai = &AutoInc{
		start: start,
		step:  step,
		queue: make(chan uint, 4),
	}

	go ai.process()
	return
}

// 产生id
func (ai *AutoInc) process() {
	defer func() { recover() }()
	for i := ai.start; ; i = i + ai.step {
		if i > UintMax {
			// reset
			i = ai.start
		}
		ai.queue <- i
	}
}

// ID 取id
func (ai *AutoInc) ID() uint {
	return <-ai.queue
}
