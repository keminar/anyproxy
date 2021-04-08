package main

import "log"

func main() {
	log.Println("test1============")
	test1()
	log.Println("test2============")
	test2()
	log.Println("test3============")
	test3()
	log.Println("test4============")
	test4()
	log.Println("test5============")
	test5()
	log.Println("test6============")
	test6()

	//结论 ok 为判断通道是否关闭， default为判断通道是否放满或者无数据时都会调用
}

func test1() {
	send := make(chan int)
	close(send)

	select {
	case t := <-send: //不用ok
		log.Println(t) //被执行
	default:
		log.Println("default")
	}
}

func test2() {
	send := make(chan int)
	close(send)

	select {
	case t, ok := <-send: // 使用ok
		log.Println(t, ok) //被执行，且ok为false
	default:
		log.Println("default")
	}
}

func test3() {
	send := make(chan int)
	close(send)

	select {
	case t, ok := <-send: // 使用ok
		log.Println(t, ok) //被执行，且ok为false
	}
}

func test4() {
	send := make(chan int)
	go func() {
		// 无close
		for i := 0; i < 10; i++ {
			send <- i
		}
	}()

	for i := 0; i < 20; i++ {
		select {
		case t, ok := <-send:
			log.Println(t, ok)
		default:
			log.Println("send is full or send is empty") //部分被执行
		}
	}
}

func test5() {
	send := make(chan int)
	go func() {
		for i := 0; i < 10; i++ {
			send <- i
		}
	}()

	for i := 0; i < 10; i++ {
		select {
		case t, ok := <-send:
			log.Println(t, ok) //全部执行
		}
	}
}

func test6() {
	send := make(chan int, 1)
	for i := 0; i < 5; i++ {
		select {
		case send <- i:
			log.Println(i)
		default:
			log.Println("send is full") //部分被执行
		}
	}
}
