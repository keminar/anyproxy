package proto

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
)

const SO_ORIGINAL_DST = 80

// GetOriginalDstAddr 目标
func GetOriginalDstAddr(tcpConn *net.TCPConn) (dstIP string, dstPort uint16, leftConn *net.TCPConn, err error) {
	// connection => file, will make a copy
	tcpConnFile, err := tcpConn.File()
	if err != nil {
		return
	}
	tcpConn.Close()
	defer tcpConnFile.Close()

	mreq, err := syscall.GetsockoptIPv6Mreq(int(tcpConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return
	}

	// only support ipv4
	dstIP = net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7]).String()
	dstPort = uint16(mreq.Multiaddr[2])<<8 + uint16(mreq.Multiaddr[3])

	newConn, err := net.FileConn(tcpConnFile)
	if err != nil {
		return
	}
	if _, ok := newConn.(*net.TCPConn); ok {
		leftConn = newConn.(*net.TCPConn)
		return
	}
	err = fmt.Errorf("ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", newConn, newConn)
	return
}

func copyBuffer(dst io.Writer, src io.Reader, dstname string, srcname string) (data bytes.Buffer, written int64, err error) {

	size := 32 * 1024
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}
	buf := make([]byte, size)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			fmt.Printf("receive from %s, data len :%d\n%s\n", srcname, nr, buf[0:nr])
			data.Write(buf[0:nr])
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				// 因为客户端已关闭，自己主动关闭与服务端的链接导致，是正常的。
				if srcname == "server" && strings.Contains(er.Error(), "use of closed network connection") {
					break
				}
				err = er
			}
			if srcname == "client" {
				// 当客户端关闭了，服务端也不用再读了，可以关闭，解决读Server卡住不能到EOF的问题
				dst.(*net.TCPConn).Close()
			}
			break
		}
	}
	return data, written, err
}

func transfer(leftConn *net.TCPConn, rightConn *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	//发送请求
	go func() {
		defer wg.Done()
		data, _, err := copyBuffer(rightConn, leftConn, "server", "client")
		if err != nil {
			//panic(err)
			fmt.Println(err.Error())
		}
		fmt.Println("request", len(data.String()))
	}()
	//取返回结果
	go func() {
		defer wg.Done()
		data, _, err := copyBuffer(leftConn, rightConn, "client", "server")
		if err != nil {
			//panic(err)
			fmt.Println(err.Error())
		}
		fmt.Println("response", len(data.String()))
	}()
	go func() {
		wg.Wait()
		leftConn.Close()
		fmt.Println("connection close")
	}()
}

func dail(dstIP string, dstPort uint16) (conn *net.TCPConn, err error) {
	var addr *net.TCPAddr
	addr, err = net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", dstIP, dstPort))
	if err != nil {
		return
	}
	conn, err = net.DialTCP("tcp4", nil, addr)
	if err != nil {
		return
	}
	return
}
