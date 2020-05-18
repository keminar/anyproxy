package proto

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/keminar/anyproxy/crypto"
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

// copyBuffer 传输数据
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
			log.Printf("receive from %s, data len :%d\n", srcname, nr)
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

// transfer 交换数据
func transfer(leftConn *net.TCPConn, rightConn *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	//发送请求
	go func() {
		defer wg.Done()
		data, _, err := copyBuffer(rightConn, leftConn, "server", "client")
		if err != nil {
			log.Println(err.Error())
		}
		log.Println("request", len(data.String()))
	}()
	//取返回结果
	go func() {
		defer wg.Done()
		data, _, err := copyBuffer(leftConn, rightConn, "client", "server")
		if err != nil {
			log.Println(err.Error())
		}
		log.Println("response", len(data.String()))
	}()
	go func() {
		wg.Wait()
		leftConn.Close()
		log.Println("connection close")
	}()
}

// dail tcp连接
func dail(dstIP string, dstPort uint16) (conn *net.TCPConn, err error) {
	var addr *net.TCPAddr
	log.Printf("accept and create a new connection to server %s:%d\n", dstIP, dstPort)
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

// handshake 和server握手
func handshake(dstName, dstIP string, dstPort uint16) (conn *net.TCPConn, err error) {
	proxyIP := "127.0.0.1"
	proxyPort := 3001
	useProxy2 := true
	if useProxy2 {
		conn, err = dail(proxyIP, uint16(proxyPort))
		if err != nil {
			log.Println("dail err", err.Error())
			return
		}
		if dstName == "" {
			dstName = dstIP
		}
		x := []byte(fmt.Sprintf("%s:%d", dstName, dstPort))
		log.Println("CONNECT ", string(x))
		key := []byte(AesToken)
		var x1 []byte
		x1, err = crypto.EncryptAES(x, key)
		if err != nil {
			log.Println("encrypt err", err.Error())
			return
		}

		// CONNECT实现的加密版
		connectString := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", base64.StdEncoding.EncodeToString(x1))
		fmt.Fprintf(conn, connectString)
		var status string
		status, err = bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			log.Printf("PROXY ERR: Could not find response to CONNECT: err=%v", err)
			return
		}
		// todo 检查是不是200返回
		if strings.Contains(status, "200") == false {
			log.Printf("PROXY ERR: Proxy response to CONNECT was: %s.\n", strconv.Quote(status))
		}
	} else {
		conn, err = dail(dstIP, dstPort)
	}
	return
}
