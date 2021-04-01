package nat

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/proto/tcp"
)

var interruptClose bool

var proxyConn net.Conn

func NewClient(addr *string) {
	interruptClose = false
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	connTimeout := time.Duration(5) * time.Second
	var err error
	proxyConn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", "127.0.0.1", 4003), connTimeout)
	fmt.Println(err)

	for {
		conn(addr, interrupt)
		if interruptClose {
			break
		}
	}
}

func copyBuffer(dst io.Writer, src io.Reader, srcname string) (written int64, err error) {
	//如果设置过大会耗内存高，4k比较合理
	size := 4 * 1024
	buf := make([]byte, size)
	i := 0
	for {
		i++
		nr, er := src.Read(buf)
		if nr > 0 {
			fmt.Println("test", string(buf[0:nr]))
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
				err = er
			}
			break
		}
	}
	return written, err
}

type WsHelp struct {
	c *websocket.Conn
}

func newWsHelp(c *websocket.Conn) *WsHelp {
	return &WsHelp{c: c}
}

func (h *WsHelp) Read(p []byte) (n int, err error) {
	_, message, err := h.c.ReadMessage()
	n = copy(p, message)
	return n, err
}

func (h *WsHelp) Write(p []byte) (n int, err error) {
	h.c.SetWriteDeadline(time.Now().Add(writeWait))

	w, err := h.c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	w.Write(p)
	if err := w.Close(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func conn(addr *string, interrupt chan os.Signal) {

	u := url.URL{Scheme: "ws", Host: *addr, Path: "/ws"}
	log.Printf("connecting to %s", u.String())

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Println("dial:", err)
		time.Sleep(time.Duration(3) * time.Second)
		return
	}
	defer c.Close()

	w := newWsHelp(c)

	done := make(chan struct{})

	go func() {
		defer close(done)
		/*for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				return
			}
			log.Printf("recv: %s", message)
		}*/
		go func() {
			readSize, err := copyBuffer(proxyConn.(*net.TCPConn), w, "client")
			fmt.Println(readSize, err)
		}()
		writeSize, err := copyBuffer(w, tcp.NewReader(proxyConn.(*net.TCPConn)), "server")
		fmt.Println(writeSize, err)
	}()

	for {
		select {
		case <-done:
			return
		case <-interrupt:
			log.Println("interrupt")
			interruptClose = true

			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}
